/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_bus.h>

#include <string.h>

static struct cdk2_ata_bus_bound_controller *find_controller(
	struct cdk2_ata_bus_binding *binding, void *handle, UINTN *position)
{
	for (UINTN index = 0; index < binding->controller_count; index++)
		if (binding->controllers[index]->handle == handle) {
			if (position != NULL)
				*position = index;
			return binding->controllers[index];
		}
	return NULL;
}

static EFI_STATUS match_path(struct cdk2_ata_pass_thru_protocol *pass_thru,
	void *remaining, UINT16 *port, UINT16 *multiplier)
{
	if (remaining == NULL) {
		*port = 0xffffU; *multiplier = 0xffffU;
		return EFI_SUCCESS;
	}
	if (((UINT8 *)remaining)[0] == 0x7fU && ((UINT8 *)remaining)[1] == 0xffU &&
	    ((UINT8 *)remaining)[2] == 4U && ((UINT8 *)remaining)[3] == 0U) {
		*port = 0xfffeU; *multiplier = 0xfffeU;
		return EFI_SUCCESS;
	}
	if (pass_thru->get_device == NULL)
		return EFI_UNSUPPORTED;
	return pass_thru->get_device(pass_thru, remaining, port, multiplier);
}

EFI_STATUS cdk2_ata_bus_binding_init(struct cdk2_ata_bus_binding *binding,
	const struct cdk2_ata_bus_binding_services *services)
{
	if (binding == NULL || services == NULL || services->open_parent == NULL ||
	    services->close_parent == NULL || services->marker == NULL ||
	    services->allocate == NULL || services->release == NULL ||
	    services->install_child == NULL || services->uninstall_child == NULL ||
	    services->child_link == NULL || services->defer == NULL ||
	    services->transport.execute == NULL || services->transport.submit == NULL ||
	    services->transport.wait == NULL || services->transport.reset == NULL ||
	    services->transport.signal == NULL)
		return EFI_INVALID_PARAMETER;
	memset(binding, 0, sizeof(*binding)); binding->services = *services;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_binding_supported(struct cdk2_ata_bus_binding *binding,
	void *controller, void *remaining_device_path)
{
	struct cdk2_ata_pass_thru_protocol *pass_thru = NULL;
	UINT16 port, multiplier; EFI_STATUS status;
	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->services.open_parent(binding->services.context, controller,
		0, &pass_thru);
	if (EFI_ERROR(status))
		return status;
	status = pass_thru == NULL ? EFI_UNSUPPORTED : match_path(pass_thru,
		remaining_device_path, &port, &multiplier);
	(void)binding->services.close_parent(binding->services.context, controller, 0);
	return status;
}

static void release_discovery_path(void *context, void *path)
{
	struct cdk2_ata_bus_binding *binding = context;
	binding->services.release(binding->services.context, path);
}

static EFI_STATUS rollback_child(struct cdk2_ata_bus_binding *binding,
	struct cdk2_ata_bus_bound_controller *owner,
	struct cdk2_ata_bus_bound_child *child)
{
	EFI_STATUS status;

	if (child->by_child) {
		status = binding->services.child_link(binding->services.context, owner->handle,
			child->handle, 0);
		if (EFI_ERROR(status))
			return status;
		child->by_child = 0;
	}
	if (child->installed) {
		status = binding->services.uninstall_child(binding->services.context,
			child->handle, child, child->model.geometry.trusted);
		if (EFI_ERROR(status))
			return status;
		child->installed = 0;
	}
	binding->services.release(binding->services.context, child);
	return EFI_SUCCESS;
}

static EFI_STATUS publish_child(struct cdk2_ata_bus_binding *binding,
	struct cdk2_ata_bus_bound_controller *owner,
	const struct cdk2_ata_bus_child *model)
{
	struct cdk2_ata_bus_bound_child *child;
	EFI_STATUS status;

	if (owner->child_count == CDK2_ATA_BUS_MAX_CHILDREN)
		return EFI_OUT_OF_RESOURCES;
	status = binding->services.allocate(binding->services.context, sizeof(*child),
		(void **)&child);
	if (EFI_ERROR(status))
		return status;
	memset(child, 0, sizeof(*child)); child->model = *model;
	status = cdk2_ata_bus_block_init(&child->block, &child->model,
		&owner->scheduler, binding->services.defer, binding->services.context);
	if (!EFI_ERROR(status))
		status = cdk2_ata_bus_disk_security_init(child, &binding->services);
	if (EFI_ERROR(status)) {
		binding->services.release(binding->services.context, child);
		return status;
	}
	status = binding->services.install_child(binding->services.context,
		&child->handle, child, child->model.geometry.trusted);
	if (EFI_ERROR(status)) {
		binding->services.release(binding->services.context, child);
		return status;
	}
	child->installed = 1;
	status = binding->services.child_link(binding->services.context, owner->handle,
		child->handle, 1);
	if (EFI_ERROR(status)) {
		EFI_STATUS rollback = rollback_child(binding, owner, child);

		if (EFI_ERROR(rollback)) {
			owner->children[owner->child_count++] = child;
			return rollback;
		}
		return status;
	}
	child->by_child = 1; owner->children[owner->child_count++] = child;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_binding_start(struct cdk2_ata_bus_binding *binding,
	void *controller, void *remaining_device_path)
{
	struct cdk2_ata_bus_bound_controller *owner = NULL;
	struct cdk2_ata_pass_thru_protocol *pass_thru = NULL;
	struct cdk2_ata_bus discovered = { 0 };
	UINT16 selected_port, selected_multiplier;
	EFI_STATUS status; BOOLEAN opened = 0, marked = 0;
	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	owner = find_controller(binding, controller, NULL);
	if (owner != NULL) {
		struct cdk2_ata_bus incremental = { 0 };

		status = match_path(owner->pass_thru, remaining_device_path, &selected_port,
			&selected_multiplier);
		if (EFI_ERROR(status))
			return status;
		if (remaining_device_path == NULL || selected_port == 0xfffeU)
			return EFI_ALREADY_STARTED;
		for (UINTN index = 0; index < owner->child_count; index++)
			if (owner->children[index]->model.port == selected_port &&
			    owner->children[index]->model.multiplier == selected_multiplier)
				return EFI_ALREADY_STARTED;
		status = cdk2_ata_bus_add_controller(&incremental, controller, owner->pass_thru,
			release_discovery_path, binding);
		if (EFI_ERROR(status))
			return status;
		for (UINTN index = 0; index < incremental.child_count; index++)
			if (incremental.children[index].port == selected_port &&
			    incremental.children[index].multiplier == selected_multiplier)
				return publish_child(binding, owner, &incremental.children[index]);
		return EFI_NOT_FOUND;
	}
	if (binding->controller_count == CDK2_ATA_BUS_MAX_CONTROLLERS)
		return EFI_OUT_OF_RESOURCES;
	status = binding->services.open_parent(binding->services.context, controller,
		1, &pass_thru);
	if (EFI_ERROR(status))
		return status;
	opened = 1;
	status = match_path(pass_thru, remaining_device_path, &selected_port,
		&selected_multiplier);
	if (EFI_ERROR(status))
		goto fail;
	status = binding->services.allocate(binding->services.context, sizeof(*owner),
		(void **)&owner);
	if (EFI_ERROR(status))
		goto fail;
	memset(owner, 0, sizeof(*owner)); owner->handle = controller;
	owner->pass_thru = pass_thru; owner->parent_open = 1;
	status = binding->services.marker(binding->services.context, controller, 1);
	if (EFI_ERROR(status))
		goto fail;
	marked = 1; owner->marker = 1;
	status = cdk2_ata_bus_scheduler_init(&owner->scheduler,
		&binding->services.transport);
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_ata_bus_add_controller(&discovered, controller, pass_thru,
		release_discovery_path, binding);
	if (EFI_ERROR(status))
		goto fail;
	for (UINTN index = 0; index < discovered.child_count; index++) {
		struct cdk2_ata_bus_child *model = &discovered.children[index];
		if (selected_port != 0xffffU && (model->port != selected_port ||
		    model->multiplier != selected_multiplier))
			continue;
		status = publish_child(binding, owner, model);
		if (EFI_ERROR(status))
			goto fail;
	}
	if (owner->child_count == 0U && selected_port != 0xfffeU) {
		status = EFI_NOT_FOUND;
		goto fail;
	}
	binding->controllers[binding->controller_count++] = owner;
	return EFI_SUCCESS;
fail:
	if (owner != NULL) {
		while (owner->child_count != 0U) {
			struct cdk2_ata_bus_bound_child *child =
				owner->children[owner->child_count - 1U];
			EFI_STATUS rollback = rollback_child(binding, owner, child);

			if (EFI_ERROR(rollback)) {
				if (binding->controller_count < CDK2_ATA_BUS_MAX_CONTROLLERS)
					binding->controllers[binding->controller_count++] = owner;
				return rollback;
			}
			owner->child_count--;
		}
	}
	if (marked) {
		EFI_STATUS cleanup = binding->services.marker(binding->services.context,
			controller, 0);

		if (EFI_ERROR(cleanup)) {
			binding->controllers[binding->controller_count++] = owner;
			return cleanup;
		}
		owner->marker = 0;
	}
	if (opened) {
		EFI_STATUS cleanup = binding->services.close_parent(
			binding->services.context, controller, 1);

		if (EFI_ERROR(cleanup) && owner != NULL) {
			binding->controllers[binding->controller_count++] = owner;
			return cleanup;
		}
		if (owner != NULL)
			owner->parent_open = 0;
	}
	if (owner != NULL)
		binding->services.release(binding->services.context, owner);
	return status;
}

EFI_STATUS cdk2_ata_bus_binding_stop(struct cdk2_ata_bus_binding *binding,
	void *controller, UINTN child_count, void **children)
{
	struct cdk2_ata_bus_bound_controller *owner; UINTN position;
	EFI_STATUS first = EFI_SUCCESS;
	if (binding == NULL || controller == NULL || (child_count != 0U && children == NULL))
		return EFI_INVALID_PARAMETER;
	owner = find_controller(binding, controller, &position);
	if (owner == NULL)
		return EFI_NOT_STARTED;
	if (owner->scheduler.worker_active || owner->scheduler.dispatching ||
	    owner->scheduler.parent_active)
		return EFI_NOT_READY;
	first = child_count == 0U ? cdk2_ata_bus_stop_scheduler(&owner->scheduler) :
		cdk2_ata_bus_drain_scheduler(&owner->scheduler);
	for (UINTN index = owner->child_count; index-- != 0U;) {
		struct cdk2_ata_bus_bound_child *child = owner->children[index]; BOOLEAN selected;
		selected = child_count == 0U;
		for (UINTN target = 0; target < child_count; target++)
			if (children[target] == child->handle)
				selected = 1;
		if (!selected)
			continue;
		EFI_STATUS status = child->by_child ?
			binding->services.child_link(binding->services.context,
				controller, child->handle, 0) : EFI_SUCCESS;
		if (!EFI_ERROR(status)) {
			child->by_child = 0;
			status = binding->services.uninstall_child(binding->services.context,
				child->handle, child, child->model.geometry.trusted);
		}
		if (EFI_ERROR(status)) {
			if (!EFI_ERROR(first))
				first = status;
			if (!child->by_child) {
				(void)binding->services.child_link(binding->services.context,
					controller, child->handle, 1);
				child->by_child = 1;
			}
			continue;
		}
		child->installed = 0; binding->services.release(binding->services.context, child);
		memmove(&owner->children[index], &owner->children[index + 1],
			(owner->child_count - index - 1U) * sizeof(owner->children[0]));
		owner->child_count--;
	}
	if (child_count != 0U || owner->child_count != 0U)
		return first;
	EFI_STATUS status = owner->marker ? binding->services.marker(
		binding->services.context, controller, 0) : EFI_SUCCESS;
	BOOLEAN removed_marker = owner->marker;
	if (EFI_ERROR(status))
		return status;
	owner->marker = 0;
	status = owner->parent_open ? binding->services.close_parent(
		binding->services.context, controller, 1) : EFI_SUCCESS;
	if (EFI_ERROR(status)) {
		if (removed_marker && !EFI_ERROR(binding->services.marker(
		    binding->services.context, controller, 1)))
			owner->marker = 1;
		return status;
	}
	owner->parent_open = 0;
	memmove(&binding->controllers[position], &binding->controllers[position + 1],
		(binding->controller_count - position - 1U) * sizeof(binding->controllers[0]));
	binding->controller_count--; binding->services.release(binding->services.context, owner);
	return first;
}
