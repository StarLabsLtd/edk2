/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_bus.h>

#include <string.h>

static void move_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *to = destination;
	const UINT8 *from = source;

	if (to < from)
		for (UINTN index = 0U; index < size; index++)
			to[index] = from[index];
	else
		for (UINTN index = size; index > 0U; index--)
			to[index - 1U] = from[index - 1U];
}

EFI_STATUS cdk2_usb_binding_init(struct cdk2_usb_binding *binding,
	const struct cdk2_usb_binding_services *services)
{
	if (binding == NULL || services == NULL || services->open_host == NULL ||
	    services->close_host == NULL || services->install_marker == NULL ||
	    services->uninstall_marker == NULL || services->publish_child == NULL ||
	    services->remove_child == NULL || services->link_child == NULL ||
	    services->unlink_child == NULL || services->allocate == NULL ||
	    services->free == NULL || services->delay == NULL)
		return EFI_INVALID_PARAMETER;
	memset(binding, 0, sizeof(*binding));
	binding->services = *services;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_binding_supported(struct cdk2_usb_binding *binding,
	void *controller)
{
	struct cdk2_usb2_hc_protocol *host;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->services.open_host(binding->services.context, controller,
		&host);
	if (!EFI_ERROR(status))
		status = binding->services.close_host(binding->services.context,
			controller);
	return status;
}

static EFI_STATUS remove_child(struct cdk2_usb_binding *binding,
	struct cdk2_usb_binding_controller *owner, UINTN index)
{
	struct cdk2_usb_child *child = &owner->bus->children[index];
	UINT8 address = child->address;
	BOOLEAN address_in_use = FALSE;
	EFI_STATUS status;

	status = binding->services.unlink_child(binding->services.context,
		owner->handle, child->handle);
	if (EFI_ERROR(status))
		return status;
	status = binding->services.remove_child(binding->services.context,
		owner->handle, child, child->handle);
	if (EFI_ERROR(status)) {
		(void)binding->services.link_child(binding->services.context,
			owner->handle, child->handle);
		return status;
	}
	for (UINTN other = 0U; other < owner->bus->child_count; other++)
		if (other != index && owner->bus->children[other].address == address)
			address_in_use = TRUE;
	move_bytes(child, child + 1U,
		(owner->bus->child_count - index - 1U) * sizeof(*child));
	memset(&owner->bus->children[--owner->bus->child_count], 0,
		sizeof(*child));
	if (!address_in_use)
		(void)cdk2_usb_release_address(&owner->bus->addresses, address);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_binding_start(struct cdk2_usb_binding *binding,
	void *controller)
{
	struct cdk2_usb_binding_controller *owner;
	struct cdk2_usb2_hc_protocol *host;
	UINT8 speed, ports, is_64bit;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0U; index < binding->count; index++)
		if (binding->controllers[index].handle == controller)
			return EFI_ALREADY_STARTED;
	if (binding->count == 8U)
		return EFI_OUT_OF_RESOURCES;
	status = binding->services.open_host(binding->services.context, controller,
		&host);
	if (EFI_ERROR(status))
		return status;
	owner = &binding->controllers[binding->count];
	memset(owner, 0, sizeof(*owner));
	owner->handle = controller;
	status = binding->services.allocate(binding->services.context,
		sizeof(*owner->bus), (void **)&owner->bus);
	if (EFI_ERROR(status))
		goto close;
	status = cdk2_usb_bus_init(owner->bus, host,
		binding->services.delay_context, binding->services.delay);
	if (EFI_ERROR(status))
		goto free;
	owner->bus->allocate_context = binding->services.context;
	owner->bus->allocate = binding->services.allocate;
	status = binding->services.install_marker(binding->services.context,
		controller, owner->bus);
	if (EFI_ERROR(status))
		goto free;
	owner->marker = TRUE;
	status = host->get_capability(host, &speed, &ports, &is_64bit);
	if (EFI_ERROR(status))
		goto rollback;
	for (UINT8 port = 0U; port < ports; port++) {
		status = cdk2_usb_bus_enumerate_port(owner->bus, port);
		if (status == EFI_NOT_FOUND)
			continue;
		if (EFI_ERROR(status))
			goto rollback;
	}
	for (UINTN index = 0U; index < owner->bus->child_count; index++) {
		struct cdk2_usb_child *child = &owner->bus->children[index];

		status = binding->services.publish_child(binding->services.context,
			controller, child, &child->handle);
		if (!EFI_ERROR(status))
			status = binding->services.link_child(binding->services.context,
				controller, child->handle);
		if (EFI_ERROR(status)) {
			if (child->handle != NULL)
				(void)binding->services.remove_child(binding->services.context,
					controller, child, child->handle);
			goto rollback;
		}
	}
	binding->count++;
	return EFI_SUCCESS;
rollback:
	for (UINTN index = owner->bus->child_count; index > 0U; index--)
		if (owner->bus->children[index - 1U].handle != NULL)
			(void)remove_child(binding, owner, index - 1U);
	if (owner->marker)
		(void)binding->services.uninstall_marker(binding->services.context,
			controller, owner->bus);
free:
	binding->services.free(binding->services.context, owner->bus);
	memset(owner, 0, sizeof(*owner));
close:
	(void)binding->services.close_host(binding->services.context, controller);
	return status;
}

EFI_STATUS cdk2_usb_binding_rescan(struct cdk2_usb_binding *binding,
	void *controller)
{
	struct cdk2_usb_binding_controller *owner = NULL;
	UINT8 speed, ports, is_64bit;
	UINTN first;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0U; index < binding->count; index++)
		if (binding->controllers[index].handle == controller)
			owner = &binding->controllers[index];
	if (owner == NULL)
		return EFI_NOT_FOUND;
	status = owner->bus->host->get_capability(owner->bus->host, &speed, &ports,
		&is_64bit);
	if (EFI_ERROR(status))
		return status;
	first = owner->bus->child_count;
	for (UINT8 port = 0U; port < ports; port++) {
		status = cdk2_usb_bus_enumerate_port(owner->bus, port);
		if (status != EFI_NOT_FOUND && status != EFI_ALREADY_STARTED &&
		    EFI_ERROR(status))
			goto rollback;
	}
	for (UINTN index = first; index < owner->bus->child_count; index++) {
		struct cdk2_usb_child *child = &owner->bus->children[index];

		status = binding->services.publish_child(binding->services.context,
			controller, child, &child->handle);
		if (!EFI_ERROR(status))
			status = binding->services.link_child(binding->services.context,
				controller, child->handle);
		if (EFI_ERROR(status))
			goto rollback;
	}
	return EFI_SUCCESS;
rollback:
	while (owner->bus->child_count > first) {
		struct cdk2_usb_child *child =
			&owner->bus->children[owner->bus->child_count - 1U];

		if (child->handle != NULL)
			(void)remove_child(binding, owner,
				owner->bus->child_count - 1U);
		else
			owner->bus->child_count--;
	}
	return status;
}

EFI_STATUS cdk2_usb_binding_stop(struct cdk2_usb_binding *binding,
	void *controller, UINTN child_count, void **children)
{
	struct cdk2_usb_binding_controller *owner = NULL;
	UINTN owner_index = 0U;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL ||
	    (child_count != 0U && children == NULL))
		return EFI_INVALID_PARAMETER;
	for (; owner_index < binding->count; owner_index++)
		if (binding->controllers[owner_index].handle == controller) {
			owner = &binding->controllers[owner_index];
			break;
		}
	if (owner == NULL)
		return EFI_UNSUPPORTED;
	if (child_count != 0U) {
		for (UINTN selected = 0U; selected < child_count; selected++) {
			UINTN index = 0U;

			while (index < owner->bus->child_count &&
			       owner->bus->children[index].handle != children[selected])
				index++;
			if (index == owner->bus->child_count)
				return EFI_NOT_FOUND;
			status = remove_child(binding, owner, index);
			if (EFI_ERROR(status))
				return status;
		}
		return EFI_SUCCESS;
	}
	while (owner->bus->child_count != 0U) {
		status = remove_child(binding, owner, owner->bus->child_count - 1U);
		if (EFI_ERROR(status))
			return status;
	}
	status = binding->services.uninstall_marker(binding->services.context,
		controller, owner->bus);
	if (EFI_ERROR(status))
		return status;
	status = binding->services.close_host(binding->services.context, controller);
	if (EFI_ERROR(status)) {
		(void)binding->services.install_marker(binding->services.context,
			controller, owner->bus);
		return status;
	}
	binding->services.free(binding->services.context, owner->bus);
	move_bytes(owner, owner + 1U,
		(binding->count - owner_index - 1U) * sizeof(*owner));
	memset(&binding->controllers[--binding->count], 0, sizeof(*owner));
	return EFI_SUCCESS;
}
