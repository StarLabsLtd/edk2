/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mass.h>

#include <string.h>

static void move_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *to = destination;
	const UINT8 *from = source;

	for (UINTN index = 0U; index < size; index++)
		to[index] = from[index];
}

EFI_STATUS cdk2_usb_mass_binding_init(struct cdk2_usb_mass_binding *binding,
	const struct cdk2_usb_mass_binding_services *services)
{
	if (binding == NULL || services == NULL || services->open_usb == NULL ||
	    services->close_usb == NULL || services->publish == NULL ||
	    services->remove == NULL || services->link == NULL ||
	    services->unlink == NULL || services->allocate == NULL ||
	    services->release == NULL)
		return EFI_INVALID_PARAMETER;
	memset(binding, 0, sizeof(*binding));
	binding->services = *services;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_binding_supported(struct cdk2_usb_mass_binding *binding,
	void *controller)
{
	struct cdk2_usb_io_protocol *usb;
	struct cdk2_usb_mass_device device;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->services.open_usb(binding->services.context, controller,
		&usb);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_usb_mass_init(&device, usb);
	(void)binding->services.close_usb(binding->services.context, controller);
	return status;
}

static EFI_STATUS remove_child(struct cdk2_usb_mass_binding *binding,
	struct cdk2_usb_mass_controller *owner, UINTN index)
{
	struct cdk2_usb_mass_child *child = &owner->children[index];
	EFI_STATUS status;

	status = binding->services.unlink(binding->services.context, owner->handle,
		child->handle);
	if (EFI_ERROR(status))
		return status;
	child->linked = FALSE;
	status = binding->services.remove(binding->services.context, owner->handle,
		child, child->handle);
	if (EFI_ERROR(status)) {
		if (!EFI_ERROR(binding->services.link(binding->services.context,
			owner->handle, child->handle)))
			child->linked = TRUE;
		return status;
	}
	move_bytes(child, child + 1U,
		(owner->child_count - index - 1U) * sizeof(*child));
	memset(&owner->children[--owner->child_count], 0, sizeof(*child));
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_binding_start(struct cdk2_usb_mass_binding *binding,
	void *controller)
{
	struct cdk2_usb_mass_controller *owner;
	struct cdk2_usb_io_protocol *usb;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0U; index < binding->count; index++)
		if (binding->controllers[index]->handle == controller)
			return EFI_ALREADY_STARTED;
	if (binding->count == CDK2_USB_MASS_MAX_CONTROLLERS)
		return EFI_OUT_OF_RESOURCES;
	status = binding->services.open_usb(binding->services.context, controller,
		&usb);
	if (EFI_ERROR(status))
		return status;
	status = binding->services.allocate(binding->services.context,
		sizeof(*owner), (void **)&owner);
	if (EFI_ERROR(status))
		goto close;
	memset(owner, 0, sizeof(*owner));
	owner->handle = controller;
	status = cdk2_usb_mass_init(&owner->device, usb);
	if (!EFI_ERROR(status))
		status = cdk2_usb_mass_get_max_lun(&owner->device);
	if (EFI_ERROR(status))
		goto release;
	for (UINT8 lun = 0U; lun <= owner->device.maximum_lun; lun++) {
		struct cdk2_usb_mass_child *child;

		status = cdk2_usb_mass_probe_lun(&owner->device, lun);
		if (EFI_ERROR(status))
			continue;
		child = &owner->children[owner->child_count];
		status = cdk2_usb_mass_block_init(&child->block, &owner->device, lun);
		if (EFI_ERROR(status))
			goto rollback;
		child->path = (struct cdk2_usb_mass_lun_path) { 3U, 17U,
			sizeof(child->path), lun };
		status = binding->services.publish(binding->services.context, controller,
			child, &child->handle);
		if (!EFI_ERROR(status)) {
			child->installed = TRUE;
			status = binding->services.link(binding->services.context, controller,
				child->handle);
		}
		if (EFI_ERROR(status)) {
			if (child->installed)
				(void)binding->services.remove(binding->services.context,
					controller, child, child->handle);
			goto rollback;
		}
		child->linked = TRUE;
		owner->child_count++;
	}
	if (owner->child_count == 0U) {
		status = EFI_NOT_FOUND;
		goto release;
	}
	binding->controllers[binding->count++] = owner;
	return EFI_SUCCESS;
rollback:
	while (owner->child_count != 0U)
		if (EFI_ERROR(remove_child(binding, owner, owner->child_count - 1U)))
			break;
release:
	binding->services.release(binding->services.context, owner);
close:
	(void)binding->services.close_usb(binding->services.context, controller);
	return status;
}

EFI_STATUS cdk2_usb_mass_binding_stop(struct cdk2_usb_mass_binding *binding,
	void *controller, UINTN child_count, void **children)
{
	struct cdk2_usb_mass_controller *owner = NULL;
	UINTN owner_index = 0U;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL ||
	    (child_count != 0U && children == NULL))
		return EFI_INVALID_PARAMETER;
	for (; owner_index < binding->count; owner_index++)
		if (binding->controllers[owner_index]->handle == controller) {
			owner = binding->controllers[owner_index];
			break;
		}
	if (owner == NULL)
		return EFI_UNSUPPORTED;
	if (child_count != 0U) {
		for (UINTN selected = 0U; selected < child_count; selected++) {
			UINTN index = 0U;

			while (index < owner->child_count &&
			       owner->children[index].handle != children[selected])
				index++;
			if (index == owner->child_count)
				return EFI_NOT_FOUND;
			status = remove_child(binding, owner, index);
			if (EFI_ERROR(status))
				return status;
		}
		return EFI_SUCCESS;
	}
	while (owner->child_count != 0U) {
		status = remove_child(binding, owner, owner->child_count - 1U);
		if (EFI_ERROR(status))
			return status;
	}
	status = binding->services.close_usb(binding->services.context, controller);
	if (EFI_ERROR(status))
		return status;
	binding->services.release(binding->services.context, owner);
	move_bytes(&binding->controllers[owner_index],
		&binding->controllers[owner_index + 1U],
		(binding->count - owner_index - 1U) * sizeof(owner));
	binding->controllers[--binding->count] = NULL;
	return EFI_SUCCESS;
}
