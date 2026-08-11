/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_keyboard.h>

#include <string.h>

static UINTN find_controller(struct cdk2_usb_keyboard_binding *binding,
	void *controller)
{
	UINTN index = 0U;

	while (index < binding->count &&
	       binding->controllers[index]->handle != controller)
		index++;
	return index;
}

EFI_STATUS cdk2_usb_keyboard_binding_init(
	struct cdk2_usb_keyboard_binding *binding,
	const struct cdk2_usb_keyboard_binding_services *services)
{
	if (binding == NULL || services == NULL || services->open == NULL ||
	    services->close == NULL || services->create_event == NULL ||
	    services->close_event == NULL || services->publish == NULL ||
	    services->remove == NULL || services->allocate == NULL ||
	    services->release == NULL)
		return EFI_INVALID_PARAMETER;
	memset(binding, 0, sizeof(*binding));
	binding->services = *services;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_keyboard_binding_supported(
	struct cdk2_usb_keyboard_binding *binding, void *controller)
{
	struct cdk2_usb_io_protocol *usb;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_controller(binding, controller) != binding->count)
		return EFI_ALREADY_STARTED;
	status = binding->services.open(binding->services.context, controller, &usb);
	if (!EFI_ERROR(status))
		status = binding->services.close(binding->services.context, controller);
	return status;
}

EFI_STATUS cdk2_usb_keyboard_binding_start(
	struct cdk2_usb_keyboard_binding *binding, void *controller)
{
	struct cdk2_usb_keyboard_controller *owner = NULL;
	struct cdk2_usb_io_protocol *usb;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_controller(binding, controller) != binding->count)
		return EFI_ALREADY_STARTED;
	if (binding->count == CDK2_USB_KEYBOARD_CONTROLLERS)
		return EFI_OUT_OF_RESOURCES;
	status = binding->services.open(binding->services.context, controller, &usb);
	if (EFI_ERROR(status))
		return status;
	status = binding->services.allocate(binding->services.context,
		sizeof(*owner), (void **)&owner);
	if (EFI_ERROR(status))
		goto close;
	memset(owner, 0, sizeof(*owner)); owner->handle = controller;
	status = binding->services.create_event(binding->services.context,
		owner, FALSE, &owner->wait);
	if (!EFI_ERROR(status))
		status = binding->services.create_event(binding->services.context,
			owner, TRUE, &owner->wait_ex);
	if (!EFI_ERROR(status))
		status = cdk2_usb_keyboard_start_io(&owner->device, usb);
	if (!EFI_ERROR(status))
		status = cdk2_usb_keyboard_protocol_init(&owner->device, owner->wait,
			owner->wait_ex);
	if (!EFI_ERROR(status))
		status = binding->services.publish(binding->services.context,
			controller, owner);
	if (!EFI_ERROR(status)) {
		owner->installed = TRUE;
		binding->controllers[binding->count++] = owner;
		return EFI_SUCCESS;
	}
	if (owner->device.active)
		(void)cdk2_usb_keyboard_stop_io(&owner->device);
	if (owner->wait_ex != NULL)
		(void)binding->services.close_event(binding->services.context,
			owner->wait_ex);
	if (owner->wait != NULL)
		(void)binding->services.close_event(binding->services.context,
			owner->wait);
	binding->services.release(binding->services.context, owner);
close:
	(void)binding->services.close(binding->services.context, controller);
	return status;
}

EFI_STATUS cdk2_usb_keyboard_binding_stop(
	struct cdk2_usb_keyboard_binding *binding, void *controller)
{
	struct cdk2_usb_keyboard_controller *owner;
	UINTN index;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	index = find_controller(binding, controller);
	if (index == binding->count)
		return EFI_NOT_STARTED;
	owner = binding->controllers[index];
	status = binding->services.remove(binding->services.context, controller,
		owner);
	if (EFI_ERROR(status))
		return status;
	owner->installed = FALSE;
	status = cdk2_usb_keyboard_stop_io(&owner->device);
	if (EFI_ERROR(status)) {
		if (!EFI_ERROR(binding->services.publish(binding->services.context,
		    controller, owner)))
			owner->installed = TRUE;
		return status;
	}
	status = binding->services.close(binding->services.context, controller);
	if (EFI_ERROR(status))
		return status;
	(void)binding->services.close_event(binding->services.context,
		owner->wait_ex);
	(void)binding->services.close_event(binding->services.context, owner->wait);
	binding->services.release(binding->services.context, owner);
	for (UINTN move = index + 1U; move < binding->count; move++)
		binding->controllers[move - 1U] = binding->controllers[move];
	binding->count--;
	return EFI_SUCCESS;
}
