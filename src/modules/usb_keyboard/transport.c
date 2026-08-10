/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_keyboard.h>

#include <string.h>

static EFI_STATUS CDK2_MS_ABI receive(void *data, UINTN length, void *context,
	UINT32 status)
{
	struct cdk2_usb_keyboard_device *device = context;

	if (device == NULL || !device->active)
		return EFI_NOT_READY;
	if (status != 0U)
		return EFI_DEVICE_ERROR;
	return cdk2_usb_keyboard_report(&device->keyboard, data, length);
}

static EFI_STATUS class_request(struct cdk2_usb_io_protocol *usb,
	UINT8 request_code, UINT16 value, UINT16 index)
{
	struct cdk2_usb_request request = { 0x21U, request_code, value, index, 0U };
	UINTN length = 0U;
	UINT32 result;

	return usb->control_transfer(usb, &request, 2U, 1000U, NULL, &length,
		&result);
}

EFI_STATUS cdk2_usb_keyboard_start_io(struct cdk2_usb_keyboard_device *device,
	struct cdk2_usb_io_protocol *usb)
{
	UINT8 interface[9], endpoint[7];
	EFI_STATUS status;

	if (device == NULL || usb == NULL || usb->get_interface_descriptor == NULL ||
	    usb->get_endpoint_descriptor == NULL || usb->control_transfer == NULL ||
	    usb->async_interrupt_transfer == NULL)
		return EFI_INVALID_PARAMETER;
	status = usb->get_interface_descriptor(usb, interface);
	if (EFI_ERROR(status))
		return status;
	if (interface[5] != 3U || interface[6] != 1U || interface[7] != 1U)
		return EFI_UNSUPPORTED;
	status = usb->get_endpoint_descriptor(usb, 0U, endpoint);
	if (EFI_ERROR(status))
		return status;
	if ((endpoint[2] & 0x80U) == 0U || (endpoint[3] & 3U) != 3U ||
	    endpoint[6] == 0U)
		return EFI_UNSUPPORTED;
	memset(device, 0, sizeof(*device));
	device->usb = usb; device->endpoint = endpoint[2];
	device->packet_size = endpoint[4] | (UINT16)endpoint[5] << 8;
	device->interval = endpoint[6];
	if (device->packet_size < sizeof(struct cdk2_usb_keyboard_report))
		return EFI_UNSUPPORTED;
	status = cdk2_usb_keyboard_init(&device->keyboard);
	if (!EFI_ERROR(status))
		status = class_request(usb, 11U, 0U, interface[2]);
	if (!EFI_ERROR(status))
		status = class_request(usb, 10U, 0U, interface[2]);
	if (EFI_ERROR(status))
		return status;
	device->active = TRUE;
	status = usb->async_interrupt_transfer(usb, device->endpoint, TRUE,
		device->interval, sizeof(struct cdk2_usb_keyboard_report), receive,
		device);
	if (EFI_ERROR(status))
		device->active = FALSE;
	return status;
}

EFI_STATUS cdk2_usb_keyboard_stop_io(struct cdk2_usb_keyboard_device *device)
{
	EFI_STATUS status;

	if (device == NULL || device->usb == NULL)
		return EFI_INVALID_PARAMETER;
	status = device->usb->async_interrupt_transfer(device->usb,
		device->endpoint, FALSE, device->interval,
		sizeof(struct cdk2_usb_keyboard_report), NULL, device);
	if (!EFI_ERROR(status))
		device->active = FALSE;
	return status;
}
