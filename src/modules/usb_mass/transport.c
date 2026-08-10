/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mass.h>

#include <string.h>

static EFI_STATUS clear_halt(struct cdk2_usb_mass_device *device, UINT8 endpoint)
{
	struct cdk2_usb_request request = { 2U, 1U, 0U, endpoint, 0U };
	UINTN length = 0U;
	UINT32 result;

	return device->usb->control_transfer(device->usb, &request, 0U, 1000U,
		NULL, &length, &result);
}

EFI_STATUS cdk2_usb_mass_reset(struct cdk2_usb_mass_device *device)
{
	struct cdk2_usb_request request = { 0x21U, 0xffU, 0U, 0U, 0U };
	UINTN length = 0U;
	UINT32 result;
	EFI_STATUS status;

	if (device == NULL || device->usb == NULL)
		return EFI_INVALID_PARAMETER;
	status = device->usb->control_transfer(device->usb, &request, 0U, 1000U,
		NULL, &length, &result);
	if (!EFI_ERROR(status))
		status = clear_halt(device, device->bulk_in);
	if (!EFI_ERROR(status))
		status = clear_halt(device, device->bulk_out);
	return status;
}

EFI_STATUS cdk2_usb_mass_get_max_lun(struct cdk2_usb_mass_device *device)
{
	struct cdk2_usb_request request = { 0xa1U, 0xfeU, 0U, 0U, 1U };
	UINTN length = 1U;
	UINT32 result;
	UINT8 value = 0U;
	EFI_STATUS status;

	if (device == NULL || device->usb == NULL)
		return EFI_INVALID_PARAMETER;
	status = device->usb->control_transfer(device->usb, &request, 1U, 1000U,
		&value, &length, &result);
	if (status == EFI_DEVICE_ERROR) {
		device->maximum_lun = 0U;
		return EFI_SUCCESS;
	}
	if (EFI_ERROR(status) || length != 1U || value > 15U)
		return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
	device->maximum_lun = value;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_transport(struct cdk2_usb_mass_device *device,
	UINT8 lun, const void *command, UINT8 command_length, void *data,
	UINT32 *length, BOOLEAN input, UINTN timeout)
{
	struct cdk2_usb_mass_cbw cbw;
	struct cdk2_usb_mass_csw csw;
	UINTN transfer;
	UINT32 result, actual;
	EFI_STATUS status;

	if (device == NULL || length == NULL || (*length != 0U && data == NULL))
		return EFI_INVALID_PARAMETER;
	status = cdk2_usb_mass_build_cbw(device, lun, command, command_length,
		*length, input, &cbw);
	if (EFI_ERROR(status))
		return status;
	transfer = sizeof(cbw);
	status = device->usb->bulk_transfer(device->usb, device->bulk_out, &cbw,
		&transfer, timeout, &result);
	if (EFI_ERROR(status) || transfer != sizeof(cbw))
		goto recover;
	actual = 0U;
	if (*length != 0U) {
		transfer = *length;
		status = device->usb->bulk_transfer(device->usb,
			input ? device->bulk_in : device->bulk_out, data, &transfer,
			timeout, &result);
		actual = (UINT32)transfer;
		if (EFI_ERROR(status) && status != EFI_DEVICE_ERROR)
			goto recover;
	}
	transfer = sizeof(csw);
	status = device->usb->bulk_transfer(device->usb, device->bulk_in, &csw,
		&transfer, timeout, &result);
	if (EFI_ERROR(status))
		goto recover;
	status = cdk2_usb_mass_validate_csw(&cbw, &csw, (UINT32)transfer, length);
	if (!EFI_ERROR(status) && *length != actual)
		return EFI_COMPROMISED_DATA;
	return status;
recover:
	(void)cdk2_usb_mass_reset(device);
	return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
}
