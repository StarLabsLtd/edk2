/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mass.h>

#include <string.h>

static UINT32 be32(const UINT8 *bytes)
{
	return (UINT32)bytes[0] << 24 | (UINT32)bytes[1] << 16 |
		(UINT32)bytes[2] << 8 | bytes[3];
}

EFI_STATUS cdk2_usb_mass_init(struct cdk2_usb_mass_device *device,
	struct cdk2_usb_io_protocol *usb)
{
	UINT8 descriptor[9];
	EFI_STATUS status;

	if (device == NULL || usb == NULL)
		return EFI_INVALID_PARAMETER;
	memset(device, 0, sizeof(*device));
	device->usb = usb;
	status = usb->get_interface_descriptor(usb, descriptor);
	if (EFI_ERROR(status))
		return status;
	if (descriptor[5] != 8U || descriptor[6] != 6U || descriptor[7] != 0x50U)
		return EFI_UNSUPPORTED;
	for (UINT8 index = 0U; index < descriptor[4]; index++) {
		UINT8 endpoint[7];

		status = usb->get_endpoint_descriptor(usb, index, endpoint);
		if (EFI_ERROR(status))
			return status;
		if ((endpoint[3] & 3U) != 2U)
			continue;
		if ((endpoint[2] & 0x80U) != 0U)
			device->bulk_in = endpoint[2];
		else
			device->bulk_out = endpoint[2];
	}
	return device->bulk_in == 0U || device->bulk_out == 0U ?
		EFI_UNSUPPORTED : EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_build_cbw(struct cdk2_usb_mass_device *device,
	UINT8 lun, const void *command, UINT8 command_length, UINT32 transfer_length,
	BOOLEAN input, struct cdk2_usb_mass_cbw *cbw)
{
	if (device == NULL || command == NULL || cbw == NULL ||
	    command_length == 0U || command_length > 16U || lun > 15U)
		return EFI_INVALID_PARAMETER;
	memset(cbw, 0, sizeof(*cbw));
	cbw->signature = CDK2_USB_MASS_CBW_SIGNATURE;
	cbw->tag = ++device->next_tag;
	if (cbw->tag == 0U)
		cbw->tag = ++device->next_tag;
	cbw->transfer_length = transfer_length;
	cbw->flags = input ? 0x80U : 0U;
	cbw->lun = lun;
	cbw->command_length = command_length;
	memcpy(cbw->command, command, command_length);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_validate_csw(const struct cdk2_usb_mass_cbw *cbw,
	const struct cdk2_usb_mass_csw *csw, UINT32 actual, UINT32 *transferred)
{
	if (cbw == NULL || csw == NULL || transferred == NULL)
		return EFI_INVALID_PARAMETER;
	if (csw->signature != CDK2_USB_MASS_CSW_SIGNATURE || csw->tag != cbw->tag ||
	    csw->residue > cbw->transfer_length || actual != sizeof(*csw) ||
	    csw->status > 2U)
		return EFI_COMPROMISED_DATA;
	*transferred = cbw->transfer_length - csw->residue;
	return csw->status == 0U ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS cdk2_usb_mass_parse_capacity10(const UINT8 bytes[8],
	struct cdk2_usb_mass_media *media)
{
	UINT32 last, block;

	if (bytes == NULL || media == NULL)
		return EFI_INVALID_PARAMETER;
	last = be32(bytes);
	block = be32(bytes + 4U);
	if (last == 0xffffffffU)
		return EFI_NOT_READY;
	if (block == 0U || (block & (block - 1U)) != 0U)
		return EFI_COMPROMISED_DATA;
	media->last_block = last;
	media->block_size = block;
	media->present = TRUE;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_parse_capacity16(const UINT8 bytes[32],
	struct cdk2_usb_mass_media *media)
{
	UINT64 last = 0U;
	UINT32 block;

	if (bytes == NULL || media == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0U; index < 8U; index++)
		last = last << 8 | bytes[index];
	block = be32(bytes + 8U);
	if (block == 0U || (block & (block - 1U)) != 0U)
		return EFI_COMPROMISED_DATA;
	media->last_block = last;
	media->block_size = block;
	media->present = TRUE;
	return EFI_SUCCESS;
}
