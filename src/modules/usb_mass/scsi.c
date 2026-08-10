/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mass.h>

#include <string.h>

static void put32(UINT8 *bytes, UINT32 value)
{
	bytes[0] = (UINT8)(value >> 24); bytes[1] = (UINT8)(value >> 16);
	bytes[2] = (UINT8)(value >> 8); bytes[3] = (UINT8)value;
}

static void put64(UINT8 *bytes, UINT64 value)
{
	for (UINTN index = 8U; index > 0U; index--) {
		bytes[index - 1U] = (UINT8)value;
		value >>= 8;
	}
}

EFI_STATUS cdk2_usb_mass_probe_lun(struct cdk2_usb_mass_device *device,
	UINT8 lun)
{
	UINT8 inquiry_command[6] = { 0x12U, 0U, 0U, 0U, 36U, 0U };
	UINT8 inquiry[36], capacity[32], command[16] = { 0 };
	UINT32 length = sizeof(inquiry);
	EFI_STATUS status;

	if (device == NULL || lun > device->maximum_lun)
		return EFI_INVALID_PARAMETER;
	status = cdk2_usb_mass_transport(device, lun, inquiry_command,
		sizeof(inquiry_command), inquiry, &length, TRUE, 3000U);
	if (EFI_ERROR(status) || length < 5U || (inquiry[0] & 0x1fU) != 0U)
		return EFI_ERROR(status) ? status : EFI_UNSUPPORTED;
	device->media[lun] = (struct cdk2_usb_mass_media) { .lun = lun,
		.removable = (inquiry[1] & 0x80U) != 0U, .media_id = 0U };
	command[0] = 0x25U;
	length = 8U;
	status = cdk2_usb_mass_transport(device, lun, command, 10U, capacity,
		&length, TRUE, 3000U);
	if (!EFI_ERROR(status) && length == 8U)
		status = cdk2_usb_mass_parse_capacity10(capacity, &device->media[lun]);
	if (status == EFI_NOT_READY) {
		memset(command, 0, sizeof(command));
		command[0] = 0x9eU; command[1] = 0x10U; command[13] = sizeof(capacity);
		length = sizeof(capacity);
		status = cdk2_usb_mass_transport(device, lun, command, sizeof(command),
			capacity, &length, TRUE, 3000U);
		if (!EFI_ERROR(status) && length == sizeof(capacity))
			status = cdk2_usb_mass_parse_capacity16(capacity,
				&device->media[lun]);
	}
	if (!EFI_ERROR(status) && device->media_count <= lun)
		device->media_count = lun + 1U;
	return status;
}

static EFI_STATUS transfer(struct cdk2_usb_mass_device *device, UINT8 lun,
	UINT64 lba, UINTN blocks, void *buffer, BOOLEAN input)
{
	struct cdk2_usb_mass_media *media;
	UINT8 command[16];
	UINT8 *bytes = buffer;

	if (device == NULL || lun >= device->media_count ||
	    (blocks != 0U && buffer == NULL))
		return EFI_INVALID_PARAMETER;
	media = &device->media[lun];
	if (!media->present)
		return EFI_NO_MEDIA;
	if (!input && media->readonly)
		return EFI_WRITE_PROTECTED;
	if (blocks == 0U)
		return EFI_SUCCESS;
	if (lba > media->last_block || blocks - 1U > media->last_block - lba)
		return EFI_INVALID_PARAMETER;
	while (blocks != 0U) {
		UINTN count = blocks > 0xffffU ? 0xffffU : blocks;
		UINT64 byte_count = (UINT64)count * media->block_size;
		UINT32 length;
		EFI_STATUS status;

		if (byte_count > 0xffffffffU)
			return EFI_BAD_BUFFER_SIZE;
		memset(command, 0, sizeof(command));
		if (lba <= 0xffffffffU && count <= 0xffffU) {
			command[0] = input ? 0x28U : 0x2aU;
			put32(command + 2U, (UINT32)lba);
			command[7] = (UINT8)(count >> 8);
			command[8] = (UINT8)count;
			length = (UINT32)byte_count;
			status = cdk2_usb_mass_transport(device, lun, command, 10U, bytes,
				&length, input, 30000U);
		} else {
			command[0] = input ? 0x88U : 0x8aU;
			put64(command + 2U, lba);
			put32(command + 10U, (UINT32)count);
			length = (UINT32)byte_count;
			status = cdk2_usb_mass_transport(device, lun, command, 16U, bytes,
				&length, input, 30000U);
		}
		if (EFI_ERROR(status) || length != byte_count)
			return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
		bytes += length; lba += count; blocks -= count;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_read(struct cdk2_usb_mass_device *device, UINT8 lun,
	UINT64 lba, UINTN blocks, void *buffer)
{ return transfer(device, lun, lba, blocks, buffer, TRUE); }

EFI_STATUS cdk2_usb_mass_write(struct cdk2_usb_mass_device *device, UINT8 lun,
	UINT64 lba, UINTN blocks, const void *buffer)
{ return transfer(device, lun, lba, blocks, (void *)buffer, FALSE); }
