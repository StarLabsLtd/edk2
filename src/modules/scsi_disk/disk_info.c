/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_disk.h>

#include <stddef.h>
#include <string.h>

static const EFI_GUID scsi_interface = { 0x08f74baa, 0xea36, 0x41d9,
	{ 0x95, 0x21, 0x21, 0xa7, 0x0f, 0x87, 0x80, 0xbc } };

static struct cdk2_scsi_disk_bound_controller *from_info(
	struct cdk2_scsi_disk_info *info)
{
	return info == NULL ? NULL : (void *)((UINT8 *)info -
		offsetof(struct cdk2_scsi_disk_bound_controller, disk_info));
}

static EFI_STATUS copy_data(const UINT8 *source, UINT32 source_size, void *buffer,
	UINT32 *size)
{
	if (size == NULL)
		return EFI_INVALID_PARAMETER;
	if (buffer == NULL || *size < source_size) {
		*size = source_size;
		return EFI_BUFFER_TOO_SMALL;
	}
	memcpy(buffer, source, source_size);
	*size = source_size;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_inquiry(struct cdk2_scsi_disk_info *info,
	void *buffer, UINT32 *size)
{
	struct cdk2_scsi_disk_bound_controller *bound = from_info(info);

	return bound == NULL ? EFI_INVALID_PARAMETER : copy_data(bound->disk.inquiry,
		sizeof(bound->disk.inquiry), buffer, size);
}

static EFI_STATUS CDK2_MS_ABI get_identify(struct cdk2_scsi_disk_info *info,
	void *buffer, UINT32 *size)
{
	(void)buffer; (void)size;
	return from_info(info) == NULL ? EFI_INVALID_PARAMETER : EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI get_sense(struct cdk2_scsi_disk_info *info,
	void *buffer, UINT32 *size, UINT8 *number)
{
	struct cdk2_scsi_disk_bound_controller *bound = from_info(info);

	if (bound == NULL || number == NULL)
		return EFI_INVALID_PARAMETER;
	if (bound->disk.sense_length == 0U) {
		*number = 0U;
		return EFI_NOT_FOUND;
	}
	*number = 1U;
	return copy_data(bound->disk.sense, bound->disk.sense_length, buffer, size);
}

static EFI_STATUS CDK2_MS_ABI which_ide(struct cdk2_scsi_disk_info *info,
	UINT32 *channel, UINT32 *device)
{
	(void)channel; (void)device;
	return from_info(info) == NULL ? EFI_INVALID_PARAMETER : EFI_UNSUPPORTED;
}

EFI_STATUS cdk2_scsi_disk_info_init(
	struct cdk2_scsi_disk_bound_controller *bound)
{
	if (bound == NULL)
		return EFI_INVALID_PARAMETER;
	bound->disk_info = (struct cdk2_scsi_disk_info) { scsi_interface, get_inquiry,
		get_identify, get_sense, which_ide };
	return EFI_SUCCESS;
}
