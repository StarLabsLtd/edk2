/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_disk.h>

static EFI_STATUS transfer(struct cdk2_scsi_disk *disk, UINT32 media_id,
	UINT64 lba, UINTN size, void *buffer, BOOLEAN write)
{
	UINT64 remaining;
	UINT32 maximum;
	UINT8 *position = buffer;
	EFI_STATUS status;

	if (disk == NULL || disk->transport.execute == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_scsi_disk_validate(&disk->media, media_id, lba, size, buffer,
		write);
	if (EFI_ERROR(status) || size == 0U)
		return status;
	remaining = size / disk->media.block_size;
	maximum = disk->cdb16 ? UINT32_MAX : UINT16_MAX;
	if (maximum > UINT32_MAX / disk->media.block_size)
		maximum = UINT32_MAX / disk->media.block_size;
	if (maximum == 0U)
		return EFI_BAD_BUFFER_SIZE;
	while (remaining != 0U) {
		struct cdk2_scsi_disk_command command;
		UINT32 blocks = remaining > maximum ? maximum : (UINT32)remaining;
		UINT64 bytes64 = (UINT64)blocks * disk->media.block_size;
		UINT32 bytes;
		UINT8 host_status = 0;
		UINT8 target_status = 0;

		if (bytes64 > UINT32_MAX)
			return EFI_BAD_BUFFER_SIZE;
		bytes = (UINT32)bytes64;
		status = cdk2_scsi_disk_build_rw(write, lba, blocks, disk->cdb16,
			&command);
		if (EFI_ERROR(status))
			return status;
		status = disk->transport.execute(disk->transport.context, &command,
			position, bytes, write, &host_status, &target_status);
		if (EFI_ERROR(status))
			return status;
		if (host_status != 0U || target_status != 0U)
			return EFI_DEVICE_ERROR;
		position += bytes;
		lba += blocks;
		remaining -= blocks;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_read(struct cdk2_scsi_disk *disk, UINT32 media_id,
	UINT64 lba, UINTN size, void *buffer)
{
	return transfer(disk, media_id, lba, size, buffer, FALSE);
}

EFI_STATUS cdk2_scsi_disk_write(struct cdk2_scsi_disk *disk, UINT32 media_id,
	UINT64 lba, UINTN size, const void *buffer)
{
	return transfer(disk, media_id, lba, size, (void *)buffer, TRUE);
}
