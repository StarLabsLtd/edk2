/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_disk.h>

static UINT32 get_be32(const UINT8 *value)
{
	return (UINT32)value[0] << 24 | (UINT32)value[1] << 16 |
		(UINT32)value[2] << 8 | value[3];
}

static UINT64 get_be64(const UINT8 *value)
{
	return (UINT64)get_be32(value) << 32 | get_be32(value + 4U);
}

static void put_be16(UINT8 *value, UINT16 number)
{
	value[0] = (UINT8)(number >> 8);
	value[1] = (UINT8)number;
}

static void put_be32(UINT8 *value, UINT32 number)
{
	value[0] = (UINT8)(number >> 24);
	value[1] = (UINT8)(number >> 16);
	value[2] = (UINT8)(number >> 8);
	value[3] = (UINT8)number;
}

static void put_be64(UINT8 *value, UINT64 number)
{
	put_be32(value, (UINT32)(number >> 32));
	put_be32(value + 4U, (UINT32)number);
}

EFI_STATUS cdk2_scsi_disk_parse_capacity10(const UINT8 response[8],
	UINT64 *last_block, UINT32 *block_size, BOOLEAN *needs_capacity16)
{
	UINT32 last;
	UINT32 size;

	if (response == NULL || last_block == NULL || block_size == NULL ||
	    needs_capacity16 == NULL)
		return EFI_INVALID_PARAMETER;
	last = get_be32(response);
	size = get_be32(response + 4U);
	if (size == 0U || (size & (size - 1U)) != 0U)
		return EFI_DEVICE_ERROR;
	*last_block = last;
	*block_size = size;
	*needs_capacity16 = last == UINT32_MAX;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_parse_capacity16(const UINT8 response[32],
	UINT64 *last_block, UINT32 *block_size)
{
	UINT64 last;
	UINT32 size;

	if (response == NULL || last_block == NULL || block_size == NULL)
		return EFI_INVALID_PARAMETER;
	last = get_be64(response);
	size = get_be32(response + 8U);
	if (last == UINT64_MAX || size == 0U || (size & (size - 1U)) != 0U)
		return EFI_DEVICE_ERROR;
	*last_block = last;
	*block_size = size;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_build_rw(BOOLEAN write, UINT64 lba, UINT32 blocks,
	BOOLEAN cdb16, struct cdk2_scsi_disk_command *command)
{
	if (command == NULL || blocks == 0U)
		return EFI_INVALID_PARAMETER;
	*command = (struct cdk2_scsi_disk_command) { 0 };
	command->blocks = blocks;
	if (!cdb16) {
		if (lba > UINT32_MAX || blocks > UINT16_MAX)
			return EFI_BAD_BUFFER_SIZE;
		command->cdb[0] = write ? 0x2aU : 0x28U;
		put_be32(command->cdb + 2U, (UINT32)lba);
		put_be16(command->cdb + 7U, (UINT16)blocks);
		command->cdb_length = 10U;
	} else {
		command->cdb[0] = write ? 0x8aU : 0x88U;
		put_be64(command->cdb + 2U, lba);
		put_be32(command->cdb + 10U, blocks);
		command->cdb_length = 16U;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_validate(const struct cdk2_scsi_disk_media *media,
	UINT32 media_id, UINT64 lba, UINTN size, const void *buffer, BOOLEAN write)
{
	UINT64 blocks;

	if (media == NULL)
		return EFI_INVALID_PARAMETER;
	if (media_id != media->media_id)
		return EFI_MEDIA_CHANGED;
	if (!media->present)
		return EFI_NO_MEDIA;
	if (buffer == NULL && size != 0U)
		return EFI_INVALID_PARAMETER;
	if (size == 0U)
		return EFI_SUCCESS;
	if (media->block_size == 0U || size % media->block_size != 0U)
		return EFI_BAD_BUFFER_SIZE;
	blocks = size / media->block_size;
	if (lba > media->last_block || blocks - 1U > media->last_block - lba)
		return EFI_INVALID_PARAMETER;
	if (media->io_align > 1U && ((media->io_align & (media->io_align - 1U)) != 0U ||
	    (UINTN)buffer % media->io_align != 0U))
		return EFI_INVALID_PARAMETER;
	if (write && media->read_only)
		return EFI_WRITE_PROTECTED;
	return EFI_SUCCESS;
}
