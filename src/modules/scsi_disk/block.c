/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_disk.h>

#include <stddef.h>
#include <string.h>

#define CDK2_BLOCK_IO_REVISION3 0x0002001fULL

static struct cdk2_scsi_disk_block *from_block(struct cdk2_block_io *block)
{
	return block == NULL ? NULL : (void *)((UINT8 *)block -
		offsetof(struct cdk2_scsi_disk_block, block));
}

static struct cdk2_scsi_disk_block *from_block2(struct cdk2_block_io2 *block)
{
	return block == NULL ? NULL : (void *)((UINT8 *)block -
		offsetof(struct cdk2_scsi_disk_block, block2));
}

static uint64_t CDK2_MS_ABI reset(struct cdk2_block_io *block,
	uint8_t extended_verification)
{
	struct cdk2_scsi_disk_block *instance = from_block(block);

	(void)extended_verification;
	return instance == NULL || instance->async == NULL ? EFI_INVALID_PARAMETER :
		cdk2_scsi_disk_async_reset(instance->async);
}

static uint64_t CDK2_MS_ABI read_blocks(struct cdk2_block_io *block,
	uint32_t media_id, uint64_t lba, size_t size, void *buffer)
{
	struct cdk2_scsi_disk_block *instance = from_block(block);

	return instance == NULL ? EFI_INVALID_PARAMETER :
		cdk2_scsi_disk_read(instance->disk, media_id, lba, size, buffer);
}

static uint64_t CDK2_MS_ABI write_blocks(struct cdk2_block_io *block,
	uint32_t media_id, uint64_t lba, size_t size, void *buffer)
{
	struct cdk2_scsi_disk_block *instance = from_block(block);

	return instance == NULL ? EFI_INVALID_PARAMETER :
		cdk2_scsi_disk_write(instance->disk, media_id, lba, size, buffer);
}

static uint64_t CDK2_MS_ABI flush_blocks(struct cdk2_block_io *block)
{
	return from_block(block) == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI reset_ex(struct cdk2_block_io2 *block,
	BOOLEAN extended_verification)
{
	struct cdk2_scsi_disk_block *instance = from_block2(block);

	(void)extended_verification;
	return instance == NULL || instance->async == NULL ? EFI_INVALID_PARAMETER :
		cdk2_scsi_disk_async_reset(instance->async);
}

static EFI_STATUS CDK2_MS_ABI read_blocks_ex(struct cdk2_block_io2 *block,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token, UINTN size,
	void *buffer)
{
	struct cdk2_scsi_disk_block *instance = from_block2(block);

	return instance == NULL || instance->async == NULL ? EFI_INVALID_PARAMETER :
		cdk2_scsi_disk_async_submit(instance->async, media_id, lba, size, buffer,
			FALSE, token);
}

static EFI_STATUS CDK2_MS_ABI write_blocks_ex(struct cdk2_block_io2 *block,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token, UINTN size,
	void *buffer)
{
	struct cdk2_scsi_disk_block *instance = from_block2(block);

	return instance == NULL || instance->async == NULL ? EFI_INVALID_PARAMETER :
		cdk2_scsi_disk_async_submit(instance->async, media_id, lba, size, buffer,
			TRUE, token);
}

static EFI_STATUS CDK2_MS_ABI flush_blocks_ex(struct cdk2_block_io2 *block,
	struct cdk2_block_io2_token *token)
{
	struct cdk2_scsi_disk_block *instance = from_block2(block);

	if (instance == NULL || instance->async == NULL || token == NULL ||
	    token->event == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_scsi_disk_async_flush(instance->async, token);
}

EFI_STATUS cdk2_scsi_disk_block_init(struct cdk2_scsi_disk_block *instance,
	struct cdk2_scsi_disk *disk, struct cdk2_scsi_disk_async *async)
{
	if (instance == NULL || disk == NULL || async == NULL)
		return EFI_INVALID_PARAMETER;
	memset(instance, 0, sizeof(*instance));
	instance->disk = disk;
	instance->async = async;
	instance->media = (struct cdk2_block_media) { .media_id = disk->media.media_id,
		.removable_media = disk->media.removable,
		.media_present = disk->media.present, .read_only = disk->media.read_only,
		.block_size = disk->media.block_size, .io_align = disk->media.io_align,
		.last_block = disk->media.last_block };
	instance->block = (struct cdk2_block_io) { CDK2_BLOCK_IO_REVISION3,
		&instance->media, reset, read_blocks, write_blocks, flush_blocks };
	instance->block2 = (struct cdk2_block_io2) { &instance->media, reset_ex,
		read_blocks_ex, write_blocks_ex, flush_blocks_ex };
	return EFI_SUCCESS;
}
