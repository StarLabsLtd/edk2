/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mass.h>

#include <stddef.h>
#include <string.h>

#ifndef EFI_MEDIA_CHANGED
#define EFI_MEDIA_CHANGED EFIERR(13)
#endif

static struct cdk2_usb_mass_block *owner(struct cdk2_block_io *protocol)
{
	return (struct cdk2_usb_mass_block *)((UINT8 *)protocol -
		offsetof(struct cdk2_usb_mass_block, block));
}

static struct cdk2_usb_mass_block *owner2(struct cdk2_block_io2 *protocol)
{
	return (struct cdk2_usb_mass_block *)((UINT8 *)protocol -
		offsetof(struct cdk2_usb_mass_block, block2));
}

static EFI_STATUS validate(struct cdk2_usb_mass_block *block, UINT32 media_id,
	UINT64 lba, UINTN size, const void *buffer, UINTN *blocks)
{
	if (media_id != block->media.media_id)
		return EFI_MEDIA_CHANGED;
	if (!block->media.media_present)
		return EFI_NO_MEDIA;
	if (size != 0U && buffer == NULL)
		return EFI_INVALID_PARAMETER;
	if (size == 0U) {
		*blocks = 0U;
		return EFI_SUCCESS;
	}
	if (size % block->media.block_size != 0U)
		return EFI_BAD_BUFFER_SIZE;
	*blocks = size / block->media.block_size;
	if (lba > block->media.last_block ||
	    *blocks - 1U > block->media.last_block - lba)
		return EFI_INVALID_PARAMETER;
	if (block->media.io_align > 1U &&
	    ((UINTN)buffer & (block->media.io_align - 1U)) != 0U)
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI reset(struct cdk2_block_io *protocol,
	uint8_t extended)
{
	(void)extended;
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_usb_mass_reset(owner(protocol)->device);
}

static uint64_t CDK2_MS_ABI read_blocks(struct cdk2_block_io *protocol,
	uint32_t media_id, uint64_t lba, size_t size, void *buffer)
{
	struct cdk2_usb_mass_block *block;
	UINTN blocks;
	EFI_STATUS status;

	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	block = owner(protocol);
	status = validate(block, media_id, lba, size, buffer, &blocks);
	return EFI_ERROR(status) ? status : cdk2_usb_mass_read(block->device,
		block->lun, lba, blocks, buffer);
}

static uint64_t CDK2_MS_ABI write_blocks(struct cdk2_block_io *protocol,
	uint32_t media_id, uint64_t lba, size_t size, void *buffer)
{
	struct cdk2_usb_mass_block *block;
	UINTN blocks;
	EFI_STATUS status;

	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	block = owner(protocol);
	status = validate(block, media_id, lba, size, buffer, &blocks);
	if (!EFI_ERROR(status) && block->media.read_only)
		status = EFI_WRITE_PROTECTED;
	return EFI_ERROR(status) ? status : cdk2_usb_mass_write(block->device,
		block->lun, lba, blocks, buffer);
}

static uint64_t CDK2_MS_ABI flush(struct cdk2_block_io *protocol)
{ return protocol == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS; }

static EFI_STATUS CDK2_MS_ABI reset2(struct cdk2_block_io2 *protocol,
	BOOLEAN extended)
{
	(void)extended;
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_usb_mass_reset(owner2(protocol)->device);
}

static EFI_STATUS block2_sync(struct cdk2_block_io2 *protocol, UINT32 media_id,
	UINT64 lba, struct cdk2_block_io2_token *token, UINTN size, void *buffer,
	BOOLEAN write)
{
	struct cdk2_usb_mass_block *block;
	EFI_STATUS status;

	if (protocol == NULL || token == NULL)
		return EFI_INVALID_PARAMETER;
	if (token->event != NULL)
		return EFI_UNSUPPORTED;
	block = owner2(protocol);
	status = write ? write_blocks(&block->block, media_id, lba, size, buffer) :
		read_blocks(&block->block, media_id, lba, size, buffer);
	token->transaction_status = status;
	return status;
}

static EFI_STATUS CDK2_MS_ABI read_blocks2(struct cdk2_block_io2 *protocol,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token, UINTN size,
	void *buffer)
{ return block2_sync(protocol, media_id, lba, token, size, buffer, FALSE); }

static EFI_STATUS CDK2_MS_ABI write_blocks2(struct cdk2_block_io2 *protocol,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token, UINTN size,
	void *buffer)
{ return block2_sync(protocol, media_id, lba, token, size, buffer, TRUE); }

static EFI_STATUS CDK2_MS_ABI flush2(struct cdk2_block_io2 *protocol,
	struct cdk2_block_io2_token *token)
{
	if (protocol == NULL || token == NULL)
		return EFI_INVALID_PARAMETER;
	if (token->event != NULL)
		return EFI_UNSUPPORTED;
	token->transaction_status = EFI_SUCCESS;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mass_block_init(struct cdk2_usb_mass_block *block,
	struct cdk2_usb_mass_device *device, UINT8 lun)
{
	struct cdk2_usb_mass_media *media;

	if (block == NULL || device == NULL || lun >= device->media_count ||
	    !device->media[lun].present)
		return EFI_INVALID_PARAMETER;
	memset(block, 0, sizeof(*block));
	block->device = device;
	block->lun = lun;
	media = &device->media[lun];
	block->media = (struct cdk2_block_media) { .media_id = media->media_id,
		.removable_media = media->removable, .media_present = TRUE,
		.read_only = media->readonly, .block_size = media->block_size,
		.io_align = 1U, .last_block = media->last_block };
	block->block = (struct cdk2_block_io) { 0x00010000ULL, &block->media,
		reset, read_blocks, write_blocks, flush };
	block->block2 = (struct cdk2_block_io2) { &block->media, reset2,
		read_blocks2, write_blocks2, flush2 };
	return EFI_SUCCESS;
}
