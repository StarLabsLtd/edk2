/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_bus.h>

#include <stddef.h>
#include <string.h>

#define CDK2_BLOCK_IO_REVISION3 0x0002001fULL

static struct cdk2_ata_bus_block_instance *from_block(struct cdk2_block_io *block)
{
	return (struct cdk2_ata_bus_block_instance *)((UINT8 *)block -
		offsetof(struct cdk2_ata_bus_block_instance, block));
}

static struct cdk2_ata_bus_block_instance *from_block2(struct cdk2_block_io2 *block)
{
	return (struct cdk2_ata_bus_block_instance *)((UINT8 *)block -
		offsetof(struct cdk2_ata_bus_block_instance, block2));
}

static EFI_STATUS sync_request(struct cdk2_ata_bus_block_instance *instance,
	enum cdk2_ata_bus_operation operation, UINT32 media_id, UINT64 lba,
	UINTN bytes, void *buffer)
{
	struct cdk2_ata_bus_request request = { instance->child, operation, NULL,
		media_id, lba, bytes, buffer };
	return cdk2_ata_bus_execute_sync(instance->scheduler, &request);
}

static uint64_t CDK2_MS_ABI block_reset(struct cdk2_block_io *block,
	uint8_t extended_verification)
{
	struct cdk2_ata_bus_block_instance *instance = from_block(block);
	return cdk2_ata_bus_reset(instance->scheduler, instance->child,
		extended_verification);
}
static uint64_t CDK2_MS_ABI block_read(struct cdk2_block_io *block,
	uint32_t media_id, uint64_t lba, size_t bytes, void *buffer)
{ return sync_request(from_block(block), CDK2_ATA_BUS_READ, media_id, lba,
	bytes, buffer); }
static uint64_t CDK2_MS_ABI block_write(struct cdk2_block_io *block,
	uint32_t media_id, uint64_t lba, size_t bytes, void *buffer)
{ return sync_request(from_block(block), CDK2_ATA_BUS_WRITE, media_id, lba,
	bytes, buffer); }
static uint64_t CDK2_MS_ABI block_flush(struct cdk2_block_io *block)
{ return sync_request(from_block(block), CDK2_ATA_BUS_FLUSH, 0, 0, 0, NULL); }

static EFI_STATUS async_request(struct cdk2_ata_bus_block_instance *instance,
	enum cdk2_ata_bus_operation operation, UINT32 media_id, UINT64 lba,
	struct cdk2_block_io2_token *token, UINTN bytes, void *buffer)
{
	struct cdk2_ata_bus_request request = { instance->child, operation, token,
		media_id, lba, bytes, buffer };
	EFI_STATUS status;
	if (token == NULL || token->event == NULL)
		return sync_request(instance, operation, media_id, lba, bytes, buffer);
	status = cdk2_ata_bus_submit(instance->scheduler, &request);
	if (EFI_ERROR(status))
		return status;
	if (instance->scheduler->deferred)
		return EFI_SUCCESS;
	instance->scheduler->deferred = 1;
	status = instance->defer(instance->defer_context, instance);
	if (EFI_ERROR(status)) {
		instance->scheduler->deferred = 0;
		(void)cdk2_ata_bus_cancel_token(instance->scheduler, token);
		token->transaction_status = status;
	}
	return status;
}

static EFI_STATUS CDK2_MS_ABI block2_reset(struct cdk2_block_io2 *block,
	BOOLEAN extended_verification)
{
	struct cdk2_ata_bus_block_instance *instance = from_block2(block);
	return cdk2_ata_bus_reset(instance->scheduler, instance->child,
		extended_verification);
}
static EFI_STATUS CDK2_MS_ABI block2_read(struct cdk2_block_io2 *block,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token,
	UINTN bytes, void *buffer)
{ return async_request(from_block2(block), CDK2_ATA_BUS_READ, media_id, lba,
	token, bytes, buffer); }
static EFI_STATUS CDK2_MS_ABI block2_write(struct cdk2_block_io2 *block,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token,
	UINTN bytes, void *buffer)
{ return async_request(from_block2(block), CDK2_ATA_BUS_WRITE, media_id, lba,
	token, bytes, buffer); }
static EFI_STATUS CDK2_MS_ABI block2_flush(struct cdk2_block_io2 *block,
	struct cdk2_block_io2_token *token)
{ return async_request(from_block2(block), CDK2_ATA_BUS_FLUSH, 0, 0, token,
	0, NULL); }

EFI_STATUS cdk2_ata_bus_block_init(struct cdk2_ata_bus_block_instance *instance,
	struct cdk2_ata_bus_child *child, struct cdk2_ata_bus_scheduler *scheduler,
	cdk2_ata_bus_defer_fn *defer, void *defer_context)
{
	if (instance == NULL || child == NULL || scheduler == NULL || defer == NULL ||
	    child->geometry.blocks == 0U || child->geometry.block_size == 0U)
		return EFI_INVALID_PARAMETER;
	memset(instance, 0, sizeof(*instance)); instance->child = child;
	instance->scheduler = scheduler; instance->defer = defer;
	instance->defer_context = defer_context;
	instance->media = (struct cdk2_block_media) { .media_id = 0,
		.removable_media = child->geometry.removable, .media_present = 1,
		.read_only = child->geometry.read_only,
		.write_caching = child->geometry.write_caching,
		.block_size = child->geometry.block_size, .io_align = child->geometry.io_align,
		.last_block = child->geometry.blocks - 1U,
		.lowest_aligned_lba = child->geometry.lowest_aligned_lba,
		.logical_blocks_per_physical_block =
			child->geometry.logical_blocks_per_physical_block,
		.optimal_transfer_length_granularity =
			child->geometry.optimal_transfer_granularity };
	instance->block = (struct cdk2_block_io) { CDK2_BLOCK_IO_REVISION3,
		&instance->media, block_reset, block_read, block_write, block_flush };
	instance->block2 = (struct cdk2_block_io2) { &instance->media, block2_reset,
		block2_read, block2_write, block2_flush };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_block_worker(struct cdk2_ata_bus_block_instance *instance)
{
	EFI_STATUS status;
	if (instance == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_ata_bus_worker(instance->scheduler);
	instance->scheduler->deferred = 0;
	if (instance->scheduler->count != 0U) {
		EFI_STATUS defer_status;
		instance->scheduler->deferred = 1;
		defer_status = instance->defer(instance->defer_context, instance);
		if (EFI_ERROR(defer_status))
			instance->scheduler->deferred = 0;
	}
	return status;
}
