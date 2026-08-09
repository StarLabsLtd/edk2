/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#define MEDIA_CHANGED EFIERR(13)
#define ABORTED EFIERR(21)
#define BLOCK_IO_REVISION2 0x00020001ULL

struct cdk2_partition_async_request {
	struct cdk2_partition_async_request *next;
	struct cdk2_partition_child *child;
	struct cdk2_disk_io2_token *caller_token;
	struct cdk2_disk_io2_token parent_token;
	UINT32 media_id;
	UINT64 parent_offset;
	UINTN size;
	void *buffer;
	void *event;
	BOOLEAN write;
	BOOLEAN flush;
	BOOLEAN cancel_pending;
};

struct cdk2_partition_child {
	struct cdk2_block_io block;
	struct cdk2_block_io2 block2;
	struct cdk2_disk_io disk;
	struct cdk2_disk_io2 disk2;
	struct cdk2_block_media media;
	struct cdk2_partition_info info;
	struct cdk2_partition partition;
	const struct cdk2_partition_child_services *services;
	struct cdk2_block_io *parent_block;
	struct cdk2_block_io2 *parent_block2;
	struct cdk2_disk_io *parent_disk;
	struct cdk2_disk_io2 *parent_disk2;
	void *parent;
	void *handle;
	void *device_path;
	UINT64 byte_offset;
	UINT64 byte_size;
	BOOLEAN parent_open;
	struct cdk2_partition_async_scheduler *scheduler;
};

static const EFI_GUID efi_system_partition_guid = {
	0xc12a7328U, 0xf81fU, 0x11d2U,
	{ 0xbaU, 0x4bU, 0x00U, 0xa0U, 0xc9U, 0x3eU, 0xc9U, 0x3bU }
};

static BOOLEAN guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *left_bytes = (const UINT8 *)left;
	const UINT8 *right_bytes = (const UINT8 *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++)
		if (left_bytes[index] != right_bytes[index])
			return FALSE;
	return TRUE;
}

static struct cdk2_partition_child *from_block(struct cdk2_block_io *block)
{
	return (struct cdk2_partition_child *)((UINT8 *)block -
		offsetof(struct cdk2_partition_child, block));
}

static struct cdk2_partition_child *from_block2(struct cdk2_block_io2 *block)
{
	return (struct cdk2_partition_child *)((UINT8 *)block -
		offsetof(struct cdk2_partition_child, block2));
}

static struct cdk2_partition_child *from_disk(struct cdk2_disk_io *disk)
{
	return (struct cdk2_partition_child *)((UINT8 *)disk -
		offsetof(struct cdk2_partition_child, disk));
}

static struct cdk2_partition_child *from_disk2(struct cdk2_disk_io2 *disk)
{
	return (struct cdk2_partition_child *)((UINT8 *)disk -
		offsetof(struct cdk2_partition_child, disk2));
}

static EFI_STATUS block_range(struct cdk2_partition_child *child, UINT32 media_id,
	UINT64 lba, UINTN size, void *buffer, UINT64 *parent_lba)
{
	if (media_id != child->media.media_id)
		return MEDIA_CHANGED;
	if (size != 0 && buffer == NULL)
		return EFI_INVALID_PARAMETER;
	if (size % child->media.block_size != 0)
		return EFI_BAD_BUFFER_SIZE;
	if (size == 0 && lba > child->media.last_block)
		return EFI_INVALID_PARAMETER;
	if (size != 0 && (lba > child->media.last_block ||
	    size / child->media.block_size - 1U > child->media.last_block - lba))
		return EFI_INVALID_PARAMETER;
	*parent_lba = child->partition.start_lba + lba;
	return EFI_SUCCESS;
}

static EFI_STATUS disk_range(struct cdk2_partition_child *child, UINT32 media_id,
	UINT64 offset, UINTN size, void *buffer, UINT64 *parent_offset)
{
	if (media_id != child->media.media_id)
		return MEDIA_CHANGED;
	if ((size != 0 && buffer == NULL) ||
	    (size == 0 && offset > child->byte_size) ||
	    (size != 0 && (offset >= child->byte_size || size - 1U >
	    child->byte_size - offset - 1U)))
		return EFI_INVALID_PARAMETER;
	*parent_offset = child->byte_offset + offset;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI child_reset(struct cdk2_block_io *block,
	UINT8 extended)
{
	struct cdk2_partition_child *child = from_block(block);

	return child->parent_block->reset(child->parent_block, extended);
}

static EFI_STATUS block_transfer(struct cdk2_block_io *block, BOOLEAN write,
	UINT32 media_id, UINT64 lba, UINTN size, void *buffer)
{
	struct cdk2_partition_child *child = from_block(block);
	UINT64 parent_lba = 0;
	EFI_STATUS status;

	status = block_range(child, media_id, lba, size, buffer, &parent_lba);
	if (EFI_ERROR(status) || size == 0)
		return status;
	return (write ? child->parent_block->write_blocks :
		child->parent_block->read_blocks)(child->parent_block, media_id,
		parent_lba, size, buffer);
}

static uint64_t CDK2_MS_ABI child_read(struct cdk2_block_io *block,
	uint32_t media_id, uint64_t lba, size_t size, void *buffer)
{
	return block_transfer(block, FALSE, media_id, lba, size, buffer);
}

static uint64_t CDK2_MS_ABI child_write(struct cdk2_block_io *block,
	uint32_t media_id, uint64_t lba, size_t size, void *buffer)
{
	return block_transfer(block, TRUE, media_id, lba, size, buffer);
}

static uint64_t CDK2_MS_ABI child_flush(struct cdk2_block_io *block)
{
	struct cdk2_partition_child *child = from_block(block);

	return child->parent_block->flush_blocks(child->parent_block);
}

static void complete(struct cdk2_partition_child *child,
	struct cdk2_block_io2_token *token, EFI_STATUS status)
{
	if (token == NULL)
		return;
	token->transaction_status = status;
	if (token->event != NULL)
		(void)child->services->signal_event(token->event);
}

static EFI_STATUS CDK2_MS_ABI child_reset2(struct cdk2_block_io2 *block,
	BOOLEAN extended)
{
	struct cdk2_partition_child *child = from_block2(block);

	if (child->parent_block2 != NULL)
		return child->parent_block2->reset(child->parent_block2, extended);
	return child->parent_block->reset(child->parent_block, extended);
}

static EFI_STATUS block2_transfer(struct cdk2_block_io2 *block, BOOLEAN write,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token,
	UINTN size, void *buffer)
{
	struct cdk2_partition_child *child = from_block2(block);
	UINT64 parent_lba = 0;
	EFI_STATUS status;

	status = block_range(child, media_id, lba, size, buffer, &parent_lba);
	if (EFI_ERROR(status))
		return status;
	if (size == 0) {
		complete(child, token, status);
		return token != NULL && token->event != NULL ? EFI_SUCCESS : status;
	}
	if (child->parent_block2 != NULL)
		return (write ? child->parent_block2->write_blocks :
			child->parent_block2->read_blocks)(child->parent_block2,
			media_id, parent_lba, token, size, buffer);
	status = block_transfer(&child->block, write, media_id, lba, size, buffer);
	complete(child, token, status);
	return token != NULL && token->event != NULL ? EFI_SUCCESS : status;
}

static EFI_STATUS CDK2_MS_ABI child_read2(struct cdk2_block_io2 *block,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token,
	UINTN size, void *buffer)
{
	return block2_transfer(block, FALSE, media_id, lba, token, size, buffer);
}

static EFI_STATUS CDK2_MS_ABI child_write2(struct cdk2_block_io2 *block,
	UINT32 media_id, UINT64 lba, struct cdk2_block_io2_token *token,
	UINTN size, void *buffer)
{
	return block2_transfer(block, TRUE, media_id, lba, token, size, buffer);
}

static EFI_STATUS CDK2_MS_ABI child_flush2(struct cdk2_block_io2 *block,
	struct cdk2_block_io2_token *token)
{
	struct cdk2_partition_child *child = from_block2(block);
	EFI_STATUS status;

	if (child->parent_block2 != NULL)
		return child->parent_block2->flush_blocks(child->parent_block2, token);
	status = child->parent_block->flush_blocks(child->parent_block);
	complete(child, token, status);
	return token != NULL && token->event != NULL ? EFI_SUCCESS : status;
}

static EFI_STATUS disk_transfer(struct cdk2_disk_io *disk, BOOLEAN write,
	UINT32 media_id, UINT64 offset, UINTN size, void *buffer)
{
	struct cdk2_partition_child *child = from_disk(disk);
	UINT64 parent_offset = 0;
	EFI_STATUS status;

	status = disk_range(child, media_id, offset, size, buffer, &parent_offset);
	if (EFI_ERROR(status) || size == 0)
		return status;
	return (write ? child->parent_disk->write_disk : child->parent_disk->read_disk)(
		child->parent_disk, media_id, parent_offset, size, buffer);
}

static void dispatch_async(struct cdk2_partition_async_scheduler *scheduler);

static void CDK2_MS_ABI async_complete(void *event, void *context)
{
	struct cdk2_partition_async_request *request = context;
	struct cdk2_partition_async_scheduler *scheduler = request->child->scheduler;

	(void)event;
	request->caller_token->transaction_status = request->cancel_pending ? ABORTED :
		request->parent_token.transaction_status;
	(void)request->child->services->signal_event(request->caller_token->event);
	scheduler->active = NULL;
	(void)request->child->services->close_event(request->event);
	request->child->services->free(request);
	dispatch_async(scheduler);
}

static void dispatch_async(struct cdk2_partition_async_scheduler *scheduler)
{
	struct cdk2_partition_async_request *request;
	EFI_STATUS status;

	if (scheduler == NULL || scheduler->canceling || scheduler->active != NULL ||
	    scheduler->head == NULL)
		return;
	request = scheduler->head;
	scheduler->head = request->next;
	if (scheduler->head == NULL)
		scheduler->tail = NULL;
	scheduler->active = request;
	if (request->flush)
		status = scheduler->parent->flush_disk_ex(scheduler->parent,
			&request->parent_token);
	else
		status = (request->write ? scheduler->parent->write_disk_ex :
			scheduler->parent->read_disk_ex)(scheduler->parent, request->media_id,
			request->parent_offset, &request->parent_token, request->size,
			request->buffer);
	if (EFI_ERROR(status)) {
		request->parent_token.transaction_status = status;
		async_complete(request->event, request);
	}
}

static EFI_STATUS queue_async(struct cdk2_partition_child *child, BOOLEAN write,
	UINT32 media_id, UINT64 parent_offset, struct cdk2_disk_io2_token *token,
	UINTN size, void *buffer, BOOLEAN flush)
{
	struct cdk2_partition_async_request *request;
	EFI_STATUS status;

	if (child->scheduler == NULL || child->parent_disk2 == NULL || token == NULL ||
	    token->event == NULL)
		return EFI_UNSUPPORTED;
	status = child->services->allocate(sizeof(*request), (void **)&request);
	if (EFI_ERROR(status))
		return status;
	__builtin_memset(request, 0, sizeof(*request));
	request->child = child;
	request->caller_token = token;
	request->media_id = media_id;
	request->parent_offset = parent_offset;
	request->size = size;
	request->buffer = buffer;
	request->write = write;
	request->flush = flush;
	status = child->services->create_event(async_complete, request, &request->event);
	if (EFI_ERROR(status)) {
		child->services->free(request);
		return status;
	}
	request->parent_token.event = request->event;
	request->parent_token.transaction_status = EFI_NOT_READY;
	if (child->scheduler->tail == NULL)
		child->scheduler->head = request;
	else
		((struct cdk2_partition_async_request *)child->scheduler->tail)->next = request;
	child->scheduler->tail = request;
	dispatch_async(child->scheduler);
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI child_read_disk(struct cdk2_disk_io *disk,
	uint32_t media_id, uint64_t offset, size_t size, void *buffer)
{
	return disk_transfer(disk, FALSE, media_id, offset, size, buffer);
}

static uint64_t CDK2_MS_ABI child_write_disk(struct cdk2_disk_io *disk,
	uint32_t media_id, uint64_t offset, size_t size, void *buffer)
{
	return disk_transfer(disk, TRUE, media_id, offset, size, buffer);
}

static EFI_STATUS disk2_transfer(struct cdk2_disk_io2 *disk, BOOLEAN write,
	UINT32 media_id, UINT64 offset, struct cdk2_disk_io2_token *token,
	UINTN size, void *buffer)
{
	struct cdk2_partition_child *child = from_disk2(disk);
	UINT64 parent_offset = 0;
	EFI_STATUS status;

	status = disk_range(child, media_id, offset, size, buffer, &parent_offset);
	if (EFI_ERROR(status))
		return status;
	if (size == 0) {
		if (token != NULL) {
			token->transaction_status = status;
			if (token->event != NULL)
				(void)child->services->signal_event(token->event);
		}
		return token != NULL && token->event != NULL ? EFI_SUCCESS : status;
	}
	if (token != NULL && token->event != NULL && child->parent_disk2 != NULL)
		return queue_async(child, write, media_id, parent_offset, token, size, buffer,
			FALSE);
	status = disk_transfer(&child->disk, write, media_id, offset, size, buffer);
	complete(child, (struct cdk2_block_io2_token *)token, status);
	return token != NULL && token->event != NULL ? EFI_SUCCESS : status;
}

static uint64_t CDK2_MS_ABI child_read_disk2(struct cdk2_disk_io2 *disk,
	uint32_t media_id, uint64_t offset, struct cdk2_disk_io2_token *token,
	size_t size, void *buffer)
{
	return disk2_transfer(disk, FALSE, media_id, offset, token, size, buffer);
}

static uint64_t CDK2_MS_ABI child_write_disk2(struct cdk2_disk_io2 *disk,
	uint32_t media_id, uint64_t offset, struct cdk2_disk_io2_token *token,
	size_t size, void *buffer)
{
	return disk2_transfer(disk, TRUE, media_id, offset, token, size, buffer);
}

static uint64_t CDK2_MS_ABI child_cancel(struct cdk2_disk_io2 *disk)
{
	struct cdk2_partition_child *child = from_disk2(disk);
	struct cdk2_partition_async_scheduler *scheduler = child->scheduler;
	struct cdk2_partition_async_request **link;
	struct cdk2_partition_async_request *request;
	EFI_STATUS status = EFI_SUCCESS;

	if (scheduler == NULL)
		return EFI_SUCCESS;
	link = (struct cdk2_partition_async_request **)&scheduler->head;
	while (*link != NULL) {
		request = *link;
		if (request->child != child) {
			link = &request->next;
			continue;
		}
		*link = request->next;
		request->caller_token->transaction_status = ABORTED;
		(void)child->services->signal_event(request->caller_token->event);
		(void)child->services->close_event(request->event);
		child->services->free(request);
	}
	scheduler->tail = NULL;
	for (request = scheduler->head; request != NULL; request = request->next)
		scheduler->tail = request;
	request = scheduler->active;
	if (request != NULL && request->child == child) {
		request->cancel_pending = TRUE;
		status = EFI_NOT_READY;
	}
	return status;
}

static uint64_t CDK2_MS_ABI child_flush_disk2(struct cdk2_disk_io2 *disk,
	struct cdk2_disk_io2_token *token)
{
	struct cdk2_partition_child *child = from_disk2(disk);
	EFI_STATUS status;

	if (token != NULL && token->event != NULL && child->parent_disk2 != NULL)
		return queue_async(child, FALSE, child->media.media_id, 0, token, 0, NULL,
			TRUE);
	status = child->parent_block->flush_blocks(child->parent_block);
	if (token != NULL) {
		token->transaction_status = status;
		if (token->event != NULL)
			(void)child->services->signal_event(token->event);
	}
	return token != NULL && token->event != NULL ? EFI_SUCCESS : status;
}

EFI_STATUS cdk2_partition_child_create(
	const struct cdk2_partition_child_services *services, void *parent,
	struct cdk2_block_io *parent_block, struct cdk2_block_io2 *parent_block2,
	struct cdk2_disk_io *parent_disk, struct cdk2_disk_io2 *parent_disk2,
	struct cdk2_partition_async_scheduler *scheduler,
	void *device_path, const struct cdk2_partition *partition,
	struct cdk2_partition_child **child_out)
{
	struct cdk2_partition_child *child;
	UINT64 blocks;
	EFI_STATUS status;

	if (services == NULL || services->allocate == NULL || services->free == NULL ||
	    services->install == NULL || services->uninstall == NULL ||
	    services->open_parent == NULL || services->close_parent == NULL ||
	    services->signal_event == NULL || services->create_event == NULL ||
	    services->close_event == NULL || parent_block == NULL ||
	    parent_block->media == NULL || parent_disk == NULL || partition == NULL ||
	    child_out == NULL || partition->start_lba > partition->end_lba ||
	    partition->end_lba > parent_block->media->last_block)
		return EFI_INVALID_PARAMETER;
	*child_out = NULL;
	blocks = partition->end_lba - partition->start_lba + 1U;
	if (blocks > MAX_UINT64 / parent_block->media->block_size)
		return EFI_BAD_BUFFER_SIZE;
	if (partition->start_lba > MAX_UINT64 / parent_block->media->block_size)
		return EFI_BAD_BUFFER_SIZE;
	status = services->allocate(sizeof(*child), (void **)&child);
	if (EFI_ERROR(status))
		return status;
	__builtin_memset(child, 0, sizeof(*child));
	child->services = services;
	child->parent = parent;
	child->parent_block = parent_block;
	child->parent_block2 = parent_block2;
	child->parent_disk = parent_disk;
	child->parent_disk2 = parent_disk2;
	child->scheduler = scheduler;
	child->device_path = device_path;
	__builtin_memcpy(&child->media, parent_block->media,
		offsetof(struct cdk2_block_media, lowest_aligned_lba));
	if (parent_block->revision >= BLOCK_IO_REVISION2)
		__builtin_memcpy(&child->media.lowest_aligned_lba,
			&parent_block->media->lowest_aligned_lba,
			sizeof(child->media) -
			offsetof(struct cdk2_block_media, lowest_aligned_lba));
	child->media.logical_partition = TRUE;
	child->media.last_block = blocks - 1U;
	if (parent_block->revision >= BLOCK_IO_REVISION2 &&
	    child->media.logical_blocks_per_physical_block > 1U) {
		UINT64 physical = child->media.logical_blocks_per_physical_block;
		UINT64 parent_alignment = child->media.lowest_aligned_lba % physical;
		UINT64 start_alignment = partition->start_lba % physical;

		child->media.lowest_aligned_lba =
			(parent_alignment + physical - start_alignment) % physical;
	} else {
		child->media.lowest_aligned_lba = 0;
	}
	child->byte_offset = partition->start_lba * parent_block->media->block_size;
	child->byte_size = blocks * parent_block->media->block_size;
	child->partition = *partition;
	child->info.revision = 0x1000U;
	child->info.type = partition->scheme == CDK2_PARTITION_MBR ? 1U :
		(partition->scheme == CDK2_PARTITION_GPT ? 2U : 0U);
	child->info.system = partition->mbr_type == 0xefU ||
		guid_equal(&partition->type_guid, &efi_system_partition_guid);
	if (partition->scheme == CDK2_PARTITION_MBR) {
		__builtin_memcpy(&child->info.info.mbr, partition->mbr_record,
			sizeof(child->info.info.mbr));
	} else if (partition->scheme == CDK2_PARTITION_GPT) {
		child->info.info.gpt.partition_type_guid = partition->type_guid;
		child->info.info.gpt.unique_partition_guid = partition->unique_guid;
		child->info.info.gpt.starting_lba = partition->start_lba;
		child->info.info.gpt.ending_lba = partition->end_lba;
		child->info.info.gpt.attributes = partition->attributes;
		__builtin_memcpy(child->info.info.gpt.partition_name,
			partition->name, sizeof(child->info.info.gpt.partition_name));
	}
	child->block = (struct cdk2_block_io){ parent_block->revision, &child->media,
		child_reset, child_read, child_write, child_flush };
	child->block2 = (struct cdk2_block_io2){ &child->media, child_reset2,
		child_read2, child_write2, child_flush2 };
	child->disk = (struct cdk2_disk_io){ CDK2_DISK_IO_REVISION,
		child_read_disk, child_write_disk };
	child->disk2 = (struct cdk2_disk_io2){ CDK2_DISK_IO2_REVISION, child_cancel,
		child_read_disk2, child_write_disk2, child_flush_disk2 };
	status = services->install(&child->handle, &child->block, &child->block2,
		&child->disk, &child->disk2, device_path, &child->info);
	if (EFI_ERROR(status)) {
		services->free(child);
		return status;
	}
	status = services->open_parent(parent, child->handle);
	if (EFI_ERROR(status)) {
		EFI_STATUS rollback = services->uninstall(child->handle, &child->block,
			&child->block2,
			&child->disk, &child->disk2, device_path, &child->info);

		if (EFI_ERROR(rollback)) {
			/* Installed interfaces still own every backing pointer. */
			*child_out = child;
			return EFI_SUCCESS;
		}
		services->free(child);
		return status;
	}
	child->parent_open = TRUE;
	*child_out = child;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_partition_child_destroy(struct cdk2_partition_child *child)
{
	EFI_STATUS status;

	if (child == NULL)
		return EFI_INVALID_PARAMETER;
	status = child_cancel(&child->disk2);
	if (EFI_ERROR(status))
		return status;
	if (child->parent_open) {
		status = child->services->close_parent(child->parent, child->handle);
		if (EFI_ERROR(status))
			return status;
		child->parent_open = FALSE;
	}
	status = child->services->uninstall(child->handle, &child->block,
		&child->block2, &child->disk, &child->disk2, child->device_path,
		&child->info);
	if (EFI_ERROR(status)) {
		EFI_STATUS reopen = child->services->open_parent(child->parent, child->handle);

		if (!EFI_ERROR(reopen))
			child->parent_open = TRUE;
		else
			return reopen;
		return status;
	}
	child->services->free(child);
	return EFI_SUCCESS;
}

struct cdk2_block_io *cdk2_partition_child_block(struct cdk2_partition_child *child)
{
	return child == NULL ? NULL : &child->block;
}

struct cdk2_block_io2 *cdk2_partition_child_block2(
	struct cdk2_partition_child *child)
{
	return child == NULL ? NULL : &child->block2;
}

struct cdk2_disk_io *cdk2_partition_child_disk(struct cdk2_partition_child *child)
{
	return child == NULL ? NULL : &child->disk;
}

struct cdk2_disk_io2 *cdk2_partition_child_disk2(struct cdk2_partition_child *child)
{
	return child == NULL ? NULL : &child->disk2;
}

void *cdk2_partition_child_handle(struct cdk2_partition_child *child)
{
	return child == NULL ? NULL : child->handle;
}
