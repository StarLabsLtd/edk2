/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Byte-granularity Disk I/O layered on a controller's Block I/O protocol. */

#include <cdk2/disk_io.h>

struct guid { uint32_t a; uint16_t b, c; uint8_t d[8]; };
static const struct guid block_io_guid = { 0x964e5b21, 0x6459, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid disk_io_guid = { 0xce345171, 0xba0b, 0x11d2,
	{ 0x8e, 0x4f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid disk_io2_guid = { 0x151c8eae, 0x7f2c, 0x472c,
	{ 0x9e, 0x54, 0x98, 0x28, 0x19, 0x4f, 0x6a, 0x88 } };
static const struct guid driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };

typedef uint64_t CDK2_MS_ABI install_multiple_fn(void **, const struct guid *, void *, ...);
typedef uint64_t CDK2_MS_ABI open_protocol_fn(void *, const struct guid *, void **,
	void *, void *, uint32_t);
typedef uint64_t CDK2_MS_ABI close_protocol_fn(void *, const struct guid *, void *, void *);
typedef uint64_t CDK2_MS_ABI uninstall_multiple_fn(void *, const struct guid *, void *, ...);
typedef uint64_t CDK2_MS_ABI allocate_pool_fn(uint32_t, size_t, void **);
typedef uint64_t CDK2_MS_ABI free_pool_fn(void *);
typedef uint64_t CDK2_MS_ABI signal_event_fn(void *);

struct boot_services {
	uint8_t to_allocate_pool[64];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	uint8_t to_signal_event[24];
	signal_event_fn *signal_event;
	uint8_t to_open_protocol[168];
	open_protocol_fn *open_protocol;
	close_protocol_fn *close_protocol;
	uint8_t to_install_multiple[32];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct system_table { uint8_t before_boot_services[96]; struct boot_services *boot_services; };

struct disk_context {
	struct cdk2_disk_io disk;
	struct cdk2_disk_io2 disk2;
	struct cdk2_block_io *block;
	void *controller;
	void *scratch_allocation;
	void *scratch;
};

static struct boot_services *bs;
static void *driver_image;

static struct disk_context *from_disk(struct cdk2_disk_io *disk)
{
	return (struct disk_context *)((uint8_t *)disk - offsetof(struct disk_context, disk));
}
static struct disk_context *from_disk2(struct cdk2_disk_io2 *disk)
{
	return (struct disk_context *)((uint8_t *)disk - offsetof(struct disk_context, disk2));
}

static uint64_t transfer(struct disk_context *ctx, int write, uint32_t media_id,
	uint64_t offset, size_t size, void *buffer)
{
	struct cdk2_block_media *media;
	uint8_t *bytes = buffer;
	uint64_t lba, status;
	size_t block, part;

	if (ctx == NULL || ctx->block == NULL || ctx->block->media == NULL ||
	    (size != 0 && buffer == NULL))
		return EFI_INVALID_PARAMETER;
	media = ctx->block->media;
	block = media->block_size;
	if (block == 0 || (size != 0 && offset > UINT64_MAX - (size - 1U)))
		return EFI_INVALID_PARAMETER;
	if (size == 0)
		return EFI_SUCCESS;
	if (offset / block > media->last_block ||
	    (offset + size - 1U) / block > media->last_block)
		return EFI_INVALID_PARAMETER;
	while (size != 0) {
		lba = offset / block;
		part = block - (size_t)(offset % block);
		if (part > size)
			part = size;
		if (part == block && (media->io_align <= 1 ||
		    ((uintptr_t)bytes & (media->io_align - 1U)) == 0)) {
			status = (write ? ctx->block->write_blocks : ctx->block->read_blocks)(
				ctx->block, media_id, lba, block, bytes);
		} else {
			if (write && part == block) {
				__builtin_memcpy(ctx->scratch, bytes, block);
				status = EFI_SUCCESS;
			} else {
				status = ctx->block->read_blocks(ctx->block, media_id, lba,
					block, ctx->scratch);
			}
			if (status == EFI_SUCCESS && write) {
				if (part != block)
					__builtin_memcpy((uint8_t *)ctx->scratch + offset % block,
						bytes, part);
				status = ctx->block->write_blocks(ctx->block, media_id, lba,
					block, ctx->scratch);
			} else if (status == EFI_SUCCESS) {
				__builtin_memcpy(bytes, (uint8_t *)ctx->scratch + offset % block, part);
			}
		}
		if (status != EFI_SUCCESS)
			return status;
		offset += part; bytes += part; size -= part;
	}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI read_disk(struct cdk2_disk_io *disk, uint32_t id,
	uint64_t offset, size_t size, void *buffer)
{ return transfer(from_disk(disk), 0, id, offset, size, buffer); }
static uint64_t CDK2_MS_ABI write_disk(struct cdk2_disk_io *disk, uint32_t id,
	uint64_t offset, size_t size, void *buffer)
{ return transfer(from_disk(disk), 1, id, offset, size, buffer); }
static void complete(struct cdk2_disk_io2_token *token, uint64_t status)
{
	if (token != NULL) {
		token->transaction_status = status;
		if (token->event != NULL && bs != NULL && bs->signal_event != NULL)
			(void)bs->signal_event(token->event);
	}
}
static uint64_t disk2_transfer(struct cdk2_disk_io2 *disk, int write, uint32_t id,
	uint64_t offset, struct cdk2_disk_io2_token *token, size_t size, void *buffer)
{
	uint64_t status;
	status = transfer(from_disk2(disk), write, id, offset, size, buffer);
	if (token == NULL)
		return status;
	complete(token, status);
	return token->event == NULL ? status : EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI read_disk_ex(struct cdk2_disk_io2 *disk, uint32_t id,
	uint64_t off, struct cdk2_disk_io2_token *tok, size_t len, void *buf)
{ return disk2_transfer(disk, 0, id, off, tok, len, buf); }
static uint64_t CDK2_MS_ABI write_disk_ex(struct cdk2_disk_io2 *disk, uint32_t id,
	uint64_t off, struct cdk2_disk_io2_token *tok, size_t len, void *buf)
{ return disk2_transfer(disk, 1, id, off, tok, len, buf); }
static uint64_t CDK2_MS_ABI cancel(struct cdk2_disk_io2 *disk)
{ (void)disk; return EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI flush_disk_ex(struct cdk2_disk_io2 *disk,
	struct cdk2_disk_io2_token *token)
{
	uint64_t status;
	status = from_disk2(disk)->block->flush_blocks(from_disk2(disk)->block);
	if (token == NULL)
		return status;
	complete(token, status);
	return token->event == NULL ? status : EFI_SUCCESS;
}

#define OPEN_TEST_PROTOCOL 4U
#define OPEN_BY_DRIVER 0x10U
struct driver_binding {
	uint64_t (CDK2_MS_ABI *supported)(struct driver_binding *, void *, void *);
	uint64_t (CDK2_MS_ABI *start)(struct driver_binding *, void *, void *);
	uint64_t (CDK2_MS_ABI *stop)(struct driver_binding *, void *, size_t, void **);
	uint32_t version; void *image_handle; void *driver_binding_handle;
};
static uint64_t CDK2_MS_ABI supported(struct driver_binding *binding, void *controller,
	void *remaining)
{
	void *block = NULL; (void)remaining;
	return bs->open_protocol(controller, &block_io_guid, &block,
		binding->driver_binding_handle, controller, OPEN_TEST_PROTOCOL);
}
static uint64_t CDK2_MS_ABI start(struct driver_binding *binding, void *controller,
	void *remaining)
{
	struct disk_context *ctx = NULL; struct cdk2_block_io *block = NULL;
	uint64_t status; (void)remaining;
	status = bs->open_protocol(controller, &block_io_guid, (void **)&block,
		binding->driver_binding_handle, controller, OPEN_BY_DRIVER);
	if (status != EFI_SUCCESS)
		return status;
	if (block == NULL || block->media == NULL || block->media->block_size == 0) {
		status = EFI_INVALID_PARAMETER; goto close;
	}
	{
		status = bs->allocate_pool(4, sizeof(*ctx), (void **)&ctx);
		if (status != EFI_SUCCESS)
			goto close;
		__builtin_memset(ctx, 0, sizeof(*ctx)); ctx->block = block; ctx->controller = controller;
		{
			size_t alignment = block->media->io_align;
			size_t allocation_size = block->media->block_size;
			if (alignment < 2)
				alignment = 1;
			if ((alignment & (alignment - 1U)) != 0 ||
			    allocation_size > SIZE_MAX - (alignment - 1U)) {
				status = EFI_INVALID_PARAMETER; bs->free_pool(ctx); goto close;
			}
			allocation_size += alignment - 1U;
			status = bs->allocate_pool(4, allocation_size, &ctx->scratch_allocation);
			if (status == EFI_SUCCESS)
				ctx->scratch = (void *)(((uintptr_t)ctx->scratch_allocation +
					alignment - 1U) & ~(uintptr_t)(alignment - 1U));
		}
		if (status != EFI_SUCCESS) {
			bs->free_pool(ctx);
			goto close;
		}
		ctx->disk = (struct cdk2_disk_io){ CDK2_DISK_IO_REVISION, read_disk, write_disk };
		ctx->disk2 = (struct cdk2_disk_io2){ CDK2_DISK_IO2_REVISION, cancel,
			read_disk_ex, write_disk_ex, flush_disk_ex };
		status = bs->install_multiple(&controller, &disk_io_guid, &ctx->disk,
			&disk_io2_guid, &ctx->disk2, NULL);
		if (status == EFI_SUCCESS)
			return status;
		bs->free_pool(ctx->scratch_allocation); bs->free_pool(ctx);
	}
close:
	(void)bs->close_protocol(controller, &block_io_guid,
		binding->driver_binding_handle, controller);
	return status;
}
static uint64_t CDK2_MS_ABI stop(struct driver_binding *binding, void *controller,
	size_t children, void **child_buffer)
{
	void *interface = NULL; struct disk_context *ctx; uint64_t status;
	(void)children; (void)child_buffer;
	status = bs->open_protocol(controller, &disk_io_guid, &interface,
		binding->driver_binding_handle, controller, OPEN_TEST_PROTOCOL);
	if (status != EFI_SUCCESS)
		return status;
	ctx = from_disk(interface);
	status = bs->uninstall_multiple(controller, &disk_io_guid, &ctx->disk,
		&disk_io2_guid, &ctx->disk2, NULL);
	if (status != EFI_SUCCESS)
		return status;
	(void)bs->close_protocol(controller, &block_io_guid,
		binding->driver_binding_handle, controller);
	bs->free_pool(ctx->scratch_allocation); bs->free_pool(ctx); return EFI_SUCCESS;
}
static struct driver_binding binding = { supported, start, stop, 0x10, NULL, NULL };

uint64_t CDK2_MS_ABI cdk2_disk_io_entry(void *image, struct system_table *system)
{
	driver_image = image; bs = system->boot_services;
	binding.image_handle = image; binding.driver_binding_handle = image;
	return bs->install_multiple(&image, &driver_binding_guid, &binding, NULL);
}
