/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#define OPEN_GET_PROTOCOL 2U
#define OPEN_TEST_PROTOCOL 4U
#define OPEN_BY_CHILD_CONTROLLER 8U
#define OPEN_BY_DRIVER 0x10U
#define MAX_PARTITIONS 128U
#define GPT_ENTRY_CAPACITY (1024U * 1024U)

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *,
	void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI signal_event_fn(void *);

struct boot_services_view {
	UINT8 to_allocate_pool[64];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	UINT8 to_signal_event[24];
	signal_event_fn *signal_event;
	UINT8 to_open_protocol[168];
	open_protocol_fn *open_protocol;
	close_protocol_fn *close_protocol;
	UINT8 to_install_multiple[32];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};

struct system_table_view {
	UINT8 before_boot_services[96];
	struct boot_services_view *boot;
};

struct driver_binding;
typedef EFI_STATUS CDK2_MS_ABI supported_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI start_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI stop_fn(struct driver_binding *, void *, UINTN,
	void **);

struct driver_binding {
	supported_fn *supported;
	start_fn *start;
	stop_fn *stop;
	UINT32 version;
	void *image_handle;
	void *driver_binding_handle;
};

struct child_record {
	struct child_record *next;
	struct cdk2_partition_child *child;
	void *device_path;
};

struct controller_record {
	struct controller_record *next;
	void *controller;
	struct cdk2_disk_io *disk;
	struct child_record *children;
};

static const EFI_GUID block_io_guid = { 0x964e5b21U, 0x6459U, 0x11d2U,
	{ 0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };
static const EFI_GUID block_io2_guid = { 0xa77b2472U, 0xe282U, 0x4e9fU,
	{ 0xa2U, 0x45U, 0xc2U, 0xc0U, 0xe2U, 0x7bU, 0xbcU, 0xc1U } };
static const EFI_GUID disk_io_guid = { 0xce345171U, 0xba0bU, 0x11d2U,
	{ 0x8eU, 0x4fU, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };
static const EFI_GUID disk_io2_guid = { 0x151c8eaeU, 0x7f2cU, 0x472cU,
	{ 0x9eU, 0x54U, 0x98U, 0x28U, 0x19U, 0x4fU, 0x6aU, 0x88U } };
static const EFI_GUID device_path_guid = { 0x09576e91U, 0x6d3fU, 0x11d2U,
	{ 0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };
static const EFI_GUID partition_info_guid = { 0x8cf2f62cU, 0xbc9bU, 0x4821U,
	{ 0x80U, 0x8dU, 0xecU, 0x9eU, 0xc4U, 0x21U, 0xa1U, 0xa0U } };
static const EFI_GUID driver_binding_guid = { 0x18a031abU, 0xb443U, 0x4d1aU,
	{ 0xa5U, 0xc0U, 0x0cU, 0x09U, 0x26U, 0x1eU, 0x9fU, 0x71U } };

static struct boot_services_view *boot;
static struct driver_binding binding;
static struct controller_record *controllers;

static EFI_STATUS allocate(UINTN size, void **buffer)
{
	return boot->allocate_pool(4U, size, buffer);
}

static void release(void *buffer)
{
	(void)boot->free_pool(buffer);
}

static EFI_STATUS install_child(void **handle, struct cdk2_block_io *block,
	struct cdk2_block_io2 *block2, struct cdk2_disk_io *disk,
	struct cdk2_disk_io2 *disk2, void *device_path,
	struct cdk2_partition_info *info)
{
	return boot->install_multiple(handle, &block_io_guid, block, &block_io2_guid,
		block2, &disk_io_guid, disk, &disk_io2_guid, disk2, &device_path_guid,
		device_path, &partition_info_guid, info, NULL);
}

static EFI_STATUS uninstall_child(void *handle, struct cdk2_block_io *block,
	struct cdk2_block_io2 *block2, struct cdk2_disk_io *disk,
	struct cdk2_disk_io2 *disk2, void *device_path,
	struct cdk2_partition_info *info)
{
	return boot->uninstall_multiple(handle, &block_io_guid, block, &block_io2_guid,
		block2, &disk_io_guid, disk, &disk_io2_guid, disk2, &device_path_guid,
		device_path, &partition_info_guid, info, NULL);
}

static EFI_STATUS open_parent(void *parent, void *child)
{
	void *interface;

	return boot->open_protocol(parent, &disk_io_guid, &interface,
		binding.driver_binding_handle, child, OPEN_BY_CHILD_CONTROLLER);
}

static EFI_STATUS close_parent(void *parent, void *child)
{
	return boot->close_protocol(parent, &disk_io_guid,
		binding.driver_binding_handle, child);
}

static EFI_STATUS signal_child_event(void *event)
{
	return boot->signal_event(event);
}

static const struct cdk2_partition_child_services child_services = {
	allocate, release, install_child, uninstall_child, open_parent, close_parent,
	signal_child_event,
};

static EFI_STATUS media_read(void *context, UINT64 lba, UINTN blocks,
	void *buffer)
{
	struct cdk2_block_io *block = context;

	if (blocks > MAX_UINTN / block->media->block_size)
		return EFI_BAD_BUFFER_SIZE;
	return block->read_blocks(block, block->media->media_id, lba,
		blocks * block->media->block_size, buffer);
}

static UINT16 path_node_length(const UINT8 *node)
{
	return (UINT16)node[2] | (UINT16)node[3] << 8;
}

static EFI_STATUS build_child_path(const UINT8 *parent,
	const struct cdk2_partition *partition, void **result)
{
	UINT8 node[42] = { 0 };
	UINTN parent_size = 0;
	UINTN node_size;
	UINT16 length;
	UINT8 *output;
	UINTN index;

	if (parent == NULL)
		return EFI_INVALID_PARAMETER;
	while (parent_size < MAX_UINT16) {
		length = path_node_length(parent + parent_size);
		if (length < 4U || length > MAX_UINT16 - parent_size)
			return EFI_COMPROMISED_DATA;
		if (parent[parent_size] == 0x7fU && parent[parent_size + 1U] == 0xffU)
			break;
		parent_size += length;
	}
	if (parent_size >= MAX_UINT16)
		return EFI_COMPROMISED_DATA;
	if (partition->scheme == CDK2_PARTITION_GPT ||
	    partition->scheme == CDK2_PARTITION_MBR) {
		node[0] = 4U;
		node[1] = 1U;
		node[2] = sizeof(node);
		node[4] = (UINT8)partition->index;
		node[5] = (UINT8)(partition->index >> 8);
		node[6] = (UINT8)(partition->index >> 16);
		node[7] = (UINT8)(partition->index >> 24);
		for (index = 0; index < 8U; index++) {
			node[8U + index] = (UINT8)(partition->start_lba >> (index * 8U));
			node[16U + index] = (UINT8)((partition->end_lba -
				partition->start_lba + 1U) >> (index * 8U));
		}
		if (partition->scheme == CDK2_PARTITION_GPT) {
			__builtin_memcpy(node + 24, &partition->unique_guid, 16U);
			node[40] = 2U;
			node[41] = 2U;
		} else {
			__builtin_memcpy(node + 24, &partition->disk_signature, 4U);
			node[40] = 1U;
			node[41] = 1U;
		}
		node_size = sizeof(node);
	} else {
		UINT64 partition_size = partition->end_lba - partition->start_lba + 1U;

		node[0] = 4U;
		node[1] = 2U;
		node[2] = 24U;
		__builtin_memcpy(node + 4, &partition->boot_entry, 4U);
		__builtin_memcpy(node + 8, &partition->start_lba, 8U);
		__builtin_memcpy(node + 16, &partition_size, sizeof(partition_size));
		node_size = 24U;
	}
	if (parent_size > MAX_UINTN - node_size - 4U)
		return EFI_OUT_OF_RESOURCES;
	if (EFI_ERROR(allocate(parent_size + node_size + 4U, (void **)&output)))
		return EFI_OUT_OF_RESOURCES;
	__builtin_memcpy(output, parent, parent_size);
	__builtin_memcpy(output + parent_size, node, node_size);
	output[parent_size + node_size] = 0x7fU;
	output[parent_size + node_size + 1U] = 0xffU;
	output[parent_size + node_size + 2U] = 4U;
	output[parent_size + node_size + 3U] = 0;
	*result = output;
	return EFI_SUCCESS;
}

static EFI_STATUS discover(struct cdk2_block_io *block, void *scratch,
	UINTN scratch_size, void *entries, struct cdk2_partition *partitions,
	UINTN *count)
{
	struct cdk2_partition_media media = {
		block, media_read, block->media->block_size, block->media->last_block
	};
	EFI_STATUS status;

	status = cdk2_partition_parse_gpt(&media, scratch, scratch_size, entries,
		GPT_ENTRY_CAPACITY, partitions, MAX_PARTITIONS, count);
	if (status != EFI_NOT_FOUND)
		return status;
	status = cdk2_partition_parse_mbr(&media, scratch, scratch_size, partitions,
		MAX_PARTITIONS, count);
	if (status != EFI_NOT_FOUND)
		return status;
	status = cdk2_partition_parse_el_torito(&media, scratch, scratch_size,
		partitions, MAX_PARTITIONS, count);
	if (status != EFI_NOT_FOUND)
		return status;
	return cdk2_partition_parse_udf(&media, scratch, scratch_size, partitions,
		MAX_PARTITIONS, count);
}

static EFI_STATUS CDK2_MS_ABI supported(struct driver_binding *driver,
	void *controller, void *remaining)
{
	void *interface;
	EFI_STATUS status;

	(void)remaining;
	status = boot->open_protocol(controller, &disk_io_guid, &interface,
		driver->driver_binding_handle, controller, OPEN_TEST_PROTOCOL);
	if (EFI_ERROR(status))
		return status;
	return boot->open_protocol(controller, &block_io_guid, &interface,
		driver->driver_binding_handle, controller, OPEN_TEST_PROTOCOL);
}

static void destroy_records(struct controller_record *record)
{
	while (record->children != NULL) {
		struct child_record *child = record->children;

		record->children = child->next;
		(void)cdk2_partition_child_destroy(child->child);
		release(child->device_path);
		release(child);
	}
}

static EFI_STATUS CDK2_MS_ABI start(struct driver_binding *driver,
	void *controller, void *remaining)
{
	struct controller_record *record = NULL;
	struct cdk2_partition *partitions = NULL;
	struct cdk2_block_io *block = NULL;
	struct cdk2_block_io2 *block2 = NULL;
	struct cdk2_disk_io *disk = NULL;
	struct cdk2_disk_io2 *disk2 = NULL;
	void *parent_path = NULL;
	void *scratch = NULL;
	void *entries = NULL;
	UINTN scratch_size;
	UINTN count;
	UINTN index;
	EFI_STATUS status;

	(void)remaining;
	status = boot->open_protocol(controller, &disk_io_guid, (void **)&disk,
		driver->driver_binding_handle, controller, OPEN_BY_DRIVER);
	if (EFI_ERROR(status))
		return status;
	status = boot->open_protocol(controller, &block_io_guid, (void **)&block,
		driver->driver_binding_handle, controller, OPEN_GET_PROTOCOL);
	if (EFI_ERROR(status) || block == NULL || block->media == NULL ||
	    block->media->block_size == 0) {
		status = EFI_UNSUPPORTED;
		goto fail;
	}
	status = boot->open_protocol(controller, &device_path_guid, &parent_path,
		driver->driver_binding_handle, controller, OPEN_GET_PROTOCOL);
	if (EFI_ERROR(status))
		goto fail;
	(void)boot->open_protocol(controller, &block_io2_guid, (void **)&block2,
		driver->driver_binding_handle, controller, OPEN_GET_PROTOCOL);
	(void)boot->open_protocol(controller, &disk_io2_guid, (void **)&disk2,
		driver->driver_binding_handle, controller, OPEN_GET_PROTOCOL);
	scratch_size = block->media->block_size > 2048U ?
		block->media->block_size : 2048U;
	status = allocate(scratch_size, &scratch);
	if (!EFI_ERROR(status))
		status = allocate(GPT_ENTRY_CAPACITY, &entries);
	if (!EFI_ERROR(status))
		status = allocate(sizeof(*partitions) * MAX_PARTITIONS,
			(void **)&partitions);
	if (!EFI_ERROR(status))
		status = allocate(sizeof(*record), (void **)&record);
	if (EFI_ERROR(status))
		goto fail;
	__builtin_memset(record, 0, sizeof(*record));
	record->controller = controller;
	record->disk = disk;
	status = discover(block, scratch, scratch_size, entries, partitions, &count);
	if (EFI_ERROR(status))
		goto fail;
	for (index = 0; index < count; index++) {
		struct child_record *child;

		status = allocate(sizeof(*child), (void **)&child);
		if (EFI_ERROR(status))
			goto fail;
		__builtin_memset(child, 0, sizeof(*child));
		status = build_child_path(parent_path, &partitions[index],
			&child->device_path);
		if (!EFI_ERROR(status))
			status = cdk2_partition_child_create(&child_services, controller,
				block, block2, disk, disk2, child->device_path,
				&partitions[index], &child->child);
		if (EFI_ERROR(status)) {
			if (child->device_path != NULL)
				release(child->device_path);
			release(child);
			goto fail;
		}
		child->next = record->children;
		record->children = child;
	}
	record->next = controllers;
	controllers = record;
	release(partitions);
	release(entries);
	release(scratch);
	return EFI_SUCCESS;
fail:
	if (record != NULL) {
		destroy_records(record);
		release(record);
	}
	if (partitions != NULL)
		release(partitions);
	if (entries != NULL)
		release(entries);
	if (scratch != NULL)
		release(scratch);
	(void)boot->close_protocol(controller, &disk_io_guid,
		driver->driver_binding_handle, controller);
	return status;
}

static EFI_STATUS CDK2_MS_ABI stop(struct driver_binding *driver,
	void *controller, UINTN child_count, void **child_handles)
{
	struct controller_record **link = &controllers;
	struct controller_record *record;
	UINTN index;

	while (*link != NULL && (*link)->controller != controller)
		link = &(*link)->next;
	if (*link == NULL)
		return EFI_NOT_FOUND;
	record = *link;
	if (child_count != 0) {
		for (index = 0; index < child_count; index++) {
			struct child_record **child_link = &record->children;

			while (*child_link != NULL &&
			       cdk2_partition_child_handle((*child_link)->child) !=
			       child_handles[index])
				child_link = &(*child_link)->next;
			if (*child_link == NULL)
				return EFI_NOT_FOUND;
			{
				struct child_record *child = *child_link;
				EFI_STATUS status = cdk2_partition_child_destroy(child->child);

				if (EFI_ERROR(status))
					return status;
				*child_link = child->next;
				release(child->device_path);
				release(child);
			}
		}
		return EFI_SUCCESS;
	}
	if (record->children != NULL)
		return EFI_DEVICE_ERROR;
	*link = record->next;
	(void)boot->close_protocol(controller, &disk_io_guid,
		driver->driver_binding_handle, controller);
	release(record);
	return EFI_SUCCESS;
}

static struct driver_binding binding = {
	supported, start, stop, 0x10U, NULL, NULL
};

EFI_STATUS CDK2_MS_ABI cdk2_partition_entry(void *image,
	struct system_table_view *system)
{
	if (system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	boot = system->boot;
	binding.image_handle = image;
	binding.driver_binding_handle = image;
	return boot->install_multiple(&image, &driver_binding_guid, &binding, NULL);
}

const void *cdk2_partition_driver_binding(void)
{
	return &binding;
}
