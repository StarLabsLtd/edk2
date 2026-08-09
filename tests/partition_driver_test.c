/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 512U
#define DISK_BLOCKS 100U

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

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *,
	void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI signal_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);

struct boot_services_view {
	UINT8 to_allocate_pool[64];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	create_event_fn *create_event;
	void *set_timer;
	void *wait_for_event;
	signal_event_fn *signal_event;
	close_event_fn *close_event;
	UINT8 to_open_protocol[160];
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

EFI_STATUS CDK2_MS_ABI cdk2_partition_entry(void *image,
	struct system_table_view *system);
const void *cdk2_partition_driver_binding(void);

static UINT8 disk_image[DISK_BLOCKS][BLOCK_SIZE];
static struct driver_binding *installed_binding;
static void *child_handle;
static UINTN allocations;
static UINTN frees;
static UINTN closes;
static UINTN child_installs;
static UINTN child_uninstalls;
static UINTN fail_allocation;
static BOOLEAN fail_child_install;
static BOOLEAN fail_child_open;
static void *installed_path;
static UINTN misaligned_reads;

static void write32(UINT8 *bytes, UINT32 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
	bytes[2] = (UINT8)(value >> 16);
	bytes[3] = (UINT8)(value >> 24);
}

static void write64(UINT8 *bytes, UINT64 value)
{
	write32(bytes, (UINT32)value);
	write32(bytes + 4, (UINT32)(value >> 32));
}

static void make_gpt(void)
{
	UINT8 *header = disk_image[1];
	UINT8 *entry = disk_image[2];

	memset(disk_image, 0, sizeof(disk_image));
	memcpy(header, "EFI PART", 8U);
	write32(header + 8, 0x00010000U);
	write32(header + 12, 92U);
	write64(header + 24, 1U);
	write64(header + 32, DISK_BLOCKS - 1U);
	write64(header + 40, 34U);
	write64(header + 48, 98U);
	write64(header + 72, 2U);
	write32(header + 80, 4U);
	write32(header + 84, 128U);
	entry[0] = 1U;
	entry[16] = 2U;
	write64(entry + 32, 40U);
	write64(entry + 40, 49U);
	write32(header + 88, cdk2_partition_crc32(entry, BLOCK_SIZE));
	write32(header + 16, cdk2_partition_crc32(header, 92U));
}

static void add_second_gpt(void)
{
	UINT8 *header = disk_image[1];
	UINT8 *entry = disk_image[2] + 128U;

	entry[0] = 3U;
	entry[16] = 4U;
	write64(entry + 32, 60U);
	write64(entry + 40, 69U);
	write32(header + 88, cdk2_partition_crc32(disk_image[2], BLOCK_SIZE));
	write32(header + 16, 0U);
	write32(header + 16, cdk2_partition_crc32(header, 92U));
}

static uint64_t CDK2_MS_ABI block_reset(struct cdk2_block_io *block, uint8_t ex)
{
	(void)block;
	(void)ex;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI block_read(struct cdk2_block_io *block, uint32_t id,
	uint64_t lba, size_t size, void *buffer)
{
	(void)id;
	if (block->media->io_align > 1U &&
	    ((UINTN)buffer & (block->media->io_align - 1U)) != 0) {
		misaligned_reads++;
		return EFI_INVALID_PARAMETER;
	}
	if (lba >= DISK_BLOCKS || size % BLOCK_SIZE != 0 ||
	    size / BLOCK_SIZE > DISK_BLOCKS - lba)
		return EFI_DEVICE_ERROR;
	memcpy(buffer, disk_image[lba], size);
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI block_write(struct cdk2_block_io *block, uint32_t id,
	uint64_t lba, size_t size, void *buffer)
{
	return block_read(block, id, lba, size, buffer);
}

static uint64_t CDK2_MS_ABI block_flush(struct cdk2_block_io *block)
{
	(void)block;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI disk_rw(struct cdk2_disk_io *disk, uint32_t id,
	uint64_t offset, size_t size, void *buffer)
{
	(void)disk;
	(void)id;
	(void)offset;
	(void)size;
	(void)buffer;
	return EFI_SUCCESS;
}

static struct cdk2_block_media media = {
	.media_id = 1U,
	.media_present = TRUE,
	.block_size = BLOCK_SIZE,
	.last_block = DISK_BLOCKS - 1U,
};
static struct cdk2_block_io block = {
	1U, &media, block_reset, block_read, block_write, block_flush
};
static struct cdk2_disk_io disk = {
	CDK2_DISK_IO_REVISION, disk_rw, disk_rw
};
static UINT8 parent_path[] = {
	0x7fU, 0x01U, 4U, 0U,
	0x7fU, 0xffU, 4U, 0U,
};

static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{
	(void)type;
	allocations++;
	if (fail_allocation != 0 && allocations == fail_allocation)
		return EFI_OUT_OF_RESOURCES;
	*buffer = malloc((size_t)size);
	if (size == 92U)
		installed_path = *buffer;
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{
	free(buffer);
	frees++;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI signal_event(void *event)
{
	(void)event;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context, void **event)
{
	(void)type; (void)tpl; (void)notify; (void)context;
	*event = (void *)1;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{
	(void)event;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI open_protocol(void *handle, const EFI_GUID * guid,
	void **interface, void *agent, void *controller, UINT32 attributes)
{
	(void)handle;
	(void)agent;
	(void)controller;
	if (attributes == 8U)
		return fail_child_open ? EFI_DEVICE_ERROR : EFI_SUCCESS;
	if (guid->data1 == 0xce345171U) {
		*interface = &disk;
		return EFI_SUCCESS;
	}
	if (guid->data1 == 0x964e5b21U) {
		*interface = &block;
		return EFI_SUCCESS;
	}
	if (guid->data1 == 0x09576e91U) {
		*interface = parent_path;
		return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI close_protocol(void *handle, const EFI_GUID * guid,
	void *agent, void *controller)
{
	(void)handle;
	(void)guid;
	(void)agent;
	(void)controller;
	closes++;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{
	if (installed_binding == NULL) {
		return EFI_SUCCESS;
	}
	child_installs++;
	if (fail_child_install)
		return EFI_DEVICE_ERROR;
	child_handle = (void *)0x5000;
	*handle = child_handle;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle, ...)
{
	(void)handle;
	child_uninstalls++;
	return EFI_SUCCESS;
}

static struct boot_services_view boot_services = {
	.allocate_pool = allocate_pool,
	.free_pool = free_pool,
	.create_event = create_event,
	.signal_event = signal_event,
	.close_event = close_event,
	.open_protocol = open_protocol,
	.close_protocol = close_protocol,
	.install_multiple = install_multiple,
	.uninstall_multiple = uninstall_multiple,
};

static int expect(BOOLEAN condition, const char *expression, int line)
{
	if (condition)
		return 0;
	fprintf(stderr, "%s:%d: %s\n", __FILE__, line, expression);
	return 1;
}

#define EXPECT(condition) (failures += expect((condition), #condition, __LINE__))

static void clear_faults(void)
{
	allocations = 0;
	frees = 0;
	closes = 0;
	child_installs = 0;
	child_uninstalls = 0;
	fail_allocation = 0;
	fail_child_install = FALSE;
	fail_child_open = FALSE;
	installed_path = NULL;
	misaligned_reads = 0;
}

int main(void)
{
	struct system_table_view system = { { 0 }, &boot_services };
	void *controller = (void *)0x2000;
	UINTN fault;
	UINT8 remaining[46] = { 0 };
	int failures = 0;

	make_gpt();
	EXPECT(cdk2_partition_entry((void *)0x1000, &system) == EFI_SUCCESS);
	installed_binding = (struct driver_binding *)cdk2_partition_driver_binding();
	EXPECT(installed_binding != NULL && installed_binding->version == 0x10U);
	EXPECT(installed_binding->supported(installed_binding, controller, NULL) ==
		EFI_SUCCESS);
	clear_faults();
	EXPECT(installed_binding->start(installed_binding, controller, NULL) == EFI_SUCCESS);
	EXPECT(child_installs == 1U && child_handle != NULL);
	EXPECT(installed_path != NULL && ((UINT8 *)installed_path)[0] == 4U &&
		((UINT8 *)installed_path)[42] == 0x7fU &&
		((UINT8 *)installed_path)[43] == 0x01U &&
		((UINT8 *)installed_path)[46] == 4U &&
		((UINT8 *)installed_path)[88] == 0x7fU &&
		((UINT8 *)installed_path)[89] == 0xffU);
	EXPECT(installed_binding->stop(installed_binding, controller, 1U,
		&child_handle) == EFI_SUCCESS);
	EXPECT(child_uninstalls == 1U);
	EXPECT(installed_binding->stop(installed_binding, controller, 0, NULL) ==
		EFI_SUCCESS);
	remaining[0] = 4U; remaining[1] = 1U; remaining[2] = 42U;
	write32(remaining + 4, 1U);
	write64(remaining + 8, 40U);
	write64(remaining + 16, 10U);
	remaining[24] = 2U; remaining[40] = 2U; remaining[41] = 2U;
	remaining[42] = 0x7fU; remaining[43] = 0xffU; remaining[44] = 4U;
	clear_faults();
	media.io_align = 64U;
	EXPECT(installed_binding->supported(installed_binding, controller, remaining) ==
		EFI_SUCCESS);
	EXPECT(installed_binding->start(installed_binding, controller, remaining) ==
		EFI_SUCCESS && child_installs == 1U && misaligned_reads == 0);
	add_second_gpt();
	write32(remaining + 4, 2U);
	write64(remaining + 8, 60U);
	remaining[24] = 4U;
	EXPECT(installed_binding->start(installed_binding, controller, remaining) ==
		EFI_SUCCESS && child_installs == 2U && misaligned_reads == 0);
	{
		void *children[2] = { child_handle, child_handle };
		EXPECT(installed_binding->stop(installed_binding, controller, 2U,
			children) == EFI_SUCCESS);
	}
	EXPECT(installed_binding->stop(installed_binding, controller, 0, NULL) ==
		EFI_SUCCESS);
	media.io_align = 0;
	write32(remaining + 4, 3U);
	clear_faults();
	EXPECT(installed_binding->start(installed_binding, controller, remaining) ==
		EFI_NOT_FOUND && child_installs == 0);
	remaining[2] = 41U;
	EXPECT(installed_binding->supported(installed_binding, controller, remaining) ==
		EFI_UNSUPPORTED);
	for (fault = 1; fault <= 4U; fault++) {
		clear_faults();
		fail_allocation = fault;
		EXPECT(installed_binding->start(installed_binding, controller, NULL) ==
			EFI_OUT_OF_RESOURCES);
		EXPECT(closes == 1U);
	}
	clear_faults();
	fail_child_install = TRUE;
	EXPECT(installed_binding->start(installed_binding, controller, NULL) ==
		EFI_DEVICE_ERROR);
	EXPECT(closes == 1U);
	clear_faults();
	fail_child_open = TRUE;
	EXPECT(installed_binding->start(installed_binding, controller, NULL) ==
		EFI_DEVICE_ERROR);
	EXPECT(child_uninstalls == 1U && closes >= 1U);
	if (failures == 0)
		puts("partition driver tests: PASS");
	return failures != 0;
}
