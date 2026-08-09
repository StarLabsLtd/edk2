/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static UINT64 last_lba;
static UINT64 last_offset;
static UINTN installs;
static UINTN uninstalls;
static UINTN opens;
static UINTN closes;
static UINTN frees;
static UINTN signals;
static EFI_STATUS install_status;
static EFI_STATUS open_status;
static EFI_STATUS uninstall_status;
static struct cdk2_partition_info *installed_info;

static uint64_t CDK2_MS_ABI reset(struct cdk2_block_io *block, uint8_t extended)
{
	(void)block;
	(void)extended;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI block_read(struct cdk2_block_io *block, uint32_t id,
	uint64_t lba, size_t size, void *buffer)
{
	(void)block;
	(void)id;
	(void)size;
	(void)buffer;
	last_lba = lba;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI block_write(struct cdk2_block_io *block, uint32_t id,
	uint64_t lba, size_t size, void *buffer)
{
	return block_read(block, id, lba, size, buffer);
}

static uint64_t CDK2_MS_ABI flush(struct cdk2_block_io *block)
{
	(void)block;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI disk_read(struct cdk2_disk_io *disk, uint32_t id,
	uint64_t offset, size_t size, void *buffer)
{
	(void)disk;
	(void)id;
	(void)size;
	(void)buffer;
	last_offset = offset;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI disk_write(struct cdk2_disk_io *disk, uint32_t id,
	uint64_t offset, size_t size, void *buffer)
{
	return disk_read(disk, id, offset, size, buffer);
}

static EFI_STATUS allocate(UINTN size, void **buffer)
{
	*buffer = malloc((size_t)size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static void release(void *buffer)
{
	frees++;
	free(buffer);
}

static EFI_STATUS install(void **handle, struct cdk2_block_io *block,
	struct cdk2_block_io2 *block2, struct cdk2_disk_io *disk,
	struct cdk2_disk_io2 *disk2, void *device_path,
	struct cdk2_partition_info *info)
{
	(void)block;
	(void)block2;
	(void)disk;
	(void)disk2;
	(void)device_path;
	installs++;
	installed_info = info;
	*handle = (void *)0x1234;
	return install_status;
}

static EFI_STATUS uninstall(void *handle, struct cdk2_block_io *block,
	struct cdk2_block_io2 *block2, struct cdk2_disk_io *disk,
	struct cdk2_disk_io2 *disk2, void *device_path,
	struct cdk2_partition_info *info)
{
	(void)handle;
	(void)block;
	(void)block2;
	(void)disk;
	(void)disk2;
	(void)device_path;
	(void)info;
	uninstalls++;
	return uninstall_status;
}

static EFI_STATUS open_parent(void *parent, void *child)
{
	(void)parent;
	(void)child;
	opens++;
	return open_status;
}

static EFI_STATUS close_parent(void *parent, void *child)
{
	(void)parent;
	(void)child;
	closes++;
	return EFI_SUCCESS;
}

static EFI_STATUS signal_event(void *event)
{
	(void)event;
	signals++;
	return EFI_SUCCESS;
}

static const struct cdk2_partition_child_services services = {
	allocate, release, install, uninstall, open_parent, close_parent, signal_event
};

static void reset_state(void)
{
	installs = 0;
	uninstalls = 0;
	opens = 0;
	closes = 0;
	frees = 0;
	signals = 0;
	install_status = EFI_SUCCESS;
	open_status = EFI_SUCCESS;
	uninstall_status = EFI_SUCCESS;
}

static int expect(BOOLEAN condition, const char *expression, int line)
{
	if (condition)
		return 0;
	fprintf(stderr, "%s:%d: %s\n", __FILE__, line, expression);
	return 1;
}

#define EXPECT(condition) (failures += expect((condition), #condition, __LINE__))

int main(void)
{
	struct cdk2_block_media media = {
		.media_id = 7U,
		.media_present = TRUE,
		.block_size = 512U,
		.last_block = 99U,
	};
	struct cdk2_block_io parent_block = {
		.revision = 3U,
		.media = &media,
		.reset = reset,
		.read_blocks = block_read,
		.write_blocks = block_write,
		.flush_blocks = flush,
	};
	struct cdk2_disk_io parent_disk = {
		.revision = CDK2_DISK_IO_REVISION,
		.read_disk = disk_read,
		.write_disk = disk_write,
	};
	struct cdk2_partition partition = {
		.scheme = CDK2_PARTITION_MBR,
		.start_lba = 10U,
		.end_lba = 19U,
		.index = 1U,
		.disk_signature = 0x12345678U,
		.mbr_type = 0xefU,
		.mbr_record = { 0x80U, 1U, 2U, 3U, 0xefU, 4U, 5U, 6U,
			10U, 0U, 0U, 0U, 10U, 0U, 0U, 0U },
	};
	struct cdk2_partition_child *child;
	struct cdk2_block_io *block;
	struct cdk2_block_io2 *block2;
	struct cdk2_disk_io *disk;
	struct cdk2_disk_io2 *disk2;
	struct cdk2_block_io2_token block_token = { (void *)1, EFI_NOT_READY };
	struct cdk2_disk_io2_token disk_token = { (void *)1, EFI_NOT_READY };
	UINT8 buffer[512];
	int failures = 0;

	reset_state();
	EXPECT(cdk2_partition_child_create(&services, (void *)2, &parent_block, NULL,
		&parent_disk, NULL, (void *)3, &partition, &child) == EFI_SUCCESS);
	EXPECT(installs == 1U && opens == 1U &&
		installed_info->revision == 0x1000U && installed_info->type == 1U &&
		installed_info->system == TRUE &&
		installed_info->info.mbr.boot_indicator == 0x80U &&
		installed_info->info.mbr.os_indicator == 0xefU &&
		installed_info->info.mbr.starting_lba[0] == 10U &&
		installed_info->info.mbr.size_in_lba[0] == 10U);
	block = cdk2_partition_child_block(child);
	block2 = cdk2_partition_child_block2(child);
	disk = cdk2_partition_child_disk(child);
	disk2 = cdk2_partition_child_disk2(child);
	EXPECT(block->media->logical_partition == TRUE && block->media->last_block == 9U);
	EXPECT(block->read_blocks(block, 7U, 2U, sizeof(buffer), buffer) == EFI_SUCCESS &&
		last_lba == 12U);
	EXPECT(block->read_blocks(block, 7U, 9U, sizeof(buffer) * 2U, buffer) ==
		EFI_INVALID_PARAMETER);
	EXPECT(disk->read_disk(disk, 7U, 20U, 4U, buffer) == EFI_SUCCESS &&
		last_offset == 5140U);
	EXPECT(disk->read_disk(disk, 7U, 5119U, 2U, buffer) == EFI_INVALID_PARAMETER);
	EXPECT(block2->read_blocks(block2, 7U, 1U, &block_token, sizeof(buffer),
		buffer) == EFI_SUCCESS && block_token.transaction_status == EFI_SUCCESS &&
		signals == 1U && last_lba == 11U);
	EXPECT(disk2->read_disk_ex(disk2, 7U, 1U, &disk_token, 1U, buffer) ==
		EFI_SUCCESS && disk_token.transaction_status == EFI_SUCCESS && signals == 2U);
	EXPECT(cdk2_partition_child_destroy(child) == EFI_SUCCESS);
	EXPECT(closes == 1U && uninstalls == 1U && frees == 1U);

	reset_state();
	install_status = EFI_DEVICE_ERROR;
	EXPECT(cdk2_partition_child_create(&services, NULL, &parent_block, NULL,
		&parent_disk, NULL, NULL, &partition, &child) == EFI_DEVICE_ERROR);
	EXPECT(frees == 1U && opens == 0 && uninstalls == 0);
	reset_state();
	open_status = EFI_DEVICE_ERROR;
	EXPECT(cdk2_partition_child_create(&services, NULL, &parent_block, NULL,
		&parent_disk, NULL, NULL, &partition, &child) == EFI_DEVICE_ERROR);
	EXPECT(frees == 1U && uninstalls == 1U);
	reset_state();
	EXPECT(cdk2_partition_child_create(&services, NULL, &parent_block, NULL,
		&parent_disk, NULL, NULL, &partition, &child) == EFI_SUCCESS);
	uninstall_status = EFI_DEVICE_ERROR;
	EXPECT(cdk2_partition_child_destroy(child) == EFI_DEVICE_ERROR);
	EXPECT(closes == 1U && opens == 2U && frees == 0);
	uninstall_status = EFI_SUCCESS;
	EXPECT(cdk2_partition_child_destroy(child) == EFI_SUCCESS && frees == 1U);
	if (failures == 0)
		puts("partition child lifecycle tests: PASS");
	return failures != 0;
}
