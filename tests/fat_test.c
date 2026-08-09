/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/fat.h>
#include <uefi.h>
#include <stdio.h>
#include <string.h>

#define FAT_VOLUME_CORRUPTED EFIERR(10)
#define FAT_ACCESS_DENIED EFIERR(15)

struct medium { uint8_t boot[512]; uint64_t size; uint64_t status; };
struct chain_medium { uint8_t fat[32], data[128]; };
struct mutation_medium {
	uint8_t bytes[3072];
	unsigned int writes, fail_write, flushes;
	uint64_t flush_status;
};

static void write16(uint8_t *data, uint16_t value)
{ data[0] = value; data[1] = value >> 8; }
static uint16_t test_read16(const uint8_t *data)
{ return (uint16_t)data[0] | ((uint16_t)data[1] << 8); }
static uint32_t test_read32(const uint8_t *data)
{ return (uint32_t)test_read16(data) | ((uint32_t)test_read16(data + 2U) << 16); }
static void write32(uint8_t *data, uint32_t value)
{ write16(data, value); write16(data + 2U, value >> 16); }
static uint64_t read_media(void *opaque, uint64_t offset, size_t size, void *buffer)
{
	struct medium *medium = opaque;
	if (medium->status != EFI_SUCCESS)
		return medium->status;
	if (offset != 0U || size != sizeof(medium->boot))
		return EFI_INVALID_PARAMETER;
	memcpy(buffer, medium->boot, size);
	return EFI_SUCCESS;
}
static uint64_t read_chain(void *opaque, uint64_t offset, size_t size, void *buffer)
{
	struct chain_medium *medium = opaque;
	if (offset >= 64U && offset + size <= 64U + sizeof(medium->fat))
		memcpy(buffer, medium->fat + offset - 64U, size);
	else if (offset >= 128U && offset + size <= 128U + sizeof(medium->data))
		memcpy(buffer, medium->data + offset - 128U, size);
	else
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}
static uint64_t mutation_read(void *opaque, uint64_t offset, size_t size,
	void *buffer)
{
	struct mutation_medium *medium = opaque;
	if (offset > sizeof(medium->bytes) || size > sizeof(medium->bytes) - offset)
		return EFI_INVALID_PARAMETER;
	memcpy(buffer, medium->bytes + offset, size);
	return EFI_SUCCESS;
}
static uint64_t mutation_write(void *opaque, uint64_t offset, size_t size,
	const void *buffer)
{
	struct mutation_medium *medium = opaque;
	medium->writes++;
	if (medium->fail_write != 0U && medium->writes == medium->fail_write)
		return EFI_DEVICE_ERROR;
	if (offset > sizeof(medium->bytes) || size > sizeof(medium->bytes) - offset)
		return EFI_INVALID_PARAMETER;
	memcpy(medium->bytes + offset, buffer, size);
	return EFI_SUCCESS;
}
static uint64_t mutation_flush(void *opaque)
{
	struct mutation_medium *medium = opaque;
	medium->flushes++;
	return medium->flush_status;
}
static void make_bpb(struct medium *medium, uint32_t sectors, uint16_t roots,
	uint16_t fat16, uint32_t fat32, uint8_t cluster)
{
	memset(medium, 0, sizeof(*medium));
	write16(medium->boot + 11U, 512U); medium->boot[13U] = cluster;
	write16(medium->boot + 14U, fat32 == 0U ? 1U : 32U);
	medium->boot[16U] = 2U; write16(medium->boot + 17U, roots);
	write32(medium->boot + 32U, sectors); write16(medium->boot + 22U, fat16);
	write32(medium->boot + 36U, fat32); write32(medium->boot + 44U, 2U);
	medium->boot[510U] = 0x55U; medium->boot[511U] = 0xaaU;
	medium->size = (uint64_t)sectors * 512U;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "FAT test: %s\n", message); return !condition; }
static uint8_t checksum(const uint8_t *name)
{
	uint8_t sum = 0U; unsigned int index;
	for (index = 0U; index < 11U; index++)
		sum = (uint8_t)(((sum & 1U) ? 0x80U : 0U) + (sum >> 1) + name[index]);
	return sum;
}
static void lfn_record(uint8_t *record, uint8_t ordinal, uint8_t sum,
	const uint16_t *name)
{
	static const uint8_t positions[13] = {
		1U, 3U, 5U, 7U, 9U, 14U, 16U, 18U, 20U, 22U, 24U, 28U, 30U
	};
	unsigned int index;
	memset(record, 0xff, 32U); record[0] = ordinal; record[11U] = 0x0fU;
	record[12U] = 0U; record[13U] = sum; write16(record + 26U, 0U);
	for (index = 0U; index < 13U; index++)
		write16(record + positions[index], name[index]);
}

int main(void)
{
	struct cdk2_fat_volume volume;
	struct medium medium;
	struct chain_medium chain = { 0 };
	struct mutation_medium mutation = { 0 };
	struct cdk2_fat_change changes[8];
	struct cdk2_fat_directory_entry entry;
	struct cdk2_fat_file root, file;
	struct cdk2_fat_file_info info;
	uint8_t records[96] = { 0 }, output[32];
	uint8_t built_records[672], short_name[11];
	uint16_t long_name[13] = {
		'L', 'o', 'n', 'g', ' ', 'N', 'a', 'm', 'e', '.', 't', 'x', 't'
	};
	size_t size, consumed;
	uint64_t offset;
	int failures = 0;

	make_bpb(&medium, 4096U, 224U, 9U, 0U, 1U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_SUCCESS && volume.fat_type == CDK2_FAT12,
		"valid FAT12 BPB was rejected");
	make_bpb(&medium, 65500U, 512U, 250U, 0U, 1U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_SUCCESS && volume.fat_type == CDK2_FAT16,
		"valid FAT16 BPB was rejected");
	make_bpb(&medium, 200000U, 0U, 0U, 1000U, 1U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_SUCCESS && volume.fat_type == CDK2_FAT32 &&
		cdk2_fat_cluster_offset(&volume, 2U, &offset) == EFI_SUCCESS &&
		offset == volume.data_offset, "valid FAT32 geometry was not mapped");
	medium.boot[510U] = 0U;
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_UNSUPPORTED, "missing boot signature was admitted");
	make_bpb(&medium, 200000U, 0U, 0U, 1000U, 3U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_UNSUPPORTED, "non-power-of-two cluster geometry was admitted");
	make_bpb(&medium, 200000U, 0U, 0U, 1000U, 1U); medium.size--;
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		FAT_VOLUME_CORRUPTED, "truncated medium was admitted");
	volume = (struct cdk2_fat_volume) {
		.read = read_chain, .context = &chain, .media_size = 160U,
		.fat_offset = 64U, .data_offset = 128U, .cluster_count = 4U,
		.bytes_per_sector = 4U, .sectors_per_cluster = 1U,
		.fat_type = CDK2_FAT16
	};
	write16(chain.fat + 4U, 3U); write16(chain.fat + 6U, 0xffffU);
	memcpy(chain.data, "ABCDEFGH", 8U); size = 6U;
	failures += expect(cdk2_fat_read_file(&volume, 2U, 8U, 1U, &size, output) ==
		EFI_SUCCESS && size == 6U && memcmp(output, "BCDEFG", 6U) == 0,
		"bounded cross-cluster file read failed");
	chain.fat[3U] = 0x03U; chain.fat[4U] = 0xf0U; chain.fat[5U] = 0xffU;
	volume.fat_type = CDK2_FAT12;
	{
		uint32_t next; int end;
		failures += expect(cdk2_fat_next_cluster(&volume, 2U, &next, &end) ==
			EFI_SUCCESS && next == 3U && !end &&
			cdk2_fat_next_cluster(&volume, 3U, &next, &end) == EFI_SUCCESS && end,
			"packed FAT12 entries were decoded incorrectly");
		chain.fat[3U] = 0xf7U; chain.fat[4U] = 0x0fU;
		failures += expect(cdk2_fat_next_cluster(&volume, 2U, &next, &end) ==
			FAT_VOLUME_CORRUPTED, "bad-cluster marker was admitted");
	}
	volume.fat_type = CDK2_FAT16;
	write16(chain.fat + 4U, 3U); write16(chain.fat + 6U, 0xffffU);
	size = sizeof(output);
	failures += expect(cdk2_fat_read_file(&volume, 2U, 9U, 0U, &size, output) ==
		FAT_VOLUME_CORRUPTED && size == 8U,
		"truncated file chain was not reported");
	write16(chain.fat + 6U, 2U); size = 20U;
	failures += expect(cdk2_fat_read_file(&volume, 2U, 20U, 0U, &size, output) ==
		FAT_VOLUME_CORRUPTED, "cyclic file chain was not bounded");
	memcpy(records + 32U, "LONGNA~1TXT", 11U); records[32U + 11U] = 0x20U;
	write16(records + 32U + 26U, 2U); write32(records + 32U + 28U, 8U);
	lfn_record(records, 0x41U, checksum(records + 32U), long_name);
	failures += expect(cdk2_fat_parse_directory_entry(records, 2U, &entry,
		&consumed) == EFI_SUCCESS && consumed == 2U && entry.name[0] == 'L' &&
		entry.name[12] == 't' && entry.first_cluster == 2U && entry.size == 8U,
		"valid long filename sequence was rejected");
	records[13U]++;
	failures += expect(cdk2_fat_parse_directory_entry(records, 2U, &entry,
		&consumed) == FAT_VOLUME_CORRUPTED,
		"long filename checksum mismatch was admitted");
	memset(records, 0, sizeof(records)); memcpy(records, "README  TXT", 11U);
	records[11U] = 0x20U;
	failures += expect(cdk2_fat_parse_directory_entry(records, 1U, &entry,
		&consumed) == EFI_SUCCESS && entry.name[6] == '.' && entry.name[9] == 'T',
		"short filename fallback was not decoded");
	write16(records + 24U, (13U << 5) | 1U);
	failures += expect(cdk2_fat_parse_directory_entry(records, 1U, &entry,
		&consumed) == FAT_VOLUME_CORRUPTED,
		"invalid FAT timestamp was admitted");
	write16(records + 24U, 0U); records[11U] = 0x80U;
	failures += expect(cdk2_fat_parse_directory_entry(records, 1U, &entry,
		&consumed) == FAT_VOLUME_CORRUPTED,
		"reserved directory attributes were admitted");
	memset(&chain, 0, sizeof(chain));
	volume = (struct cdk2_fat_volume) {
		.read = read_chain, .context = &chain, .media_size = 256U,
		.fat_offset = 64U, .data_offset = 128U, .cluster_count = 4U,
		.root_cluster = 2U, .bytes_per_sector = 32U, .sectors_per_cluster = 1U,
		.fat_type = CDK2_FAT32
	};
	write32(chain.fat + 8U, 0x0fffffffU);
	write32(chain.fat + 16U, 0x0fffffffU);
	write32(chain.fat + 20U, 0x0fffffffU);
	memcpy(chain.data, "DIR        ", 11U); chain.data[11U] = 0x10U;
	write16(chain.data + 20U, 0U); write16(chain.data + 26U, 4U);
	memcpy(chain.data + 64U, "NEST    TXT", 11U); chain.data[64U + 11U] = 0x20U;
	write16(chain.data + 64U + 26U, 5U); write32(chain.data + 64U + 28U, 5U);
	memcpy(chain.data + 96U, "HELLO", 5U);
	failures += expect(cdk2_fat_open_root(&volume, &root) == EFI_SUCCESS &&
		cdk2_fat_open(&root, (const uint16_t[]){
			'd', 'i', 'r', '/', 'n', 'e', 's', 't', '.', 't', 'x', 't', 0
		}, &file) == EFI_SUCCESS && !file.is_directory,
		"case-insensitive nested path lookup failed");
	failures += expect(file.parent_directory_cluster == 4U &&
		file.record_index == 0U && file.record_count == 1U,
		"opened file did not retain its exact parent directory record range");
	size = 0U;
	failures += expect(cdk2_fat_file_get_info(&file, &size, NULL) ==
		EFI_BUFFER_TOO_SMALL && size == offsetof(struct cdk2_fat_file_info, name) +
		18U, "file info sizing contract is wrong");
	size = sizeof(info);
	failures += expect(cdk2_fat_file_get_info(&file, &size, &info) == EFI_SUCCESS &&
		info.size == 5U && info.name[0] == 'N', "file info content is wrong");
	size = 2U;
	failures += expect(cdk2_fat_file_read(&file, &size, output) == EFI_SUCCESS &&
		size == 2U && memcmp(output, "HE", 2U) == 0 &&
		cdk2_fat_file_get_position(&file, &offset) == EFI_SUCCESS && offset == 2U,
		"file read/position semantics failed");
	failures += expect(cdk2_fat_file_set_position(&file, UINT64_MAX) == EFI_SUCCESS &&
		cdk2_fat_file_get_position(&file, &offset) == EFI_SUCCESS && offset == 5U,
		"end-position sentinel was not honored");
	size = 1U;
	failures += expect(cdk2_fat_file_read(&root, &size, output) ==
		EFI_BUFFER_TOO_SMALL && root.position == 0U && size > 1U,
		"short directory buffer advanced enumeration");
	size = sizeof(info);
	failures += expect(cdk2_fat_file_read(&root, &size, &info) == EFI_SUCCESS &&
		info.name[0] == 'D' && root.position == 1U &&
		cdk2_fat_file_set_position(&root, 1U) == EFI_UNSUPPORTED &&
		cdk2_fat_file_set_position(&root, 0U) == EFI_SUCCESS,
		"directory iteration or position reset semantics failed");
	failures += expect(cdk2_fat_generate_short_name(&volume, 2U,
		(const uint16_t[]){ 'L', 'o', 'n', 'g', ' ', 'f', 'i', 'l', 'e', '.',
			't', 'x', 't', 0 }, short_name) == EFI_SUCCESS &&
		memcmp(short_name, "LONGFI~1TXT", 11U) == 0,
		"deterministic short-name generation failed");
	size = 0U;
	failures += expect(cdk2_fat_build_directory_records(
		(const uint16_t[]){ 'L', 'o', 'n', 'g', ' ', 'f', 'i', 'l', 'e', '.',
			't', 'x', 't', 0 }, short_name, 0x20U, 5U, 5U, NULL, &size) ==
		EFI_BUFFER_TOO_SMALL && size == 2U, "LFN record sizing is wrong");
	failures += expect(cdk2_fat_build_directory_records(
		(const uint16_t[]){ 'L', 'o', 'n', 'g', ' ', 'f', 'i', 'l', 'e', '.',
			't', 'x', 't', 0 }, short_name, 0x20U, 5U, 5U, built_records,
		&size) == EFI_SUCCESS && cdk2_fat_parse_directory_entry(built_records,
		size, &entry, &consumed) == EFI_SUCCESS && entry.name[0] == 'L' &&
		entry.first_cluster == 5U && entry.size == 5U,
		"generated LFN records did not round-trip");
	volume = (struct cdk2_fat_volume) {
		.read = mutation_read, .context = &mutation, .media_size = 512U,
		.fat_offset = 64U, .data_offset = 128U, .cluster_count = 6U,
		.fat_sectors = 1U, .bytes_per_sector = 32U, .sectors_per_cluster = 1U,
		.fat_count = 2U, .fat_type = CDK2_FAT16
	};
	cdk2_fat_set_write_ops(&volume, mutation_write, mutation_flush);
	write16(mutation.bytes + 64U + 4U, 0xffffU);
	write16(mutation.bytes + 96U + 4U, 0xffffU);
	{
		uint32_t first = 2U;
		size_t change_count = 8U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 1U, 96U,
			changes, &change_count) == EFI_SUCCESS && first == 2U &&
			change_count == 3U && test_read16(mutation.bytes + 64U + 4U) == 3U &&
			test_read16(mutation.bytes + 64U + 6U) == 4U &&
			test_read16(mutation.bytes + 64U + 8U) == 0xffffU &&
			memcmp(mutation.bytes + 64U, mutation.bytes + 96U, 32U) == 0,
			"chain extension or FAT mirroring failed");
		change_count = 8U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 96U, 0U,
			changes, &change_count) == EFI_SUCCESS && first == 0U &&
			test_read16(mutation.bytes + 64U + 4U) == 0U &&
			test_read16(mutation.bytes + 64U + 6U) == 0U,
			"chain deletion did not release clusters");
		write16(mutation.bytes + 64U + 4U, 0xffffU);
		write16(mutation.bytes + 96U + 4U, 0xffffU);
		first = 2U;
		mutation.writes = 0U; mutation.fail_write = 3U; change_count = 8U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 1U, 64U,
			changes, &change_count) == EFI_DEVICE_ERROR &&
			test_read16(mutation.bytes + 64U + 4U) == 0xffffU &&
			test_read16(mutation.bytes + 64U + 6U) == 0U,
			"failed mirrored FAT write was not rolled back");
		mutation.fail_write = 0U; volume.read_only = 1U; change_count = 8U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 1U, 64U,
			changes, &change_count) == CDK2_FAT_WRITE_PROTECTED,
			"read-only volume admitted mutation");
		volume.read_only = 0U; volume.media_changed = 1U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 1U, 64U,
			changes, &change_count) == CDK2_FAT_MEDIA_CHANGED,
			"media-changed volume admitted mutation");
		volume.media_changed = 0U; volume.write_protected = 1U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 1U, 64U,
			changes, &change_count) == CDK2_FAT_WRITE_PROTECTED,
			"write-protected medium admitted mutation");
	}
	memset(&mutation, 0, sizeof(mutation));
	volume = (struct cdk2_fat_volume) {
		.read = mutation_read, .context = &mutation, .media_size = 2048U,
		.fat_offset = 1024U, .data_offset = 1536U, .cluster_count = 4U,
		.total_sectors = 4U, .fat_sectors = 1U, .bytes_per_sector = 512U,
		.sectors_per_cluster = 1U, .fat_count = 1U, .fat_type = CDK2_FAT32,
		.fsinfo_sector = 1U
	};
	cdk2_fat_set_write_ops(&volume, mutation_write, mutation_flush);
	write32(mutation.bytes + 512U, 0x41615252U);
	write32(mutation.bytes + 512U + 484U, 0x61417272U);
	write32(mutation.bytes + 512U + 488U, 3U);
	write32(mutation.bytes + 512U + 492U, 3U);
	write32(mutation.bytes + 512U + 508U, 0xaa550000U);
	write32(mutation.bytes + 1024U + 8U, 0x0fffffffU);
	{
		uint32_t first = 2U;
		size_t change_count = 8U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 1U, 1024U,
			changes, &change_count) == EFI_SUCCESS &&
			mutation.bytes[512U + 488U] == 0xffU &&
			mutation.bytes[512U + 492U] == 0xffU && mutation.flushes == 1U,
			"FAT32 FSInfo was not conservatively invalidated and flushed");
		write32(mutation.bytes + 1024U + 8U, 0x0fffffffU);
		write32(mutation.bytes + 1024U + 12U, 0U);
		mutation.flush_status = EFI_DEVICE_ERROR; change_count = 8U;
		failures += expect(cdk2_fat_resize_chain(&volume, &first, 1U, 1024U,
			changes, &change_count) == EFI_DEVICE_ERROR &&
			(test_read32(mutation.bytes + 1024U + 8U) & 0x0fffffffU) ==
				0x0fffffffU && test_read32(mutation.bytes + 1024U + 12U) == 0U,
			"flush failure did not roll back FAT allocation");
	}
	memset(&mutation, 0, sizeof(mutation));
	volume = (struct cdk2_fat_volume) {
		.read = mutation_read, .context = &mutation, .media_size = 3072U,
		.fat_offset = 1024U, .data_offset = 1536U, .cluster_count = 4U,
		.fat_sectors = 1U, .bytes_per_sector = 512U, .sectors_per_cluster = 1U,
		.fat_count = 1U, .fat_type = CDK2_FAT32, .root_cluster = 2U
	};
	cdk2_fat_set_write_ops(&volume, mutation_write, mutation_flush);
	write32(mutation.bytes + 1024U + 8U, 3U);
	write32(mutation.bytes + 1024U + 12U, 0x0fffffffU);
	for (size = 0U; size < 15U; size++)
		mutation.bytes[1536U + size * 32U] = 'A';
	size = 2U;
	(void)cdk2_fat_build_directory_records(
		(const uint16_t[]){ 'C', 'r', 'o', 's', 's', '.', 't', 'x', 't', 0 },
		(const uint8_t *)"CROSS~1 TXT", 0x20U, 4U, 7U, built_records, &size);
	{
		uint8_t rollback[64]; uint64_t placed; size_t rollback_count = 2U;
		failures += expect(cdk2_fat_place_directory_records(&volume, 2U,
			built_records, 2U, &placed, rollback, &rollback_count) == EFI_SUCCESS &&
			placed == 15U && mutation.bytes[1536U + 15U * 32U] == 0x41U &&
			mutation.bytes[2048U] != 0U,
			"directory records were not placed across a cluster boundary");
		memset(mutation.bytes + 1536U + 15U * 32U, 0, 32U);
		memset(mutation.bytes + 2048U, 0, 32U);
		mutation.writes = 0U; mutation.fail_write = 2U; rollback_count = 2U;
		failures += expect(cdk2_fat_place_directory_records(&volume, 2U,
			built_records, 2U, &placed, rollback, &rollback_count) ==
			EFI_DEVICE_ERROR && mutation.bytes[1536U + 15U * 32U] == 0U,
			"partial directory placement was not rolled back");
	}
	/* A full growable directory allocates and zeroes one new cluster. */
	memset(mutation.bytes + 1536U, 'A', 512U);
	memset(mutation.bytes + 2048U, 0xcc, 512U);
	write32(mutation.bytes + 1024U + 8U, 0x0fffffffU);
	write32(mutation.bytes + 1024U + 12U, 0U);
	mutation.writes = 0U; mutation.fail_write = 0U;
	{
		uint8_t rollback[64]; uint64_t placed; size_t rollback_count = 2U;
		failures += expect(cdk2_fat_place_directory_records(&volume, 2U,
			built_records, 2U, &placed, rollback, &rollback_count) == EFI_SUCCESS &&
			placed == 16U && (test_read32(mutation.bytes + 1024U + 8U) &
			0x0fffffffU) == 3U && mutation.bytes[2048U] == 0x41U,
			"full directory did not transactionally grow its cluster chain");
	}
	memset(mutation.bytes + 1536U, 'A', 512U);
	write32(mutation.bytes + 1024U + 8U, 0x0fffffffU);
	write32(mutation.bytes + 1024U + 12U, 0U);
	mutation.writes = 0U; mutation.fail_write = 3U;
	{
		uint8_t rollback[64]; uint64_t placed; size_t rollback_count = 2U;
		failures += expect(cdk2_fat_place_directory_records(&volume, 2U,
			built_records, 2U, &placed, rollback, &rollback_count) ==
			EFI_DEVICE_ERROR && (test_read32(mutation.bytes + 1024U + 8U) &
			0x0fffffffU) == 0x0fffffffU &&
			test_read32(mutation.bytes + 1024U + 12U) == 0U,
			"directory initialization failure leaked its allocated cluster");
	}
	mutation.fail_write = 0U;
	/* Short aliases must advance past an existing collision. */
	memset(mutation.bytes + 1536U, 0, 1024U);
	memcpy(mutation.bytes + 1536U, "LONGFI~1TXT", 11U);
	mutation.bytes[1536U + 11U] = 0x20U;
	failures += expect(cdk2_fat_generate_short_name(&volume, 2U,
		(const uint16_t[]){ 'L','o','n','g',' ','f','i','l','e','.','t','x','t',0 },
		short_name) == EFI_SUCCESS && memcmp(short_name, "LONGFI~2TXT", 11U) == 0,
		"short-name collision did not advance the numeric tail");

	/* A directory containing a real child cannot be deleted. */
	memset(mutation.bytes + 1536U, 0, 1024U);
	memcpy(mutation.bytes + 1536U, "SUBDIR     ", 11U);
	mutation.bytes[1536U + 11U] = 0x10U;
	write16(mutation.bytes + 1536U + 26U, 3U);
	memcpy(mutation.bytes + 2048U, "CHILD   TXT", 11U);
	mutation.bytes[2048U + 11U] = 0x20U;
	write32(mutation.bytes + 1024U + 8U, 0x0fffffffU);
	write32(mutation.bytes + 1024U + 12U, 0x0fffffffU);
	{
		uint32_t first = 3U; size_t change_count = 8U;
		failures += expect(cdk2_fat_delete_entry(&volume, 2U, 0U, 1U,
			&first, 512U, 1, changes, &change_count) == FAT_ACCESS_DENIED &&
			first == 3U && mutation.bytes[1536U] == 'S',
			"non-empty directory deletion was admitted");
	}

	/* Metadata failure after FAT mutation restores both allocation and entry. */
	memset(mutation.bytes + 1536U, 0, 1024U);
	memcpy(mutation.bytes + 1536U, "FILE    BIN", 11U);
	mutation.bytes[1536U + 11U] = 0x20U;
	write16(mutation.bytes + 1536U + 26U, 3U);
	write32(mutation.bytes + 1536U + 28U, 512U);
	write32(mutation.bytes + 1024U + 12U, 0x0fffffffU);
	mutation.writes = 0U; mutation.fail_write = 2U;
	{
		uint32_t first = 3U; size_t change_count = 8U;
		failures += expect(cdk2_fat_resize_file(&volume, 2U, 0U, 1U,
			&first, 512U, 0U, changes, &change_count) == EFI_DEVICE_ERROR &&
			first == 3U && (test_read32(mutation.bytes + 1024U + 12U) &
			0x0fffffffU) == 0x0fffffffU &&
			test_read32(mutation.bytes + 1536U + 28U) == 512U,
			"allocator and directory metadata did not roll back together");
	}

	/* Rename publishes the replacement transactionally and tombstones the old. */
	mutation.fail_write = 0U; mutation.writes = 0U;
	failures += expect(cdk2_fat_rename_entry(&volume, 2U, 0U, 1U,
		(const uint16_t[]){ 'R','e','n','a','m','e','d','.','b','i','n',0 },
		0x20U, 3U, 512U, &offset) == EFI_SUCCESS && offset == 1U &&
		mutation.bytes[1536U] == 0xe5U && mutation.bytes[1536U + 32U] == 0x41U,
		"transactional rename did not publish replacement records");
	/* Failed deletion of the old name restores both record ranges. */
	memset(mutation.bytes + 1536U, 0, 512U);
	memcpy(mutation.bytes + 1536U, "FILE    BIN", 11U);
	mutation.bytes[1536U + 11U] = 0x20U;
	mutation.writes = 0U; mutation.fail_write = 3U;
	failures += expect(cdk2_fat_rename_entry(&volume, 2U, 0U, 1U,
		(const uint16_t[]){ 'R','e','n','a','m','e','d','.','b','i','n',0 },
		0x20U, 3U, 512U, &offset) == EFI_DEVICE_ERROR &&
		mutation.bytes[1536U] == 'F' && mutation.bytes[1536U + 32U] == 0U,
		"failed rename did not restore old and replacement directory slots");
	/* Existing-chain writes cross clusters, report partial faults, and flush. */
	memset(mutation.bytes + 1536U, 0, 1024U);
	write32(mutation.bytes + 1024U + 8U, 3U);
	write32(mutation.bytes + 1024U + 12U, 0x0fffffffU);
	mutation.fail_write = 0U; mutation.flush_status = EFI_SUCCESS;
	mutation.writes = mutation.flushes = 0U; size = 6U;
	failures += expect(cdk2_fat_write_file(&volume, 2U, 1024U, 510U, &size,
		"ABCDEF") == EFI_SUCCESS && size == 6U &&
		memcmp(mutation.bytes + 1536U + 510U, "AB", 2U) == 0 &&
		memcmp(mutation.bytes + 2048U, "CDEF", 4U) == 0 && mutation.flushes == 1U,
		"cross-cluster byte write or flush failed");
	mutation.writes = 0U; mutation.fail_write = 2U; size = 6U;
	failures += expect(cdk2_fat_write_file(&volume, 2U, 1024U, 510U, &size,
		"GHIJKL") == EFI_DEVICE_ERROR && size == 2U,
		"write fault did not report the exact committed prefix");
	mutation.fail_write = 0U; volume.write_protected = 1U; size = 1U;
	failures += expect(cdk2_fat_write_file(&volume, 2U, 1024U, 0U, &size,
		"X") == CDK2_FAT_WRITE_PROTECTED,
		"write-protected volume admitted byte write");
	volume.write_protected = 0U;
	memset(mutation.bytes + 1536U, 0, 512U);
	memcpy(mutation.bytes + 1536U, "MY VOLUME  ", 11U);
	mutation.bytes[1536U + 11U] = 0x08U;
	write32(mutation.bytes + 1024U + 8U, 3U);
	write32(mutation.bytes + 1024U + 12U, 0x0fffffffU);
	write32(mutation.bytes + 1024U + 16U, 0U);
	write32(mutation.bytes + 1024U + 20U, 0U);
	{
		struct cdk2_fat_volume_info volume_info;
		failures += expect(cdk2_fat_get_volume_info(&volume, &volume_info) ==
			EFI_SUCCESS && volume_info.volume_size == 2048U &&
			volume_info.free_space == 1024U && volume_info.block_size == 512U &&
			volume_info.label[0] == 'M' && volume_info.label[2] == 'V',
			"volume size/free-space/label information is wrong");
	}
	memcpy(mutation.bytes + 1536U + 32U, "META    TXT", 11U);
	mutation.bytes[1536U + 32U + 11U] = 0x20U;
	file = (struct cdk2_fat_file) { .volume = &volume,
		.parent_directory_cluster = 2U, .record_index = 1U,
		.record_count = 1U };
	mutation.flush_status = EFI_SUCCESS;
	failures += expect(cdk2_fat_update_metadata(&file, 0x21U, 0x5821U,
		0x1000U, 0x5822U, 0x2000U) == EFI_SUCCESS &&
		mutation.bytes[1536U + 32U + 11U] == 0x21U &&
		file.entry.write_date == 0x5822U,
		"validated file metadata was not committed");
	mutation.flush_status = EFI_DEVICE_ERROR;
	failures += expect(cdk2_fat_update_metadata(&file, 0x22U, 0x5821U,
		0x1000U, 0x5822U, 0x2000U) == EFI_DEVICE_ERROR &&
		mutation.bytes[1536U + 32U + 11U] == 0x21U &&
		file.entry.attributes == 0x21U,
		"metadata flush failure did not restore disk and handle state");
	mutation.flush_status = EFI_SUCCESS;
	failures += expect(cdk2_fat_file_rename(&file,
		(const uint16_t[]){ 'N','e','w',' ','M','e','t','a','.','t','x','t',0 }) ==
		EFI_SUCCESS && file.entry.name[0] == 'N' && file.record_index == 2U &&
		file.record_count == 2U && mutation.bytes[1536U + 32U] == 0xe5U,
		"file-handle rename did not move ownership to replacement records");
	return failures == 0 ? 0 : 1;
}
