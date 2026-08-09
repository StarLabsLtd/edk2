/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/fat.h>
#include <uefi.h>
#include <stdio.h>
#include <string.h>

#define FAT_VOLUME_CORRUPTED EFIERR(10)

struct medium { uint8_t boot[512]; uint64_t size; uint64_t status; };
struct chain_medium { uint8_t fat[32], data[128]; };

static void write16(uint8_t *data, uint16_t value)
{ data[0] = value; data[1] = value >> 8; }
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
	struct cdk2_fat_directory_entry entry;
	struct cdk2_fat_file root, file;
	struct cdk2_fat_file_info info;
	uint8_t records[96] = { 0 }, output[32];
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
	return failures == 0 ? 0 : 1;
}
