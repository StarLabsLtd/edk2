/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_FAT_H_
#define CDK2_FAT_H_

#include <stddef.h>
#include <stdint.h>

#define CDK2_FAT12 12U
#define CDK2_FAT16 16U
#define CDK2_FAT32 32U

typedef uint64_t cdk2_fat_read_fn(void *context, uint64_t offset, size_t size,
	void *buffer);

struct cdk2_fat_volume {
	cdk2_fat_read_fn *read;
	void *context;
	uint64_t media_size;
	uint64_t fat_offset, data_offset, root_offset;
	uint32_t total_sectors, fat_sectors, cluster_count, root_cluster;
	uint16_t bytes_per_sector, root_entries;
	uint8_t sectors_per_cluster, fat_count, fat_type;
};

struct cdk2_fat_directory_entry {
	uint16_t name[256];
	uint32_t first_cluster, size;
	uint16_t creation_time, creation_date, write_time, write_date;
	uint8_t attributes;
};

struct cdk2_fat_file {
	const struct cdk2_fat_volume *volume;
	struct cdk2_fat_directory_entry entry;
	uint64_t position;
	uint32_t directory_cluster;
	uint8_t is_directory, is_root;
};

struct cdk2_fat_file_info {
	uint64_t size, physical_size;
	uint64_t attributes;
	uint16_t name[256];
};

uint64_t cdk2_fat_probe(struct cdk2_fat_volume *volume,
	cdk2_fat_read_fn *read, void *context, uint64_t media_size);
uint64_t cdk2_fat_cluster_offset(const struct cdk2_fat_volume *volume,
	uint32_t cluster, uint64_t *offset);
uint64_t cdk2_fat_next_cluster(const struct cdk2_fat_volume *volume,
	uint32_t cluster, uint32_t *next, int *end_of_chain);
uint64_t cdk2_fat_read_file(const struct cdk2_fat_volume *volume,
	uint32_t first_cluster, uint32_t file_size, uint64_t position,
	size_t *size, void *buffer);
uint64_t cdk2_fat_parse_directory_entry(const uint8_t *records, size_t count,
	struct cdk2_fat_directory_entry *entry, size_t *consumed);
uint64_t cdk2_fat_open_root(const struct cdk2_fat_volume *volume,
	struct cdk2_fat_file *file);
uint64_t cdk2_fat_open(struct cdk2_fat_file *directory, const uint16_t *path,
	struct cdk2_fat_file *file);
uint64_t cdk2_fat_file_read(struct cdk2_fat_file *file, size_t *size,
	void *buffer);
uint64_t cdk2_fat_file_get_position(const struct cdk2_fat_file *file,
	uint64_t *position);
uint64_t cdk2_fat_file_set_position(struct cdk2_fat_file *file,
	uint64_t position);
uint64_t cdk2_fat_file_get_info(const struct cdk2_fat_file *file,
	size_t *size, struct cdk2_fat_file_info *info);

#endif
