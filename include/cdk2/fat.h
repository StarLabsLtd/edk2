/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_FAT_H_
#define CDK2_FAT_H_

#include <stddef.h>
#include <stdint.h>

#define CDK2_FAT12 12U
#define CDK2_FAT16 16U
#define CDK2_FAT32 32U
#define CDK2_FAT_WRITE_PROTECTED (0x8000000000000000ULL | 8ULL)
#define CDK2_FAT_MEDIA_CHANGED (0x8000000000000000ULL | 13ULL)

typedef uint64_t cdk2_fat_read_fn(void *context, uint64_t offset, size_t size,
	void *buffer);
typedef uint64_t cdk2_fat_write_fn(void *context, uint64_t offset, size_t size,
	const void *buffer);
typedef uint64_t cdk2_fat_flush_fn(void *context);

struct cdk2_fat_volume {
	cdk2_fat_read_fn *read;
	cdk2_fat_write_fn *write;
	cdk2_fat_flush_fn *flush;
	void *context;
	uint64_t media_size;
	uint64_t fat_offset, data_offset, root_offset;
	uint32_t total_sectors, fat_sectors, cluster_count, root_cluster;
	uint16_t bytes_per_sector, root_entries;
	uint16_t fsinfo_sector;
	uint8_t sectors_per_cluster, fat_count, fat_type;
	uint8_t read_only, write_protected, media_changed;
};

struct cdk2_fat_change {
	uint32_t cluster, old_value;
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
	uint32_t parent_directory_cluster;
	uint64_t record_index;
	size_t record_count;
	uint8_t is_directory, is_root;
};

struct cdk2_fat_file_info {
	uint64_t size, physical_size;
	uint64_t attributes;
	uint16_t name[256];
};
struct cdk2_fat_volume_info {
	uint64_t volume_size, free_space;
	uint32_t block_size;
	uint8_t read_only;
	uint16_t label[12];
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
uint64_t cdk2_fat_write_file(struct cdk2_fat_volume *volume,
	uint32_t first_cluster, uint32_t file_size, uint64_t position,
	size_t *size, const void *buffer);
uint64_t cdk2_fat_parse_directory_entry(const uint8_t *records, size_t count,
	struct cdk2_fat_directory_entry *entry, size_t *consumed);
uint64_t cdk2_fat_open_root(const struct cdk2_fat_volume *volume,
	struct cdk2_fat_file *file);
uint64_t cdk2_fat_open(struct cdk2_fat_file *directory, const uint16_t *path,
	struct cdk2_fat_file *file);
uint64_t cdk2_fat_create(struct cdk2_fat_file *directory, const uint16_t *name,
	uint8_t attributes, struct cdk2_fat_file *file,
	struct cdk2_fat_change *changes, size_t *change_count);
uint64_t cdk2_fat_file_read(struct cdk2_fat_file *file, size_t *size,
	void *buffer);
uint64_t cdk2_fat_file_get_position(const struct cdk2_fat_file *file,
	uint64_t *position);
uint64_t cdk2_fat_file_set_position(struct cdk2_fat_file *file,
	uint64_t position);
uint64_t cdk2_fat_file_get_info(const struct cdk2_fat_file *file,
	size_t *size, struct cdk2_fat_file_info *info);
void cdk2_fat_set_write_ops(struct cdk2_fat_volume *volume,
	cdk2_fat_write_fn *write, cdk2_fat_flush_fn *flush);
uint64_t cdk2_fat_resize_chain(struct cdk2_fat_volume *volume,
	uint32_t *first_cluster, uint32_t old_size, uint32_t new_size,
	struct cdk2_fat_change *changes, size_t *change_count);
uint64_t cdk2_fat_generate_short_name(const struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, const uint16_t *name, uint8_t short_name[11]);
uint64_t cdk2_fat_build_directory_records(const uint16_t *name,
	const uint8_t short_name[11], uint8_t attributes, uint32_t first_cluster,
	uint32_t file_size, uint8_t *records, size_t *record_count);
uint64_t cdk2_fat_place_directory_records(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, const uint8_t *records, size_t record_count,
	uint64_t *record_index, uint8_t *rollback_records, size_t *rollback_count);
uint64_t cdk2_fat_resize_file(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t record_index, size_t record_count,
	uint32_t *first_cluster, uint32_t old_size, uint32_t new_size,
	struct cdk2_fat_change *changes, size_t *change_count);
uint64_t cdk2_fat_delete_entry(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t record_index, size_t record_count,
	uint32_t *first_cluster, uint32_t old_size, int is_directory,
	struct cdk2_fat_change *changes, size_t *change_count);
uint64_t cdk2_fat_rename_entry(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t old_index, size_t old_count,
	const uint16_t *new_name, uint8_t attributes, uint32_t first_cluster,
	uint32_t file_size, uint64_t *new_index);
uint64_t cdk2_fat_file_resize(struct cdk2_fat_file *file, uint32_t new_size,
	struct cdk2_fat_change *changes, size_t *change_count);
uint64_t cdk2_fat_file_delete(struct cdk2_fat_file *file,
	struct cdk2_fat_change *changes, size_t *change_count);
uint64_t cdk2_fat_get_volume_info(const struct cdk2_fat_volume *volume,
	struct cdk2_fat_volume_info *info);
uint64_t cdk2_fat_set_volume_label(struct cdk2_fat_volume *volume,
	const uint16_t *label);
uint64_t cdk2_fat_update_metadata(struct cdk2_fat_file *file,
	uint8_t attributes, uint16_t creation_date, uint16_t creation_time,
	uint16_t write_date, uint16_t write_time);
uint64_t cdk2_fat_file_rename(struct cdk2_fat_file *file,
	const uint16_t *new_name);
uint64_t cdk2_fat_file_set_info(struct cdk2_fat_file *file,
	const uint16_t *new_name, uint32_t new_size, uint8_t attributes,
	uint16_t creation_date, uint16_t creation_time, uint16_t write_date,
	uint16_t write_time, struct cdk2_fat_change *changes, size_t *change_count);
void cdk2_fat_file_rollback_resize(struct cdk2_fat_file *file,
	uint32_t old_first_cluster, uint32_t old_size, uint64_t old_position,
	struct cdk2_fat_change *changes, size_t change_count);

#endif
