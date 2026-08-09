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

uint64_t cdk2_fat_probe(struct cdk2_fat_volume *volume,
	cdk2_fat_read_fn *read, void *context, uint64_t media_size);
uint64_t cdk2_fat_cluster_offset(const struct cdk2_fat_volume *volume,
	uint32_t cluster, uint64_t *offset);

#endif
