/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/fat.h>
#include <uefi.h>

#define FAT_VOLUME_CORRUPTED EFIERR(10)

static uint16_t read16(const uint8_t *data)
{
	return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t read32(const uint8_t *data)
{
	return (uint32_t)read16(data) | ((uint32_t)read16(data + 2U) << 16);
}

static int power_of_two(uint32_t value)
{
	return value != 0U && (value & (value - 1U)) == 0U;
}

uint64_t cdk2_fat_probe(struct cdk2_fat_volume *volume,
	cdk2_fat_read_fn *read, void *context, uint64_t media_size)
{
	uint8_t sector[512];
	uint32_t reserved, total, fat_sectors, root_sectors, overhead, data_sectors;
	uint64_t described_size;
	uint16_t bytes_per_sector, root_entries;
	uint8_t sectors_per_cluster, fat_count, fat_type;
	uint64_t status;

	if (volume == NULL || read == NULL || media_size < sizeof(sector))
		return EFI_INVALID_PARAMETER;
	status = read(context, 0U, sizeof(sector), sector);
	if (status != EFI_SUCCESS)
		return status;
	bytes_per_sector = read16(sector + 11U);
	sectors_per_cluster = sector[13U];
	reserved = read16(sector + 14U);
	fat_count = sector[16U];
	root_entries = read16(sector + 17U);
	total = read16(sector + 19U);
	if (total == 0U)
		total = read32(sector + 32U);
	fat_sectors = read16(sector + 22U);
	if (fat_sectors == 0U)
		fat_sectors = read32(sector + 36U);
	if (sector[510U] != 0x55U || sector[511U] != 0xaaU ||
	    !power_of_two(bytes_per_sector) || bytes_per_sector < 512U ||
	    bytes_per_sector > 4096U || !power_of_two(sectors_per_cluster) ||
	    sectors_per_cluster > 128U || reserved == 0U || fat_count == 0U ||
	    total == 0U || fat_sectors == 0U)
		return EFI_UNSUPPORTED;
	root_sectors = ((uint32_t)root_entries * 32U + bytes_per_sector - 1U) /
		bytes_per_sector;
	if (fat_sectors > (UINT32_MAX - reserved - root_sectors) / fat_count)
		return FAT_VOLUME_CORRUPTED;
	overhead = reserved + fat_count * fat_sectors + root_sectors;
	if (overhead >= total)
		return FAT_VOLUME_CORRUPTED;
	described_size = (uint64_t)total * bytes_per_sector;
	if (described_size > media_size)
		return FAT_VOLUME_CORRUPTED;
	data_sectors = total - overhead;
	volume->cluster_count = data_sectors / sectors_per_cluster;
	fat_type = volume->cluster_count < 4085U ? CDK2_FAT12 :
		volume->cluster_count < 65525U ? CDK2_FAT16 : CDK2_FAT32;
	if ((fat_type == CDK2_FAT32 && root_entries != 0U) ||
	    (fat_type != CDK2_FAT32 && root_entries == 0U))
		return FAT_VOLUME_CORRUPTED;
	volume->root_cluster = fat_type == CDK2_FAT32 ? read32(sector + 44U) : 0U;
	if (fat_type == CDK2_FAT32 &&
	    (volume->root_cluster < 2U ||
	     volume->root_cluster >= volume->cluster_count + 2U))
		return FAT_VOLUME_CORRUPTED;
	*volume = (struct cdk2_fat_volume) {
		.read = read, .context = context, .media_size = media_size,
		.fat_offset = (uint64_t)reserved * bytes_per_sector,
		.data_offset = (uint64_t)overhead * bytes_per_sector,
		.root_offset = (uint64_t)(reserved + fat_count * fat_sectors) *
			bytes_per_sector,
		.total_sectors = total, .fat_sectors = fat_sectors,
		.cluster_count = data_sectors / sectors_per_cluster,
		.root_cluster = fat_type == CDK2_FAT32 ? read32(sector + 44U) : 0U,
		.bytes_per_sector = bytes_per_sector, .root_entries = root_entries,
		.sectors_per_cluster = sectors_per_cluster, .fat_count = fat_count,
		.fat_type = fat_type
	};
	return EFI_SUCCESS;
}

uint64_t cdk2_fat_cluster_offset(const struct cdk2_fat_volume *volume,
	uint32_t cluster, uint64_t *offset)
{
	uint64_t relative;

	if (volume == NULL || offset == NULL || cluster < 2U ||
	    cluster >= volume->cluster_count + 2U)
		return EFI_INVALID_PARAMETER;
	relative = (uint64_t)(cluster - 2U) * volume->sectors_per_cluster *
		volume->bytes_per_sector;
	if (relative > volume->media_size - volume->data_offset)
		return FAT_VOLUME_CORRUPTED;
	*offset = volume->data_offset + relative;
	return EFI_SUCCESS;
}
