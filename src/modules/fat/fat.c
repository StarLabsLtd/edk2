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

uint64_t cdk2_fat_next_cluster(const struct cdk2_fat_volume *volume,
	uint32_t cluster, uint32_t *next, int *end_of_chain)
{
	uint8_t data[4];
	uint64_t offset, status;
	uint32_t value, bad, end;
	size_t width;

	if (volume == NULL || volume->read == NULL || next == NULL ||
	    end_of_chain == NULL || cluster < 2U ||
	    cluster >= volume->cluster_count + 2U)
		return EFI_INVALID_PARAMETER;
	if (volume->fat_type == CDK2_FAT12) {
		offset = volume->fat_offset + cluster + cluster / 2U;
		width = 2U; bad = 0xff7U; end = 0xff8U;
	} else if (volume->fat_type == CDK2_FAT16) {
		offset = volume->fat_offset + (uint64_t)cluster * 2U;
		width = 2U; bad = 0xfff7U; end = 0xfff8U;
	} else if (volume->fat_type == CDK2_FAT32) {
		offset = volume->fat_offset + (uint64_t)cluster * 4U;
		width = 4U; bad = 0x0ffffff7U; end = 0x0ffffff8U;
	} else {
		return EFI_INVALID_PARAMETER;
	}
	if (offset > volume->media_size || width > volume->media_size - offset)
		return FAT_VOLUME_CORRUPTED;
	status = volume->read(volume->context, offset, width, data);
	if (status != EFI_SUCCESS)
		return status;
	value = width == 2U ? read16(data) : read32(data);
	if (volume->fat_type == CDK2_FAT12)
		value = (cluster & 1U) != 0U ? value >> 4 : value & 0xfffU;
	else if (volume->fat_type == CDK2_FAT32)
		value &= 0x0fffffffU;
	if (value == bad || value < 2U)
		return FAT_VOLUME_CORRUPTED;
	*end_of_chain = value >= end;
	if (!*end_of_chain && value >= volume->cluster_count + 2U)
		return FAT_VOLUME_CORRUPTED;
	*next = value;
	return EFI_SUCCESS;
}

uint64_t cdk2_fat_read_file(const struct cdk2_fat_volume *volume,
	uint32_t first_cluster, uint32_t file_size, uint64_t position,
	size_t *size, void *buffer)
{
	uint8_t *output = buffer;
	uint64_t cluster_size, cluster_offset, status;
	uint32_t cluster = first_cluster, next, steps = 0U;
	size_t wanted, part;
	int end;

	if (volume == NULL || size == NULL || (*size != 0U && buffer == NULL) ||
	    position > file_size)
		return EFI_INVALID_PARAMETER;
	wanted = *size;
	if (wanted > (uint64_t)file_size - position)
		wanted = (size_t)((uint64_t)file_size - position);
	*size = 0U;
	if (wanted == 0U)
		return EFI_SUCCESS;
	cluster_size = (uint64_t)volume->bytes_per_sector *
		volume->sectors_per_cluster;
	if (cluster_size == 0U || first_cluster < 2U)
		return FAT_VOLUME_CORRUPTED;
	while (position >= cluster_size) {
		status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
		if (status != EFI_SUCCESS || end)
			return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
		cluster = next; position -= cluster_size;
		if (++steps > volume->cluster_count)
			return FAT_VOLUME_CORRUPTED;
	}
	while (wanted != 0U) {
		if (steps >= volume->cluster_count)
			return FAT_VOLUME_CORRUPTED;
		status = cdk2_fat_cluster_offset(volume, cluster, &cluster_offset);
		if (status != EFI_SUCCESS)
			return status;
		part = (size_t)(cluster_size - position);
		if (part > wanted)
			part = wanted;
		status = volume->read(volume->context, cluster_offset + position, part,
			output);
		if (status != EFI_SUCCESS)
			return status;
		*size += part; output += part; wanted -= part; position = 0U;
		if (wanted == 0U)
			break;
		status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
		if (status != EFI_SUCCESS || end)
			return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
		cluster = next;
		if (++steps > volume->cluster_count)
			return FAT_VOLUME_CORRUPTED;
	}
	return EFI_SUCCESS;
}

static uint8_t short_checksum(const uint8_t *name)
{
	uint8_t sum = 0U;
	unsigned int index;

	for (index = 0U; index < 11U; index++)
		sum = (uint8_t)(((sum & 1U) != 0U ? 0x80U : 0U) +
			(sum >> 1) + name[index]);
	return sum;
}

static uint16_t lfn_character(const uint8_t *record, unsigned int index)
{
	static const uint8_t positions[13] = {
		1U, 3U, 5U, 7U, 9U, 14U, 16U, 18U, 20U, 22U, 24U, 28U, 30U
	};
	return read16(record + positions[index]);
}

uint64_t cdk2_fat_parse_directory_entry(const uint8_t *records, size_t count,
	struct cdk2_fat_directory_entry *entry, size_t *consumed)
{
	const uint8_t *record, *short_record;
	uint16_t character;
	uint8_t checksum = 0U, ordinal, expected = 0U;
	size_t index, part, name_length = 0U;
	int have_lfn = 0;

	if (records == NULL || entry == NULL || consumed == NULL || count == 0U)
		return EFI_INVALID_PARAMETER;
	*entry = (struct cdk2_fat_directory_entry) { 0 };
	for (index = 0U; index < count; index++) {
		record = records + index * 32U;
		if (record[0] == 0x00U)
			return EFI_NOT_FOUND;
		if (record[0] == 0xe5U) {
			have_lfn = 0; expected = 0U;
			continue;
		}
		if (record[11U] == 0x0fU) {
			ordinal = record[0] & 0x1fU;
			if (ordinal == 0U || ordinal > 20U || record[12U] != 0U ||
			    read16(record + 26U) != 0U)
				return FAT_VOLUME_CORRUPTED;
			if ((record[0] & 0x40U) != 0U) {
				have_lfn = 1; expected = ordinal; checksum = record[13U];
				name_length = (size_t)ordinal * 13U;
				if (name_length >= 256U)
					return FAT_VOLUME_CORRUPTED;
			} else if (!have_lfn || ordinal + 1U != expected ||
				   checksum != record[13U]) {
				return FAT_VOLUME_CORRUPTED;
			}
			for (part = 0U; part < 13U; part++) {
				character = lfn_character(record, (unsigned int)part);
				entry->name[(size_t)(ordinal - 1U) * 13U + part] =
					character == 0xffffU ? 0U : character;
			}
			expected = ordinal;
			continue;
		}
		short_record = record;
		if ((have_lfn && (expected != 1U ||
		     checksum != short_checksum(short_record))))
			return FAT_VOLUME_CORRUPTED;
		if (!have_lfn) {
			for (part = 0U; part < 8U && short_record[part] != ' '; part++)
				entry->name[name_length++] = short_record[part];
			if (short_record[8U] != ' ') {
				entry->name[name_length++] = '.';
				for (part = 8U; part < 11U && short_record[part] != ' '; part++)
					entry->name[name_length++] = short_record[part];
			}
			entry->name[name_length] = 0U;
		}
		entry->attributes = short_record[11U];
		entry->first_cluster = ((uint32_t)read16(short_record + 20U) << 16) |
			read16(short_record + 26U);
		entry->size = read32(short_record + 28U);
		*consumed = index + 1U;
		return EFI_SUCCESS;
	}
	return FAT_VOLUME_CORRUPTED;
}
