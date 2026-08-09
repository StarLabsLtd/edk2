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

static int valid_fat_datetime(uint16_t date, uint16_t time)
{
	unsigned int month, day, hour, minute, second;

	if (date == 0U && time == 0U)
		return 1;
	month = (date >> 5) & 15U; day = date & 31U;
	hour = time >> 11; minute = (time >> 5) & 63U;
	second = (time & 31U) * 2U;
	return month >= 1U && month <= 12U && day >= 1U && day <= 31U &&
		hour <= 23U && minute <= 59U && second <= 59U;
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
		if ((short_record[11U] & 0xc0U) != 0U ||
		    !valid_fat_datetime(read16(short_record + 16U),
			read16(short_record + 14U)) ||
		    !valid_fat_datetime(read16(short_record + 24U),
			read16(short_record + 22U)))
			return FAT_VOLUME_CORRUPTED;
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
		entry->creation_time = read16(short_record + 14U);
		entry->creation_date = read16(short_record + 16U);
		entry->write_time = read16(short_record + 22U);
		entry->write_date = read16(short_record + 24U);
		*consumed = index + 1U;
		return EFI_SUCCESS;
	}
	return FAT_VOLUME_CORRUPTED;
}

static uint64_t directory_record(const struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t index, uint8_t *record)
{
	uint64_t cluster_size, offset, status;
	uint32_t cluster, next, steps = 0U;
	int end;

	if (volume == NULL || record == NULL)
		return EFI_INVALID_PARAMETER;
	if (directory_cluster == 0U && volume->fat_type != CDK2_FAT32) {
		if (index >= volume->root_entries)
			return EFI_NOT_FOUND;
		offset = volume->root_offset + index * 32U;
		return volume->read(volume->context, offset, 32U, record);
	}
	cluster = directory_cluster == 0U ? volume->root_cluster : directory_cluster;
	cluster_size = (uint64_t)volume->bytes_per_sector *
		volume->sectors_per_cluster;
	if (cluster_size < 32U || cluster < 2U)
		return FAT_VOLUME_CORRUPTED;
	while (index >= cluster_size / 32U) {
		status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
		if (status != EFI_SUCCESS || end)
			return status == EFI_SUCCESS ? EFI_NOT_FOUND : status;
		cluster = next; index -= cluster_size / 32U;
		if (++steps >= volume->cluster_count)
			return FAT_VOLUME_CORRUPTED;
	}
	status = cdk2_fat_cluster_offset(volume, cluster, &offset);
	if (status != EFI_SUCCESS)
		return status;
	return volume->read(volume->context, offset + index * 32U, 32U, record);
}

static uint64_t next_directory_entry(const struct cdk2_fat_volume *volume,
	uint32_t cluster, uint64_t *position, struct cdk2_fat_directory_entry *entry)
{
	uint8_t records[21U * 32U], ordinal;
	uint64_t status;
	size_t count, consumed;

	for (;;) {
		status = directory_record(volume, cluster, *position, records);
		if (status != EFI_SUCCESS)
			return status;
		if (records[0] == 0x00U)
			return EFI_NOT_FOUND;
		if (records[0] == 0xe5U) {
			(*position)++;
			continue;
		}
		count = 1U;
		if (records[11U] == 0x0fU) {
			ordinal = records[0] & 0x1fU;
			if ((records[0] & 0x40U) == 0U || ordinal == 0U || ordinal > 20U)
				return FAT_VOLUME_CORRUPTED;
			count = (size_t)ordinal + 1U;
			for (consumed = 1U; consumed < count; consumed++) {
				status = directory_record(volume, cluster, *position + consumed,
					records + consumed * 32U);
				if (status != EFI_SUCCESS)
					return FAT_VOLUME_CORRUPTED;
			}
		}
		status = cdk2_fat_parse_directory_entry(records, count, entry, &consumed);
		if (status != EFI_SUCCESS)
			return status;
		*position += consumed;
		if ((entry->attributes & 0x08U) == 0U)
			return EFI_SUCCESS;
	}
}

static uint16_t fold(uint16_t character)
{
	return character >= 'a' && character <= 'z' ?
		(uint16_t)(character - ('a' - 'A')) : character;
}

static int name_equal(const uint16_t *left, const uint16_t *right, size_t length)
{
	size_t index;
	for (index = 0U; index < length; index++)
		if (left[index] == 0U || fold(left[index]) != fold(right[index]))
			return 0;
	return left[length] == 0U;
}

uint64_t cdk2_fat_open_root(const struct cdk2_fat_volume *volume,
	struct cdk2_fat_file *file)
{
	if (volume == NULL || file == NULL)
		return EFI_INVALID_PARAMETER;
	*file = (struct cdk2_fat_file) {
		.volume = volume, .directory_cluster = volume->fat_type == CDK2_FAT32 ?
			volume->root_cluster : 0U, .is_directory = 1U, .is_root = 1U
	};
	file->entry.attributes = 0x10U;
	return EFI_SUCCESS;
}

uint64_t cdk2_fat_open(struct cdk2_fat_file *directory, const uint16_t *path,
	struct cdk2_fat_file *file)
{
	struct cdk2_fat_directory_entry found;
	uint32_t cluster;
	uint64_t position, status;
	size_t length;

	if (directory == NULL || directory->volume == NULL || path == NULL ||
	    file == NULL || !directory->is_directory)
		return EFI_INVALID_PARAMETER;
	cluster = directory->directory_cluster;
	while (*path == '/' || *path == '\\')
		path++;
	if (*path == 0U) {
		*file = *directory; file->position = 0U;
		return EFI_SUCCESS;
	}
	for (;;) {
		for (length = 0U; path[length] != 0U && path[length] != '/' &&
		     path[length] != '\\'; length++)
			if (length == 255U)
				return EFI_INVALID_PARAMETER;
		if (length == 0U)
			return EFI_INVALID_PARAMETER;
		position = 0U;
		do {
			status = next_directory_entry(directory->volume, cluster, &position,
				&found);
			if (status != EFI_SUCCESS)
				return status;
		} while (!name_equal(found.name, path, length));
		path += length;
		while (*path == '/' || *path == '\\')
			path++;
		if (*path == 0U)
			break;
		if ((found.attributes & 0x10U) == 0U || found.first_cluster < 2U)
			return EFI_NOT_FOUND;
		cluster = found.first_cluster;
	}
	*file = (struct cdk2_fat_file) {
		.volume = directory->volume, .entry = found,
		.directory_cluster = found.first_cluster,
		.is_directory = (found.attributes & 0x10U) != 0U
	};
	return EFI_SUCCESS;
}

static size_t name_size(const uint16_t *name)
{
	size_t length = 0U;
	while (name[length] != 0U)
		length++;
	return (length + 1U) * sizeof(*name);
}

uint64_t cdk2_fat_file_get_info(const struct cdk2_fat_file *file,
	size_t *size, struct cdk2_fat_file_info *info)
{
	size_t needed;

	if (file == NULL || size == NULL)
		return EFI_INVALID_PARAMETER;
	needed = offsetof(struct cdk2_fat_file_info, name) +
		name_size(file->entry.name);
	if (info == NULL || *size < needed) {
		*size = needed;
		return EFI_BUFFER_TOO_SMALL;
	}
	*info = (struct cdk2_fat_file_info) {
		.size = file->entry.size, .physical_size = file->entry.size,
		.attributes = file->entry.attributes
	};
	__builtin_memcpy(info->name, file->entry.name, name_size(file->entry.name));
	*size = needed;
	return EFI_SUCCESS;
}

uint64_t cdk2_fat_file_read(struct cdk2_fat_file *file, size_t *size,
	void *buffer)
{
	uint64_t status;

	if (file == NULL || size == NULL || (*size != 0U && buffer == NULL))
		return EFI_INVALID_PARAMETER;
	if (file->is_directory) {
		struct cdk2_fat_directory_entry entry;
		struct cdk2_fat_file temporary;
		size_t needed;
		uint64_t position = file->position;
		status = next_directory_entry(file->volume, file->directory_cluster,
			&position, &entry);
		if (status == EFI_NOT_FOUND) {
			*size = 0U;
			return EFI_SUCCESS;
		}
		if (status != EFI_SUCCESS)
			return status;
		temporary = (struct cdk2_fat_file) { .volume = file->volume, .entry = entry };
		needed = *size;
		status = cdk2_fat_file_get_info(&temporary, &needed, buffer);
		*size = needed;
		if (status == EFI_SUCCESS)
			file->position = position;
		return status;
	}
	status = cdk2_fat_read_file(file->volume, file->entry.first_cluster,
		file->entry.size, file->position, size, buffer);
	if (status == EFI_SUCCESS)
		file->position += *size;
	return status;
}

uint64_t cdk2_fat_file_get_position(const struct cdk2_fat_file *file,
	uint64_t *position)
{
	if (file == NULL || position == NULL)
		return EFI_INVALID_PARAMETER;
	*position = file->position;
	return EFI_SUCCESS;
}

uint64_t cdk2_fat_file_set_position(struct cdk2_fat_file *file,
	uint64_t position)
{
	if (file == NULL)
		return EFI_INVALID_PARAMETER;
	if (file->is_directory && position != 0U)
		return EFI_UNSUPPORTED;
	file->position = position == UINT64_MAX && !file->is_directory ?
		file->entry.size : position;
	return EFI_SUCCESS;
}
