/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/fat.h>
#include <uefi.h>

#define FAT_VOLUME_CORRUPTED EFIERR(10)
#define FAT_ACCESS_DENIED EFIERR(15)
#define FAT_ALREADY_STARTED EFIERR(20)

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
		.fsinfo_sector = fat_type == CDK2_FAT32 ? read16(sector + 48U) : 0U,
		.sectors_per_cluster = sectors_per_cluster, .fat_count = fat_count,
		.fat_type = fat_type
	};
	return EFI_SUCCESS;
}

void cdk2_fat_set_write_ops(struct cdk2_fat_volume *volume,
	cdk2_fat_write_fn *write, cdk2_fat_flush_fn *flush)
{
	if (volume == NULL)
		return;
	volume->write = write;
	volume->flush = flush;
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

static uint64_t raw_fat_value(const struct cdk2_fat_volume *volume,
	uint32_t cluster, uint32_t *value)
{
	uint8_t data[4];
	uint64_t offset, status;
	size_t width;

	if (volume->fat_type == CDK2_FAT12) {
		offset = volume->fat_offset + cluster + cluster / 2U; width = 2U;
	} else if (volume->fat_type == CDK2_FAT16) {
		offset = volume->fat_offset + (uint64_t)cluster * 2U; width = 2U;
	} else {
		offset = volume->fat_offset + (uint64_t)cluster * 4U; width = 4U;
	}
	status = volume->read(volume->context, offset, width, data);
	if (status != EFI_SUCCESS)
		return status;
	*value = width == 2U ? read16(data) : read32(data);
	if (volume->fat_type == CDK2_FAT12)
		*value = (cluster & 1U) != 0U ? *value >> 4 : *value & 0xfffU;
	else if (volume->fat_type == CDK2_FAT32)
		*value &= 0x0fffffffU;
	return EFI_SUCCESS;
}

static uint32_t end_marker(const struct cdk2_fat_volume *volume)
{
	return volume->fat_type == CDK2_FAT12 ? 0xfffU :
		volume->fat_type == CDK2_FAT16 ? 0xffffU : 0x0fffffffU;
}

static uint64_t write_fat_value(struct cdk2_fat_volume *volume,
	uint32_t cluster, uint32_t value)
{
	uint8_t data[4];
	uint64_t base, offset, status;
	uint32_t mirror;
	size_t width;

	for (mirror = 0U; mirror < volume->fat_count; mirror++) {
		base = volume->fat_offset + (uint64_t)mirror * volume->fat_sectors *
			volume->bytes_per_sector;
		if (volume->fat_type == CDK2_FAT12) {
			offset = base + cluster + cluster / 2U; width = 2U;
			status = volume->read(volume->context, offset, width, data);
			if (status != EFI_SUCCESS)
				return status;
			if ((cluster & 1U) != 0U) {
				data[0] = (uint8_t)((data[0] & 0x0fU) | (value << 4));
				data[1] = (uint8_t)(value >> 4);
			} else {
				data[0] = (uint8_t)value;
				data[1] = (uint8_t)((data[1] & 0xf0U) | (value >> 8));
			}
		} else if (volume->fat_type == CDK2_FAT16) {
			offset = base + (uint64_t)cluster * 2U; width = 2U;
			data[0] = (uint8_t)value; data[1] = (uint8_t)(value >> 8);
		} else {
			offset = base + (uint64_t)cluster * 4U; width = 4U;
			status = volume->read(volume->context, offset, width, data);
			if (status != EFI_SUCCESS)
				return status;
			value &= 0x0fffffffU;
			data[0] = (uint8_t)value; data[1] = (uint8_t)(value >> 8);
			data[2] = (uint8_t)(value >> 16);
			data[3] = (uint8_t)((data[3] & 0xf0U) | (value >> 24));
		}
		status = volume->write(volume->context, offset, width, data);
		if (status != EFI_SUCCESS)
			return status;
	}
	return EFI_SUCCESS;
}

static uint64_t invalidate_fsinfo(struct cdk2_fat_volume *volume)
{
	uint8_t sector[4096];
	uint64_t offset, status;

	if (volume->fat_type != CDK2_FAT32 || volume->fsinfo_sector == 0U ||
	    volume->fsinfo_sector >= volume->total_sectors)
		return EFI_SUCCESS;
	offset = (uint64_t)volume->fsinfo_sector * volume->bytes_per_sector;
	status = volume->read(volume->context, offset, volume->bytes_per_sector, sector);
	if (status != EFI_SUCCESS)
		return status;
	if (read32(sector) != 0x41615252U || read32(sector + 484U) != 0x61417272U ||
	    read32(sector + 508U) != 0xaa550000U)
		return EFI_SUCCESS;
	sector[488U] = sector[489U] = sector[490U] = sector[491U] = 0xffU;
	sector[492U] = sector[493U] = sector[494U] = sector[495U] = 0xffU;
	return volume->write(volume->context, offset, volume->bytes_per_sector, sector);
}

static void rollback_changes(struct cdk2_fat_volume *volume,
	struct cdk2_fat_change *changes, size_t count)
{
	while (count != 0U) {
		count--;
		(void)write_fat_value(volume, changes[count].cluster,
			changes[count].old_value);
	}
	if (volume->flush != NULL)
		(void)volume->flush(volume->context);
}

uint64_t cdk2_fat_resize_chain(struct cdk2_fat_volume *volume,
	uint32_t *first_cluster, uint32_t old_size, uint32_t new_size,
	struct cdk2_fat_change *changes, size_t *change_count)
{
	uint64_t cluster_size, status;
	uint32_t old_count, new_count, cluster, next, value, last = 0U;
	uint32_t index, needed, candidate;
	size_t capacity, count = 0U;
	int end;

	if (volume == NULL || first_cluster == NULL || changes == NULL ||
	    change_count == NULL)
		return EFI_INVALID_PARAMETER;
	if (volume->media_changed)
		return CDK2_FAT_MEDIA_CHANGED;
	if (volume->read_only || volume->write_protected)
		return CDK2_FAT_WRITE_PROTECTED;
	if (volume->write == NULL)
		return EFI_UNSUPPORTED;
	cluster_size = (uint64_t)volume->bytes_per_sector *
		volume->sectors_per_cluster;
	old_count = old_size == 0U ? 0U : (uint32_t)((old_size + cluster_size - 1U) /
		cluster_size);
	new_count = new_size == 0U ? 0U : (uint32_t)((new_size + cluster_size - 1U) /
		cluster_size);
	capacity = *change_count; *change_count = 0U;
	if (old_count != 0U && (*first_cluster < 2U ||
	    *first_cluster >= volume->cluster_count + 2U))
		return FAT_VOLUME_CORRUPTED;
	cluster = *first_cluster;
	for (index = 0U; index < old_count; index++) {
		last = cluster;
		if (index + 1U == old_count)
			break;
		status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
		if (status != EFI_SUCCESS || end)
			return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
		cluster = next;
	}
	if (new_count > old_count) {
		needed = new_count - old_count;
		for (candidate = 2U; candidate < volume->cluster_count + 2U &&
		     needed != 0U; candidate++) {
			status = raw_fat_value(volume, candidate, &value);
			if (status != EFI_SUCCESS)
				return status;
			if (value != 0U)
				continue;
			if (count == capacity) {
				*change_count = count + needed;
				return EFI_BUFFER_TOO_SMALL;
			}
			changes[count++] = (struct cdk2_fat_change) { candidate, 0U };
			needed--;
		}
		if (needed != 0U)
			return EFI_VOLUME_FULL;
		if (old_count != 0U) {
			if (count == capacity) {
				*change_count = count + 1U;
				return EFI_BUFFER_TOO_SMALL;
			}
			status = raw_fat_value(volume, last, &value);
			if (status != EFI_SUCCESS)
				return status;
			changes[count++] = (struct cdk2_fat_change) { last, value };
		}
		for (index = 0U; index < new_count - old_count; index++) {
			next = index + 1U < new_count - old_count ?
				changes[index + 1U].cluster : end_marker(volume);
			status = write_fat_value(volume, changes[index].cluster, next);
			if (status != EFI_SUCCESS)
				goto rollback;
		}
		if (old_count != 0U) {
			status = write_fat_value(volume, last, changes[0].cluster);
			if (status != EFI_SUCCESS)
				goto rollback;
		} else {
			*first_cluster = changes[0].cluster;
		}
	} else if (new_count < old_count) {
		cluster = *first_cluster;
		for (index = 0U; index < old_count; index++) {
			status = raw_fat_value(volume, cluster, &value);
			if (status != EFI_SUCCESS)
				return status;
			if (index + 1U >= new_count) {
				if (count == capacity) {
					*change_count = count + old_count - index;
					return EFI_BUFFER_TOO_SMALL;
				}
				changes[count++] = (struct cdk2_fat_change) { cluster, value };
			}
			if (index + 1U == old_count)
				break;
			status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
			if (status != EFI_SUCCESS || end)
				return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
			cluster = next;
		}
		if (new_count != 0U)
			status = write_fat_value(volume, changes[0].cluster,
				end_marker(volume));
		else
			status = EFI_SUCCESS;
		for (index = new_count == 0U ? 0U : 1U;
		     status == EFI_SUCCESS && index < count; index++)
			status = write_fat_value(volume, changes[index].cluster, 0U);
		if (status != EFI_SUCCESS)
			goto rollback;
		if (new_count == 0U)
			*first_cluster = 0U;
	}
	status = invalidate_fsinfo(volume);
	if (status != EFI_SUCCESS)
		goto rollback;
	if (volume->flush != NULL) {
		status = volume->flush(volume->context);
		if (status != EFI_SUCCESS)
			goto rollback;
	}
	*change_count = count;
	return EFI_SUCCESS;
rollback:
	rollback_changes(volume, changes, count);
	*change_count = count;
	return status;
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

uint64_t cdk2_fat_write_file(struct cdk2_fat_volume *volume,
	uint32_t first_cluster, uint32_t file_size, uint64_t position,
	size_t *size, const void *buffer)
{
	const uint8_t *input = buffer;
	uint64_t cluster_size, offset, status;
	uint32_t cluster = first_cluster, next, steps = 0U;
	size_t wanted, part;
	int end;
	if (volume == NULL || size == NULL || (*size != 0U && buffer == NULL) ||
	    position > file_size || *size > (uint64_t)file_size - position)
		return EFI_INVALID_PARAMETER;
	if (volume->media_changed)
		return CDK2_FAT_MEDIA_CHANGED;
	if (volume->read_only || volume->write_protected)
		return CDK2_FAT_WRITE_PROTECTED;
	if (volume->write == NULL)
		return EFI_UNSUPPORTED;
	wanted = *size; *size = 0U;
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
		if (++steps >= volume->cluster_count)
			return FAT_VOLUME_CORRUPTED;
	}
	while (wanted != 0U) {
		status = cdk2_fat_cluster_offset(volume, cluster, &offset);
		if (status != EFI_SUCCESS)
			return status;
		part = (size_t)(cluster_size - position);
		if (part > wanted) part = wanted;
		status = volume->write(volume->context, offset + position, part, input);
		if (status != EFI_SUCCESS)
			return status;
		*size += part; input += part; wanted -= part; position = 0U;
		if (wanted == 0U) break;
		status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
		if (status != EFI_SUCCESS || end)
			return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
		cluster = next;
		if (++steps >= volume->cluster_count)
			return FAT_VOLUME_CORRUPTED;
	}
	return volume->flush == NULL ? EFI_SUCCESS : volume->flush(volume->context);
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
	uint64_t position, start = 0U, status;
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
			start = position;
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
		.parent_directory_cluster = cluster,
		.record_index = start, .record_count = (size_t)(position - start),
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

static int valid_short_character(uint16_t character)
{
	if (character < 0x21U || character > 0x7eU)
		return 0;
	return character != '"' && character != '*' && character != '+' &&
		character != ',' && character != '/' && character != ':' &&
		character != ';' && character != '<' && character != '=' &&
		character != '>' && character != '?' && character != '[' &&
		character != '\\' && character != ']' && character != '|';
}

static int short_name_exists(const struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, const uint8_t name[11])
{
	uint8_t record[32];
	uint64_t index = 0U, status;

	for (;;) {
		status = directory_record(volume, directory_cluster, index++, record);
		if (status != EFI_SUCCESS || record[0] == 0x00U)
			return 0;
		if (record[0] != 0xe5U && record[11U] != 0x0fU &&
		    __builtin_memcmp(record, name, 11U) == 0)
			return 1;
	}
}

uint64_t cdk2_fat_generate_short_name(const struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, const uint16_t *name, uint8_t short_name[11])
{
	uint8_t stem[8], extension[3];
	size_t stem_length = 0U, extension_length = 0U, index, dot = (size_t)-1;
	unsigned int suffix;

	if (volume == NULL || name == NULL || short_name == NULL || name[0] == 0U)
		return EFI_INVALID_PARAMETER;
	for (index = 0U; name[index] != 0U; index++) {
		if (index >= 255U || name[index] == '/' || name[index] == '\\')
			return EFI_INVALID_PARAMETER;
		if (name[index] == '.')
			dot = index;
	}
	for (index = 0U; name[index] != 0U; index++) {
		if (index == dot)
			continue;
		if (!valid_short_character(name[index]) || name[index] == '.')
			continue;
		if (dot != (size_t)-1 && index > dot) {
			if (extension_length < sizeof(extension))
				extension[extension_length++] = (uint8_t)fold(name[index]);
		} else if (stem_length < sizeof(stem)) {
			stem[stem_length++] = (uint8_t)fold(name[index]);
		}
	}
	if (stem_length == 0U)
		return EFI_INVALID_PARAMETER;
	for (suffix = 1U; suffix <= 999999U; suffix++) {
		unsigned int value = suffix, digits = 1U;
		size_t prefix;
		while (value >= 10U) {
			value /= 10U;
			digits++;
		}
		prefix = 8U - digits - 1U;
		if (prefix > stem_length)
			prefix = stem_length;
		__builtin_memset(short_name, ' ', 11U);
		__builtin_memcpy(short_name, stem, prefix);
		short_name[prefix] = '~'; value = suffix;
		for (index = 0U; index < digits; index++) {
			short_name[prefix + digits - index] = (uint8_t)('0' + value % 10U);
			value /= 10U;
		}
		__builtin_memcpy(short_name + 8U, extension, extension_length);
		if (!short_name_exists(volume, directory_cluster, short_name))
			return EFI_SUCCESS;
	}
	return EFI_VOLUME_FULL;
}

uint64_t cdk2_fat_build_directory_records(const uint16_t *name,
	const uint8_t short_name[11], uint8_t attributes, uint32_t first_cluster,
	uint32_t file_size, uint8_t *records, size_t *record_count)
{
	static const uint8_t positions[13] = {
		1U, 3U, 5U, 7U, 9U, 14U, 16U, 18U, 20U, 22U, 24U, 28U, 30U
	};
	size_t length = 0U, needed, ordinal, part, source;
	uint16_t character;
	uint8_t *record, checksum;

	if (name == NULL || short_name == NULL || record_count == NULL ||
	    (attributes & 0xc0U) != 0U)
		return EFI_INVALID_PARAMETER;
	while (name[length] != 0U) {
		if (length == 255U || name[length] == '/' || name[length] == '\\')
			return EFI_INVALID_PARAMETER;
		length++;
	}
	if (length == 0U)
		return EFI_INVALID_PARAMETER;
	needed = (length + 12U) / 13U + 1U;
	if (records == NULL || *record_count < needed) {
		*record_count = needed;
		return EFI_BUFFER_TOO_SMALL;
	}
	checksum = short_checksum(short_name);
	for (ordinal = needed - 1U; ordinal != 0U; ordinal--) {
		record = records + (needed - 1U - ordinal) * 32U;
		__builtin_memset(record, 0xff, 32U);
		record[0] = (uint8_t)ordinal;
		if (ordinal == needed - 1U)
			record[0] |= 0x40U;
		record[11U] = 0x0fU; record[12U] = 0U; record[13U] = checksum;
		record[26U] = record[27U] = 0U;
		for (part = 0U; part < 13U; part++) {
			source = (ordinal - 1U) * 13U + part;
			character = source < length ? name[source] : source == length ? 0U :
				0xffffU;
			record[positions[part]] = (uint8_t)character;
			record[positions[part] + 1U] = (uint8_t)(character >> 8);
		}
	}
	record = records + (needed - 1U) * 32U;
	__builtin_memset(record, 0, 32U);
	__builtin_memcpy(record, short_name, 11U); record[11U] = attributes;
	record[20U] = (uint8_t)(first_cluster >> 16);
	record[21U] = (uint8_t)(first_cluster >> 24);
	record[26U] = (uint8_t)first_cluster;
	record[27U] = (uint8_t)(first_cluster >> 8);
	record[28U] = (uint8_t)file_size;
	record[29U] = (uint8_t)(file_size >> 8);
	record[30U] = (uint8_t)(file_size >> 16);
	record[31U] = (uint8_t)(file_size >> 24);
	*record_count = needed;
	return EFI_SUCCESS;
}

static uint64_t directory_record_offset(const struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t index, uint64_t *offset)
{
	uint64_t cluster_size, status;
	uint32_t cluster, next, steps = 0U;
	int end;

	if (directory_cluster == 0U && volume->fat_type != CDK2_FAT32) {
		if (index >= volume->root_entries)
			return EFI_NOT_FOUND;
		*offset = volume->root_offset + index * 32U;
		return EFI_SUCCESS;
	}
	cluster = directory_cluster == 0U ? volume->root_cluster : directory_cluster;
	cluster_size = (uint64_t)volume->bytes_per_sector *
		volume->sectors_per_cluster;
	if (cluster_size < 32U)
		return FAT_VOLUME_CORRUPTED;
	while (index >= cluster_size / 32U) {
		status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
		if (status != EFI_SUCCESS || end)
			return status == EFI_SUCCESS ? EFI_NOT_FOUND : status;
		cluster = next; index -= cluster_size / 32U;
		if (++steps >= volume->cluster_count)
			return FAT_VOLUME_CORRUPTED;
	}
	status = cdk2_fat_cluster_offset(volume, cluster, offset);
	if (status == EFI_SUCCESS)
		*offset += index * 32U;
	return status;
}

uint64_t cdk2_fat_place_directory_records(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, const uint8_t *records, size_t record_count,
	uint64_t *record_index, uint8_t *rollback_records, size_t *rollback_count)
{
	uint8_t record[32];
	uint64_t index = 0U, start = 0U, offset, status;
	struct cdk2_fat_change growth[2];
	uint32_t first, cluster, next, clusters = 1U;
	size_t growth_count = 2U, slots, zero;
	int end, grew = 0;
	size_t free_count = 0U, written;

	if (volume == NULL || records == NULL || record_count == 0U ||
	    record_index == NULL || rollback_records == NULL || rollback_count == NULL)
		return EFI_INVALID_PARAMETER;
	if (volume->media_changed)
		return CDK2_FAT_MEDIA_CHANGED;
	if (volume->read_only || volume->write_protected)
		return CDK2_FAT_WRITE_PROTECTED;
	if (volume->write == NULL)
		return EFI_UNSUPPORTED;
	if (*rollback_count < record_count) {
		*rollback_count = record_count;
		return EFI_BUFFER_TOO_SMALL;
	}
	for (;;) {
		status = directory_record(volume, directory_cluster, index, record);
		if (status == EFI_NOT_FOUND && !grew &&
		    !(directory_cluster == 0U && volume->fat_type != CDK2_FAT32)) {
			first = directory_cluster == 0U ? volume->root_cluster :
				directory_cluster;
			cluster = first;
			while (1) {
				status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
				if (status != EFI_SUCCESS) return status;
				if (end) break;
				cluster = next;
				if (++clusters >= volume->cluster_count)
					return FAT_VOLUME_CORRUPTED;
			}
			status = cdk2_fat_resize_chain(volume, &first,
				clusters * volume->bytes_per_sector * volume->sectors_per_cluster,
				(clusters + 1U) * volume->bytes_per_sector *
				volume->sectors_per_cluster, growth, &growth_count);
			if (status != EFI_SUCCESS) return status;
			status = cdk2_fat_next_cluster(volume, cluster, &next, &end);
			if (status != EFI_SUCCESS || end) {
				rollback_changes(volume, growth, growth_count);
				return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
			}
			status = cdk2_fat_cluster_offset(volume, next, &offset);
			slots = (size_t)volume->bytes_per_sector *
				volume->sectors_per_cluster / 32U;
			__builtin_memset(record, 0, sizeof(record));
			for (zero = 0U; status == EFI_SUCCESS && zero < slots; zero++)
				status = volume->write(volume->context, offset + zero * 32U,
					32U, record);
			if (status != EFI_SUCCESS) {
				rollback_changes(volume, growth, growth_count); return status;
			}
			grew = 1; continue;
		}
		if (status != EFI_SUCCESS)
			return status == EFI_NOT_FOUND ? EFI_VOLUME_FULL : status;
		if (record[0] == 0xe5U || record[0] == 0x00U) {
			if (free_count++ == 0U)
				start = index;
			if (free_count == record_count)
				break;
		} else {
			free_count = 0U;
		}
		index++;
	}
	for (written = 0U; written < record_count; written++) {
		status = directory_record_offset(volume, directory_cluster,
			start + written, &offset);
		if (status != EFI_SUCCESS)
			goto rollback;
		status = volume->read(volume->context, offset, 32U,
			rollback_records + written * 32U);
		if (status != EFI_SUCCESS)
			goto rollback;
		status = volume->write(volume->context, offset, 32U,
			records + written * 32U);
		if (status != EFI_SUCCESS)
			goto rollback;
	}
	if (volume->flush != NULL) {
		status = volume->flush(volume->context);
		if (status != EFI_SUCCESS)
			goto rollback;
	}
	*record_index = start; *rollback_count = record_count;
	return EFI_SUCCESS;
rollback:
	while (written != 0U) {
		written--;
		if (directory_record_offset(volume, directory_cluster,
		    start + written, &offset) == EFI_SUCCESS)
			(void)volume->write(volume->context, offset, 32U,
				rollback_records + written * 32U);
	}
	if (volume->flush != NULL)
		(void)volume->flush(volume->context);
	if (grew)
		rollback_changes(volume, growth, growth_count);
	return status;
}

static uint64_t snapshot_records(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t index, size_t count, uint8_t *records)
{
	uint64_t offset, status;
	size_t item;
	for (item = 0U; item < count; item++) {
		status = directory_record_offset(volume, directory_cluster, index + item,
			&offset);
		if (status != EFI_SUCCESS)
			return status;
		status = volume->read(volume->context, offset, 32U, records + item * 32U);
		if (status != EFI_SUCCESS)
			return status;
	}
	return EFI_SUCCESS;
}

static uint64_t write_records(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t index, const uint8_t *records,
	size_t count)
{
	uint64_t offset, status = EFI_SUCCESS;
	size_t written = 0U;
	for (; written < count; written++) {
		status = directory_record_offset(volume, directory_cluster,
			index + written, &offset);
		if (status != EFI_SUCCESS)
			break;
		status = volume->write(volume->context, offset, 32U,
			records + written * 32U);
		if (status != EFI_SUCCESS)
			break;
	}
	if (status == EFI_SUCCESS && volume->flush != NULL)
		status = volume->flush(volume->context);
	return status;
}

static uint64_t update_short_record(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t record_index, size_t record_count,
	uint32_t first_cluster, uint32_t size, uint8_t old[32])
{
	uint8_t record[32];
	uint64_t offset, status;
	if (record_count == 0U)
		return EFI_INVALID_PARAMETER;
	status = directory_record_offset(volume, directory_cluster,
		record_index + record_count - 1U, &offset);
	if (status != EFI_SUCCESS)
		return status;
	status = volume->read(volume->context, offset, 32U, record);
	if (status != EFI_SUCCESS || record[11U] == 0x0fU)
		return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
	__builtin_memcpy(old, record, 32U);
	record[20U] = (uint8_t)(first_cluster >> 16);
	record[21U] = (uint8_t)(first_cluster >> 24);
	record[26U] = (uint8_t)first_cluster;
	record[27U] = (uint8_t)(first_cluster >> 8);
	record[28U] = (uint8_t)size; record[29U] = (uint8_t)(size >> 8);
	record[30U] = (uint8_t)(size >> 16); record[31U] = (uint8_t)(size >> 24);
	return write_records(volume, directory_cluster,
		record_index + record_count - 1U, record, 1U);
}

uint64_t cdk2_fat_resize_file(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t record_index, size_t record_count,
	uint32_t *first_cluster, uint32_t old_size, uint32_t new_size,
	struct cdk2_fat_change *changes, size_t *change_count)
{
	uint8_t old[32];
	uint32_t original;
	uint64_t status;
	size_t changed;
	if (first_cluster == NULL || change_count == NULL)
		return EFI_INVALID_PARAMETER;
	original = *first_cluster;
	status = cdk2_fat_resize_chain(volume, first_cluster, old_size, new_size,
		changes, change_count);
	if (status != EFI_SUCCESS)
		return status;
	changed = *change_count;
	status = update_short_record(volume, directory_cluster, record_index,
		record_count, *first_cluster, new_size, old);
	if (status != EFI_SUCCESS) {
		(void)write_records(volume, directory_cluster,
			record_index + record_count - 1U, old, 1U);
		rollback_changes(volume, changes, changed);
		*first_cluster = original;
	}
	return status;
}

static uint64_t directory_empty(const struct cdk2_fat_volume *volume,
	uint32_t cluster)
{
	struct cdk2_fat_directory_entry entry;
	uint64_t position = 0U, status;
	for (;;) {
		status = next_directory_entry(volume, cluster, &position, &entry);
		if (status == EFI_NOT_FOUND)
			return EFI_SUCCESS;
		if (status != EFI_SUCCESS)
			return status;
		if (!((entry.name[0] == '.' && entry.name[1] == 0U) ||
		    (entry.name[0] == '.' && entry.name[1] == '.' &&
		     entry.name[2] == 0U)))
			return FAT_ACCESS_DENIED;
	}
}

uint64_t cdk2_fat_delete_entry(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t record_index, size_t record_count,
	uint32_t *first_cluster, uint32_t old_size, int is_directory,
	struct cdk2_fat_change *changes, size_t *change_count)
{
	uint8_t old[32U * 21U], deleted[32U * 21U];
	uint32_t original;
	uint64_t status;
	size_t item, changed;
	if (volume == NULL || first_cluster == NULL || record_count == 0U ||
	    record_count > 21U || changes == NULL || change_count == NULL)
		return EFI_INVALID_PARAMETER;
	if (is_directory && *first_cluster >= 2U) {
		status = directory_empty(volume, *first_cluster);
		if (status != EFI_SUCCESS)
			return status;
	}
	status = snapshot_records(volume, directory_cluster, record_index,
		record_count, old);
	if (status != EFI_SUCCESS)
		return status;
	__builtin_memcpy(deleted, old, record_count * 32U);
	for (item = 0U; item < record_count; item++) deleted[item * 32U] = 0xe5U;
	original = *first_cluster;
	status = cdk2_fat_resize_chain(volume, first_cluster, old_size, 0U,
		changes, change_count);
	if (status != EFI_SUCCESS)
		return status;
	changed = *change_count;
	status = write_records(volume, directory_cluster, record_index, deleted,
		record_count);
	if (status != EFI_SUCCESS) {
		(void)write_records(volume, directory_cluster, record_index, old,
			record_count);
		rollback_changes(volume, changes, changed); *first_cluster = original;
	}
	return status;
}

uint64_t cdk2_fat_rename_entry(struct cdk2_fat_volume *volume,
	uint32_t directory_cluster, uint64_t old_index, size_t old_count,
	const uint16_t *new_name, uint8_t attributes, uint32_t first_cluster,
	uint32_t file_size, uint64_t *new_index)
{
	uint8_t short_name[11], records[32U * 21U], placed_old[32U * 21U];
	uint8_t old[32U * 21U], deleted[32U * 21U];
	struct cdk2_fat_file directory, collision;
	uint64_t status;
	size_t count = 21U, rollback_count = 21U, item;
	if (volume == NULL || new_name == NULL || new_index == NULL ||
	    old_count == 0U || old_count > 21U)
		return EFI_INVALID_PARAMETER;
	directory = (struct cdk2_fat_file) { .volume = volume,
		.directory_cluster = directory_cluster, .is_directory = 1U };
	status = cdk2_fat_open(&directory, new_name, &collision);
	if (status == EFI_SUCCESS)
		return FAT_ALREADY_STARTED;
	if (status != EFI_NOT_FOUND)
		return status;
	status = cdk2_fat_generate_short_name(volume, directory_cluster, new_name,
		short_name);
	if (status != EFI_SUCCESS)
		return status;
	status = cdk2_fat_build_directory_records(new_name, short_name, attributes,
		first_cluster, file_size, records, &count);
	if (status != EFI_SUCCESS)
		return status;
	status = snapshot_records(volume, directory_cluster, old_index, old_count, old);
	if (status != EFI_SUCCESS)
		return status;
	status = cdk2_fat_place_directory_records(volume, directory_cluster, records,
		count, new_index, placed_old, &rollback_count);
	if (status != EFI_SUCCESS)
		return status;
	__builtin_memcpy(deleted, old, old_count * 32U);
	for (item = 0U; item < old_count; item++) deleted[item * 32U] = 0xe5U;
	status = write_records(volume, directory_cluster, old_index, deleted, old_count);
	if (status != EFI_SUCCESS) {
		(void)write_records(volume, directory_cluster, old_index, old, old_count);
		(void)write_records(volume, directory_cluster, *new_index, placed_old, count);
	}
	return status;
}

uint64_t cdk2_fat_file_resize(struct cdk2_fat_file *file, uint32_t new_size,
	struct cdk2_fat_change *changes, size_t *change_count)
{
	uint64_t status;
	if (file == NULL || file->volume == NULL || file->is_root ||
	    file->is_directory)
		return EFI_INVALID_PARAMETER;
	status = cdk2_fat_resize_file((struct cdk2_fat_volume *)file->volume,
		file->parent_directory_cluster, file->record_index, file->record_count,
		&file->entry.first_cluster, file->entry.size, new_size, changes,
		change_count);
	if (status == EFI_SUCCESS) {
		file->entry.size = new_size;
		if (file->position > new_size)
			file->position = new_size;
	}
	return status;
}

uint64_t cdk2_fat_file_delete(struct cdk2_fat_file *file,
	struct cdk2_fat_change *changes, size_t *change_count)
{
	uint64_t status;
	uint32_t allocation_size;
	if (file == NULL || file->volume == NULL || file->is_root)
		return EFI_INVALID_PARAMETER;
	allocation_size = file->is_directory && file->entry.first_cluster >= 2U ?
		(uint32_t)file->volume->bytes_per_sector *
		file->volume->sectors_per_cluster : file->entry.size;
	status = cdk2_fat_delete_entry((struct cdk2_fat_volume *)file->volume,
		file->parent_directory_cluster, file->record_index, file->record_count,
		&file->entry.first_cluster, allocation_size, file->is_directory, changes,
		change_count);
	if (status == EFI_SUCCESS) {
		file->entry.size = 0U; file->position = 0U;
	}
	return status;
}

uint64_t cdk2_fat_get_volume_info(const struct cdk2_fat_volume *volume,
	struct cdk2_fat_volume_info *info)
{
	uint8_t record[32];
	uint32_t cluster, value, free_clusters = 0U;
	uint64_t cluster_size, index = 0U, status;
	size_t source, output;
	if (volume == NULL || info == NULL)
		return EFI_INVALID_PARAMETER;
	cluster_size = (uint64_t)volume->bytes_per_sector *
		volume->sectors_per_cluster;
	if (cluster_size == 0U || volume->cluster_count > UINT64_MAX / cluster_size)
		return FAT_VOLUME_CORRUPTED;
	for (cluster = 2U; cluster < volume->cluster_count + 2U; cluster++) {
		status = raw_fat_value(volume, cluster, &value);
		if (status != EFI_SUCCESS) return status;
		if (value == 0U) free_clusters++;
	}
	*info = (struct cdk2_fat_volume_info) {
		.volume_size = cluster_size * volume->cluster_count,
		.free_space = cluster_size * free_clusters,
		.block_size = (uint32_t)cluster_size,
		.read_only = volume->read_only || volume->write_protected
	};
	for (;;) {
		status = directory_record(volume, volume->fat_type == CDK2_FAT32 ?
			volume->root_cluster : 0U, index++, record);
		if (status == EFI_NOT_FOUND) break;
		if (status != EFI_SUCCESS) return status;
		if (record[0] == 0U) break;
		if (record[0] == 0xe5U || record[11U] != 0x08U) continue;
		for (source = output = 0U; source < 11U; source++)
			if (record[source] != ' ') info->label[output++] = record[source];
		info->label[output] = 0U; break;
	}
	return EFI_SUCCESS;
}

uint64_t cdk2_fat_update_metadata(struct cdk2_fat_file *file,
	uint8_t attributes, uint16_t creation_date, uint16_t creation_time,
	uint16_t write_date, uint16_t write_time)
{
	uint8_t record[32], old[32];
	uint64_t offset, status;
	if (file == NULL || file->volume == NULL || file->is_root ||
	    file->record_count == 0U || (attributes & ~0x37U) != 0U ||
	    ((attributes & 0x10U) != 0U) != file->is_directory ||
	    !valid_fat_datetime(creation_date, creation_time) ||
	    !valid_fat_datetime(write_date, write_time))
		return EFI_INVALID_PARAMETER;
	if (file->volume->read_only || file->volume->write_protected)
		return CDK2_FAT_WRITE_PROTECTED;
	if (file->volume->write == NULL)
		return EFI_UNSUPPORTED;
	status = directory_record_offset(file->volume,
		file->parent_directory_cluster,
		file->record_index + file->record_count - 1U, &offset);
	if (status != EFI_SUCCESS) return status;
	status = file->volume->read(file->volume->context, offset, 32U, record);
	if (status != EFI_SUCCESS || record[11U] == 0x0fU)
		return status == EFI_SUCCESS ? FAT_VOLUME_CORRUPTED : status;
	__builtin_memcpy(old, record, sizeof(old));
	record[11U] = attributes; record[14U] = (uint8_t)creation_time;
	record[15U] = (uint8_t)(creation_time >> 8);
	record[16U] = (uint8_t)creation_date;
	record[17U] = (uint8_t)(creation_date >> 8);
	record[22U] = (uint8_t)write_time; record[23U] = (uint8_t)(write_time >> 8);
	record[24U] = (uint8_t)write_date; record[25U] = (uint8_t)(write_date >> 8);
	status = ((struct cdk2_fat_volume *)file->volume)->write(
		file->volume->context, offset, 32U, record);
	if (status == EFI_SUCCESS && file->volume->flush != NULL)
		status = file->volume->flush(file->volume->context);
	if (status != EFI_SUCCESS) {
		(void)((struct cdk2_fat_volume *)file->volume)->write(
			file->volume->context, offset, 32U, old);
		if (file->volume->flush != NULL)
			(void)file->volume->flush(file->volume->context);
		return status;
	}
	file->entry.attributes = attributes;
	file->entry.creation_date = creation_date;
	file->entry.creation_time = creation_time;
	file->entry.write_date = write_date; file->entry.write_time = write_time;
	return EFI_SUCCESS;
}
