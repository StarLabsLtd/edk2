/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#define GPT_HEADER_SIZE 92U
#define GPT_ENTRY_MIN_SIZE 128U
#define MBR_TABLE_OFFSET 446U
#define MBR_ENTRY_SIZE 16U
#define MBR_ENTRY_COUNT 4U
#define MBR_CHAIN_LIMIT 128U
#define ISO_SECTOR_SIZE 2048U
#define ISO_DESCRIPTOR_START 16U
#define ISO_DESCRIPTOR_LIMIT 64U
#define UDF_ANCHOR_TAG 2U
#define UDF_PARTITION_TAG 5U
#define UDF_LOGICAL_VOLUME_TAG 6U
#define UDF_TERMINATING_TAG 8U
#define UDF_FILE_SET_TAG 256U
#define UDF_SEQUENCE_LIMIT 256U

static const EFI_GUID blank_guid;

static UINT32 read32(const UINT8 *bytes)
{
	return (UINT32)bytes[0] | (UINT32)bytes[1] << 8 |
		(UINT32)bytes[2] << 16 | (UINT32)bytes[3] << 24;
}

static UINT64 read64(const UINT8 *bytes)
{
	return (UINT64)read32(bytes) | (UINT64)read32(bytes + 4) << 32;
}

static BOOLEAN zero_guid(const UINT8 *guid)
{
	UINTN index;

	for (index = 0; index < sizeof(EFI_GUID); index++)
		if (guid[index] != 0)
			return FALSE;
	return TRUE;
}

static void copy(void *destination, const void *source, UINTN size)
{
	UINT8 *out = destination;
	const UINT8 *in = source;

	while (size-- != 0)
		*out++ = *in++;
}

static BOOLEAN bytes_equal(const UINT8 *left, const UINT8 *right, UINTN size)
{
	while (size-- != 0)
		if (*left++ != *right++)
			return FALSE;
	return TRUE;
}

UINT32 cdk2_partition_crc32(const void *buffer, UINTN size)
{
	const UINT8 *bytes = buffer;
	UINT32 crc = MAX_UINT32;
	UINTN index;
	UINTN bit;

	for (index = 0; index < size; index++) {
		crc ^= bytes[index];
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
	}
	return ~crc;
}

static BOOLEAN media_valid(const struct cdk2_partition_media *media)
{
	return media != NULL && media->read != NULL && media->block_size >= 512U &&
		media->block_size <= MAX_UINT16 && media->last_block >= 2U;
}

static BOOLEAN extended_type(UINT8 type)
{
	return type == 0x05U || type == 0x0fU || type == 0x85U;
}

static EFI_STATUS validate_header(UINT8 *header, UINT32 block_size,
	UINT64 last_block, UINT64 header_lba, UINT32 *entry_count, UINT32 *entry_size,
	UINT64 *entry_lba, UINT64 *first_usable, UINT64 *last_usable)
{
	UINT32 header_size;
	UINT32 expected_crc;
	UINT32 actual_crc;

	if (read64(header) != 0x5452415020494645ULL || read32(header + 8) != 0x00010000U)
		return EFI_NOT_FOUND;
	header_size = read32(header + 12);
	if (header_size < GPT_HEADER_SIZE || header_size > block_size ||
	    read32(header + 20) != 0 || read64(header + 24) != header_lba)
		return EFI_COMPROMISED_DATA;
	expected_crc = read32(header + 16);
	header[16] = 0;
	header[17] = 0;
	header[18] = 0;
	header[19] = 0;
	actual_crc = cdk2_partition_crc32(header, header_size);
	header[16] = (UINT8)expected_crc;
	header[17] = (UINT8)(expected_crc >> 8);
	header[18] = (UINT8)(expected_crc >> 16);
	header[19] = (UINT8)(expected_crc >> 24);
	if (actual_crc != expected_crc)
		return EFI_CRC_ERROR;
	if (read64(header + 32) > last_block || read64(header + 32) == header_lba)
		return EFI_COMPROMISED_DATA;
	*first_usable = read64(header + 40);
	*last_usable = read64(header + 48);
	*entry_lba = read64(header + 72);
	*entry_count = read32(header + 80);
	*entry_size = read32(header + 84);
	if (*first_usable < 2U || *first_usable > *last_usable ||
	    *last_usable >= last_block || *entry_lba < 2U ||
	    *entry_count == 0 || *entry_size < GPT_ENTRY_MIN_SIZE ||
	    (*entry_size & 7U) != 0)
		return EFI_COMPROMISED_DATA;
	return EFI_SUCCESS;
}

static EFI_STATUS validate_entry_range(const struct cdk2_partition *partitions,
	UINTN count, UINT64 start, UINT64 end, UINT64 first_usable,
	UINT64 last_usable)
{
	UINTN index;

	if (start < first_usable || end > last_usable || start > end)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < count; index++)
		if (start <= partitions[index].end_lba &&
		    end >= partitions[index].start_lba)
			return EFI_COMPROMISED_DATA;
	return EFI_SUCCESS;
}

static EFI_STATUS parse_gpt_at(const struct cdk2_partition_media *media,
	void *header_block, UINTN header_capacity, void *entry_buffer,
	UINTN entry_capacity, struct cdk2_partition *partitions,
	UINTN partition_capacity, UINTN *partition_count, UINT64 header_lba)
{
	UINT8 *header = header_block;
	UINT8 *entries = entry_buffer;
	UINT64 entry_lba;
	UINT64 first_usable;
	UINT64 last_usable;
	UINT64 entry_bytes;
	UINT64 entry_blocks;
	UINT32 entry_count;
	UINT32 entry_size;
	UINT32 expected_crc;
	UINTN found = 0;
	UINTN index;
	EFI_STATUS status;

	if (!media_valid(media) || header == NULL || entries == NULL ||
	    partitions == NULL || partition_count == NULL ||
	    header_capacity < media->block_size)
		return EFI_INVALID_PARAMETER;
	*partition_count = 0;
	status = media->read(media->context, header_lba, 1U, header);
	if (EFI_ERROR(status))
		return status;
	status = validate_header(header, media->block_size, media->last_block, header_lba,
		&entry_count, &entry_size, &entry_lba, &first_usable, &last_usable);
	if (EFI_ERROR(status))
		return status;
	if (entry_count > MAX_UINTN / entry_size)
		return EFI_OUT_OF_RESOURCES;
	entry_bytes = (UINT64)entry_count * entry_size;
	entry_blocks = (entry_bytes + media->block_size - 1U) / media->block_size;
	if (entry_blocks > MAX_UINTN ||
	    entry_blocks > MAX_UINTN / media->block_size ||
	    entry_blocks * media->block_size > entry_capacity ||
	    entry_lba > media->last_block ||
	    entry_blocks > media->last_block - entry_lba + 1U)
		return EFI_BAD_BUFFER_SIZE;
	if (entry_lba + entry_blocks - 1U >= first_usable && entry_lba <= last_usable)
		return EFI_COMPROMISED_DATA;
	if ((header_lba >= first_usable && header_lba <= last_usable) ||
	    (read64(header + 32) >= first_usable && read64(header + 32) <= last_usable) ||
	    (header_lba >= entry_lba && header_lba < entry_lba + entry_blocks) ||
	    (read64(header + 32) >= entry_lba &&
	     read64(header + 32) < entry_lba + entry_blocks))
		return EFI_COMPROMISED_DATA;
	status = media->read(media->context, entry_lba, (UINTN)entry_blocks, entries);
	if (EFI_ERROR(status))
		return status;
	expected_crc = read32(header + 88);
	if (cdk2_partition_crc32(entries, (UINTN)entry_bytes) != expected_crc)
		return EFI_CRC_ERROR;
	for (index = 0; index < entry_count; index++) {
		const UINT8 *entry = entries + index * entry_size;
		struct cdk2_partition *partition;
		UINTN character;

		if (zero_guid(entry))
			continue;
		if (found == partition_capacity)
			return EFI_BUFFER_TOO_SMALL;
		status = validate_entry_range(partitions, found, read64(entry + 32),
			read64(entry + 40), first_usable, last_usable);
		if (EFI_ERROR(status))
			return status;
		partition = &partitions[found];
		partition->scheme = CDK2_PARTITION_GPT;
		partition->start_lba = read64(entry + 32);
		partition->end_lba = read64(entry + 40);
		partition->attributes = read64(entry + 48);
		copy(&partition->type_guid, entry, sizeof(partition->type_guid));
		copy(&partition->unique_guid, entry + 16, sizeof(partition->unique_guid));
		for (character = 0; character < CDK2_GPT_NAME_CHARS; character++)
			partition->name[character] = (CHAR16)
				((UINT16)entry[56 + character * 2] |
				 (UINT16)entry[57 + character * 2] << 8);
		partition->index = (UINT32)index + 1U;
		partition->disk_signature = 0;
		partition->boot_entry = 0;
		partition->mbr_type = 0;
		__builtin_memset(partition->mbr_record, 0,
			sizeof(partition->mbr_record));
		found++;
	}
	*partition_count = found;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_partition_parse_gpt(const struct cdk2_partition_media *media,
	void *header_block, UINTN header_capacity, void *entry_buffer,
	UINTN entry_capacity, struct cdk2_partition *partitions,
	UINTN partition_capacity, UINTN *partition_count)
{
	EFI_STATUS primary;
	EFI_STATUS backup;

	if (!media_valid(media))
		return EFI_INVALID_PARAMETER;
	primary = parse_gpt_at(media, header_block, header_capacity, entry_buffer,
		entry_capacity, partitions, partition_capacity, partition_count, 1U);
	if (!EFI_ERROR(primary))
		return primary;
	backup = parse_gpt_at(media, header_block, header_capacity, entry_buffer,
		entry_capacity, partitions, partition_capacity, partition_count,
		media->last_block);
	if (!EFI_ERROR(backup))
		return backup;
	return primary;
}

static EFI_STATUS add_mbr_partition(struct cdk2_partition *partitions,
	UINTN capacity, UINTN *count, UINT64 start, UINT32 blocks, UINT8 type,
	UINT32 signature, UINT32 index, UINT64 last_block, const UINT8 *record)
{
	struct cdk2_partition *partition;
	UINTN character;
	EFI_STATUS status;

	if (blocks == 0 || start > last_block || blocks - 1U > last_block - start)
		return EFI_COMPROMISED_DATA;
	if (*count == capacity)
		return EFI_BUFFER_TOO_SMALL;
	status = validate_entry_range(partitions, *count, start,
		start + blocks - 1U, 1U, last_block);
	if (EFI_ERROR(status))
		return status;
	partition = &partitions[*count];
	partition->scheme = CDK2_PARTITION_MBR;
	partition->start_lba = start;
	partition->end_lba = start + blocks - 1U;
	partition->attributes = 0;
	partition->type_guid = blank_guid;
	partition->unique_guid = blank_guid;
	for (character = 0; character < CDK2_GPT_NAME_CHARS; character++)
		partition->name[character] = 0;
	partition->index = index;
	partition->disk_signature = signature;
	partition->boot_entry = 0;
	partition->mbr_type = type;
	copy(partition->mbr_record, record, sizeof(partition->mbr_record));
	(*count)++;
	return EFI_SUCCESS;
}

static EFI_STATUS read_iso_sector(const struct cdk2_partition_media *media,
	UINT32 sector, UINT8 *buffer)
{
	UINTN blocks;
	UINT64 lba;

	if (media->block_size > ISO_SECTOR_SIZE ||
	    ISO_SECTOR_SIZE % media->block_size != 0)
		return EFI_UNSUPPORTED;
	blocks = ISO_SECTOR_SIZE / media->block_size;
	lba = (UINT64)sector * blocks;
	if (lba > media->last_block || blocks - 1U > media->last_block - lba)
		return EFI_COMPROMISED_DATA;
	return media->read(media->context, lba, blocks, buffer);
}

static BOOLEAN catalog_checksum_valid(const UINT8 *entry)
{
	UINT32 sum = 0;
	UINTN index;

	for (index = 0; index < 32U; index += 2U)
		sum += (UINT16)entry[index] | (UINT16)entry[index + 1U] << 8;
	return (UINT16)sum == 0;
}

static EFI_STATUS add_boot_entry(const struct cdk2_partition_media *media,
	const UINT8 *entry, UINT32 boot_entry,
	struct cdk2_partition *partitions, UINTN capacity, UINTN *count)
{
	struct cdk2_partition *partition;
	UINT64 start;
	UINT64 byte_size;
	UINT64 blocks;
	UINT32 sectors;
	UINTN character;

	if (entry[0] == 0)
		return EFI_SUCCESS;
	if (entry[0] != 0x88U || entry[1] > 4U || read32(entry + 8) == 0 ||
	    ((UINT16)entry[6] | (UINT16)entry[7] << 8) == 0)
		return EFI_COMPROMISED_DATA;
	start = (UINT64)read32(entry + 8) * ISO_SECTOR_SIZE / media->block_size;
	sectors = (UINT16)entry[6] | (UINT16)entry[7] << 8;
	if (entry[1] == 1U)
		sectors = 2400U;
	else if (entry[1] == 2U)
		sectors = 2880U;
	else if (entry[1] == 3U)
		sectors = 5760U;
	byte_size = sectors * 512ULL;
	blocks = (byte_size + media->block_size - 1U) / media->block_size;
	if (start > media->last_block || blocks == 0 ||
	    blocks - 1U > media->last_block - start)
		return EFI_COMPROMISED_DATA;
	if (*count == capacity)
		return EFI_BUFFER_TOO_SMALL;
	if (EFI_ERROR(validate_entry_range(partitions, *count, start,
		start + blocks - 1U, 0, media->last_block)))
		return EFI_COMPROMISED_DATA;
	partition = &partitions[*count];
	partition->scheme = CDK2_PARTITION_EL_TORITO;
	partition->start_lba = start;
	partition->end_lba = start + blocks - 1U;
	partition->attributes = entry[1];
	partition->type_guid = blank_guid;
	partition->unique_guid = blank_guid;
	for (character = 0; character < CDK2_GPT_NAME_CHARS; character++)
		partition->name[character] = 0;
	partition->index = boot_entry + 1U;
	partition->disk_signature = 0;
	partition->boot_entry = boot_entry;
	partition->mbr_type = entry[4];
	copy(partition->mbr_record, entry, sizeof(partition->mbr_record));
	(*count)++;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_partition_parse_el_torito(
	const struct cdk2_partition_media *media, void *sector_buffer,
	UINTN sector_capacity, struct cdk2_partition *partitions,
	UINTN partition_capacity, UINTN *partition_count)
{
	UINT8 *sector = sector_buffer;
	UINT32 catalog_lba = 0;
	UINT32 descriptor;
	UINT32 boot_entry = 0;
	UINTN count = 0;
	UINT32 record;
	UINT8 entry[32];
	BOOLEAN saw_iso = FALSE;
	EFI_STATUS status;

	if (!media_valid(media) || sector == NULL || partitions == NULL ||
	    partition_count == NULL || sector_capacity < ISO_SECTOR_SIZE)
		return EFI_INVALID_PARAMETER;
	*partition_count = 0;
	for (descriptor = ISO_DESCRIPTOR_START;
	     descriptor < ISO_DESCRIPTOR_LIMIT; descriptor++) {
		status = read_iso_sector(media, descriptor, sector);
		if (EFI_ERROR(status))
			return status;
		if (sector[0] == 255U)
			break;
		if (!bytes_equal(sector + 1, (const UINT8 *)"CD001", 5) ||
		    sector[6] != 1U)
			return saw_iso ? EFI_COMPROMISED_DATA : EFI_NOT_FOUND;
		saw_iso = TRUE;
		if (sector[0] == 0 &&
		    bytes_equal(sector + 7,
			    (const UINT8 *)"EL TORITO SPECIFICATION", 23)) {
			catalog_lba = read32(sector + 71);
			break;
		}
	}
	if (catalog_lba == 0)
		return EFI_NOT_FOUND;
	status = read_iso_sector(media, catalog_lba, sector);
	if (EFI_ERROR(status))
		return status;
	if (sector[0] != 1U ||
	    (sector[1] > 2U && sector[1] != 0xefU) ||
	    sector[30] != 0x55U || sector[31] != 0xaaU ||
	    !catalog_checksum_valid(sector))
		return EFI_COMPROMISED_DATA;
	status = add_boot_entry(media, sector + 32, boot_entry++, partitions,
		partition_capacity, &count);
	if (EFI_ERROR(status))
		return status;
	for (record = 2U;;) {
		UINT8 indicator;
		UINT16 section_count;
		UINT32 section_entry;
		UINT64 catalog_sector = (UINT64)catalog_lba + record / 64U;

		if (catalog_sector > media->last_block)
			return EFI_COMPROMISED_DATA;
		status = read_iso_sector(media, catalog_sector, sector);
		if (EFI_ERROR(status))
			return status;
		copy(entry, sector + (record % 64U) * 32U, sizeof(entry));
		indicator = entry[0];

		if (indicator == 0)
			break;
		if (indicator != 0x90U && indicator != 0x91U)
			return EFI_COMPROMISED_DATA;
		if (entry[1] > 2U && entry[1] != 0xefU)
			return EFI_COMPROMISED_DATA;
		section_count = (UINT16)entry[2] | (UINT16)entry[3] << 8;
		record++;
		for (section_entry = 0; section_entry < section_count;
		     section_entry++, record++) {
			catalog_sector = (UINT64)catalog_lba + record / 64U;
			if (catalog_sector > media->last_block)
				return EFI_COMPROMISED_DATA;
			status = read_iso_sector(media, catalog_sector, sector);
			if (EFI_ERROR(status))
				return status;
			copy(entry, sector + (record % 64U) * 32U, sizeof(entry));
			status = add_boot_entry(media, entry, boot_entry++,
				partitions, partition_capacity, &count);
			if (EFI_ERROR(status))
				return status;
		}
		if (indicator == 0x91U)
			break;
	}
	*partition_count = count;
	return count == 0 ? EFI_NOT_FOUND : EFI_SUCCESS;
}

static UINT16 read16(const UINT8 *bytes)
{
	return (UINT16)bytes[0] | (UINT16)bytes[1] << 8;
}

static UINT16 udf_crc16(const UINT8 *bytes, UINTN size)
{
	UINT16 crc = 0;
	UINTN index;
	UINTN bit;

	for (index = 0; index < size; index++) {
		crc ^= (UINT16)bytes[index] << 8;
		for (bit = 0; bit < 8; bit++)
			crc = crc & 0x8000U ? (UINT16)((crc << 1) ^ 0x1021U) :
				(UINT16)(crc << 1);
	}
	return crc;
}

static EFI_STATUS validate_udf_tag(const UINT8 *block, UINT32 block_size,
	UINT16 identifier, UINT32 location)
{
	UINT8 sum = 0;
	UINT16 crc_length;
	UINTN index;

	if (read16(block) != identifier || read16(block + 2) < 2U ||
	    read32(block + 12) != location)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < 16U; index++)
		if (index != 4U)
			sum = (UINT8)(sum + block[index]);
	if (sum != block[4])
		return EFI_CRC_ERROR;
	crc_length = read16(block + 10);
	if (crc_length > block_size - 16U)
		return EFI_COMPROMISED_DATA;
	if (crc_length != 0 && udf_crc16(block + 16, crc_length) != read16(block + 8))
		return EFI_CRC_ERROR;
	return EFI_SUCCESS;
}

static EFI_STATUS read_udf_anchor(const struct cdk2_partition_media *media,
	UINT8 *block, UINT64 lba, UINT32 sequence_lba[2], UINT32 sequence_bytes[2])
{
	EFI_STATUS status;

	if (lba > media->last_block || lba > MAX_UINT32)
		return EFI_NOT_FOUND;
	status = media->read(media->context, lba, 1U, block);
	if (EFI_ERROR(status))
		return status;
	status = validate_udf_tag(block, media->block_size, UDF_ANCHOR_TAG,
		(UINT32)lba);
	if (EFI_ERROR(status))
		return status;
	sequence_bytes[0] = read32(block + 16);
	sequence_lba[0] = read32(block + 20);
	sequence_bytes[1] = read32(block + 24);
	sequence_lba[1] = read32(block + 28);
	if (sequence_bytes[0] < media->block_size ||
	    sequence_bytes[0] % media->block_size != 0)
		return EFI_COMPROMISED_DATA;
	if (sequence_bytes[1] != 0 && (sequence_bytes[1] < media->block_size ||
	    sequence_bytes[1] % media->block_size != 0))
		return EFI_COMPROMISED_DATA;
	return EFI_SUCCESS;
}

static EFI_STATUS parse_udf_sequence(const struct cdk2_partition_media *media,
	UINT8 *block, UINT32 sequence_lba, UINT32 sequence_bytes,
	struct cdk2_partition *partitions, UINTN partition_capacity, UINTN *count_out)
{
	UINT16 map_partition[64];
	UINT32 sequence_blocks;
	UINT32 file_set_lba = 0;
	UINT16 file_set_reference = 0;
	UINTN map_count = 0;
	UINTN count = 0;
	UINTN index;
	BOOLEAN logical_volume = FALSE;
	BOOLEAN terminated = FALSE;
	EFI_STATUS status;

	if (sequence_bytes == 0)
		return EFI_NOT_FOUND;
	sequence_blocks = sequence_bytes / media->block_size;
	if (sequence_blocks == 0 || sequence_blocks > UDF_SEQUENCE_LIMIT ||
	    sequence_lba > media->last_block ||
	    sequence_blocks - 1U > media->last_block - sequence_lba)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < sequence_blocks; index++) {
		UINT16 tag;

		status = media->read(media->context, sequence_lba + index, 1U, block);
		if (EFI_ERROR(status))
			return status;
		tag = read16(block);
		if (tag == 0 || tag > 9U)
			return EFI_COMPROMISED_DATA;
		status = validate_udf_tag(block, media->block_size, tag,
			sequence_lba + (UINT32)index);
		if (EFI_ERROR(status))
			return status;
		if (tag == UDF_TERMINATING_TAG) {
			terminated = TRUE;
			break;
		}
		if (tag == UDF_LOGICAL_VOLUME_TAG) {
			UINT32 map_bytes = read32(block + 264);
			UINT32 declared_maps = read32(block + 268);
			UINTN offset = 440U;

			if (read32(block + 212) != media->block_size)
				return EFI_UNSUPPORTED;
			if (map_bytes > media->block_size - offset ||
			    declared_maps > ARRAY_SIZE(map_partition))
				return EFI_COMPROMISED_DATA;
			map_count = 0;
			while (offset < 440U + map_bytes && map_count < declared_maps) {
				UINT8 length = block[offset + 1U];

				if (length > 440U + map_bytes - offset)
					return EFI_COMPROMISED_DATA;
				if (block[offset] == 1U && length >= 6U)
					map_partition[map_count++] = read16(block + offset + 4U);
				else if (block[offset] == 2U && length >= 40U)
					map_partition[map_count++] = read16(block + offset + 38U);
				else
					return EFI_UNSUPPORTED;
				offset += length;
			}
			if (offset != 440U + map_bytes || map_count != declared_maps)
				return EFI_COMPROMISED_DATA;
			file_set_lba = read32(block + 252);
			file_set_reference = read16(block + 256);
			logical_volume = TRUE;
			continue;
		}
		if (tag == UDF_PARTITION_TAG) {
			struct cdk2_partition *partition;
			UINT32 start = read32(block + 188);
			UINT32 blocks = read32(block + 192);
			UINTN character;

			if (blocks == 0 || start > media->last_block ||
			    blocks - 1U > media->last_block - start)
				return EFI_COMPROMISED_DATA;
			if (count == partition_capacity)
				return EFI_BUFFER_TOO_SMALL;
			status = validate_entry_range(partitions, count, start,
				start + blocks - 1U, 0, media->last_block);
			if (EFI_ERROR(status))
				return status;
			partition = &partitions[count++];
			__builtin_memset(partition, 0, sizeof(*partition));
			partition->scheme = CDK2_PARTITION_UDF;
			partition->start_lba = start;
			partition->end_lba = start + blocks - 1U;
			partition->attributes = read32(block + 184);
			partition->type_guid = blank_guid;
			partition->unique_guid = blank_guid;
			for (character = 0; character < CDK2_GPT_NAME_CHARS; character++)
				partition->name[character] = 0;
			partition->index = read16(block + 22) + 1U;
		}
	}
	if (!terminated || !logical_volume || count == 0 ||
	    file_set_reference >= map_count)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < count; index++)
		if (partitions[index].index ==
		    (UINT32)map_partition[file_set_reference] + 1U)
			break;
	if (index == count || file_set_lba >
	    partitions[index].end_lba - partitions[index].start_lba)
		return EFI_COMPROMISED_DATA;
	status = media->read(media->context,
		partitions[index].start_lba + file_set_lba, 1U, block);
	if (EFI_ERROR(status))
		return status;
	status = validate_udf_tag(block, media->block_size, UDF_FILE_SET_TAG,
		file_set_lba);
	if (!EFI_ERROR(status))
		*count_out = count;
	return status;
}

EFI_STATUS cdk2_partition_parse_udf(const struct cdk2_partition_media *media,
	void *block_buffer, UINTN block_capacity,
	struct cdk2_partition *partitions, UINTN partition_capacity,
	UINTN *partition_count)
{
	UINT8 *block = block_buffer;
	UINT64 anchors[3];
	UINT32 sequence_lba[2] = { 0, 0 };
	UINT32 sequence_bytes[2] = { 0, 0 };
	UINTN anchor_count = 1U;
	UINTN anchor;
	UINTN sequence;
	EFI_STATUS main_status = EFI_NOT_FOUND;
	EFI_STATUS status = EFI_NOT_FOUND;

	if (!media_valid(media) || block == NULL || partitions == NULL ||
	    partition_count == NULL || block_capacity < media->block_size)
		return EFI_INVALID_PARAMETER;
	*partition_count = 0;
	anchors[0] = 256U;
	if (media->last_block >= 256U)
		anchors[anchor_count++] = media->last_block - 256U;
	anchors[anchor_count++] = media->last_block;
	for (anchor = 0; anchor < anchor_count; anchor++) {
		status = read_udf_anchor(media, block, anchors[anchor], sequence_lba,
			sequence_bytes);
		if (!EFI_ERROR(status))
			break;
	}
	if (anchor == anchor_count)
		return status == EFI_NOT_FOUND ? EFI_NOT_FOUND : EFI_COMPROMISED_DATA;
	for (sequence = 0; sequence < 2U; sequence++) {
		if (sequence == 1U && sequence_bytes[1] == 0)
			return main_status;
		status = parse_udf_sequence(media, block, sequence_lba[sequence],
			sequence_bytes[sequence], partitions, partition_capacity,
			partition_count);
		if (!EFI_ERROR(status))
			return EFI_SUCCESS;
		if (sequence == 0)
			main_status = status;
	}
	return main_status;
}

EFI_STATUS cdk2_partition_parse_mbr(const struct cdk2_partition_media *media,
	void *block_buffer, UINTN block_capacity,
	struct cdk2_partition *partitions, UINTN partition_capacity,
	UINTN *partition_count)
{
	UINT8 *block = block_buffer;
	UINT64 extended_base = 0;
	UINT64 extended_size = 0;
	UINT64 ebr = 0;
	UINT32 signature;
	UINT32 logical_index = 5U;
	UINTN count = 0;
	UINTN index;
	EFI_STATUS status;

	if (!media_valid(media) || block == NULL || partitions == NULL ||
	    partition_count == NULL || block_capacity < media->block_size)
		return EFI_INVALID_PARAMETER;
	*partition_count = 0;
	status = media->read(media->context, 0, 1U, block);
	if (EFI_ERROR(status))
		return status;
	if (block[510] != 0x55U || block[511] != 0xaaU)
		return EFI_NOT_FOUND;
	signature = read32(block + 440);
	for (index = 0; index < MBR_ENTRY_COUNT; index++) {
		const UINT8 *entry = block + MBR_TABLE_OFFSET + index * MBR_ENTRY_SIZE;
		UINT8 type = entry[4];
		UINT32 start = read32(entry + 8);
		UINT32 blocks = read32(entry + 12);

		if (entry[0] != 0 && entry[0] != 0x80U)
			return EFI_COMPROMISED_DATA;
		if (type == 0 && start == 0 && blocks == 0)
			continue;
		if (type == 0xeeU)
			return EFI_NOT_FOUND;
		if (type == 0 || blocks == 0)
			return EFI_COMPROMISED_DATA;
		if (extended_type(type)) {
			if (extended_base != 0)
				return EFI_COMPROMISED_DATA;
			if (start == 0 || start > media->last_block ||
			    blocks - 1U > media->last_block - start)
				return EFI_COMPROMISED_DATA;
			extended_base = start;
			extended_size = blocks;
			ebr = start;
			continue;
		}
		status = add_mbr_partition(partitions, partition_capacity, &count,
			start, blocks, type, signature, (UINT32)index + 1U,
			media->last_block, entry);
		if (EFI_ERROR(status))
			return status;
	}
	for (index = 0; ebr != 0 && index < MBR_CHAIN_LIMIT; index++) {
		const UINT8 *logical;
		const UINT8 *link;
		UINT64 next;

		if (ebr < extended_base || ebr - extended_base >= extended_size ||
		    ebr > media->last_block)
			return EFI_COMPROMISED_DATA;
		status = media->read(media->context, ebr, 1U, block);
		if (EFI_ERROR(status))
			return status;
		if (block[510] != 0x55U || block[511] != 0xaaU)
			return EFI_COMPROMISED_DATA;
		logical = block + MBR_TABLE_OFFSET;
		link = logical + MBR_ENTRY_SIZE;
		if (logical[4] == 0 || extended_type(logical[4]) ||
		    read32(logical + 8) == 0)
			return EFI_COMPROMISED_DATA;
		if ((UINT64)read32(logical + 8) + read32(logical + 12) >
		    extended_base + extended_size - ebr)
			return EFI_COMPROMISED_DATA;
		status = add_mbr_partition(partitions, partition_capacity, &count,
			ebr + read32(logical + 8), read32(logical + 12), logical[4],
			signature, logical_index++, media->last_block, logical);
		if (EFI_ERROR(status))
			return status;
		if (link[4] == 0 && read32(link + 8) == 0 && read32(link + 12) == 0) {
			ebr = 0;
			break;
		}
		if (!extended_type(link[4]) || read32(link + 8) == 0)
			return EFI_COMPROMISED_DATA;
		next = extended_base + read32(link + 8);
		if (next <= extended_base || next == ebr)
			return EFI_COMPROMISED_DATA;
		ebr = next;
	}
	if (ebr != 0)
		return EFI_COMPROMISED_DATA;
	*partition_count = count;
	return count == 0 ? EFI_NOT_FOUND : EFI_SUCCESS;
}
