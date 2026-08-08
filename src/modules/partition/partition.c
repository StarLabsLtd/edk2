/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#define GPT_HEADER_SIZE 92U
#define GPT_ENTRY_MIN_SIZE 128U
#define MBR_TABLE_OFFSET 446U
#define MBR_ENTRY_SIZE 16U
#define MBR_ENTRY_COUNT 4U
#define MBR_CHAIN_LIMIT 128U

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
	UINT64 last_block, UINT32 *entry_count, UINT32 *entry_size,
	UINT64 *entry_lba, UINT64 *first_usable, UINT64 *last_usable)
{
	UINT32 header_size;
	UINT32 expected_crc;
	UINT32 actual_crc;

	if (read64(header) != 0x5452415020494645ULL || read32(header + 8) != 0x00010000U)
		return EFI_NOT_FOUND;
	header_size = read32(header + 12);
	if (header_size < GPT_HEADER_SIZE || header_size > block_size ||
	    read32(header + 20) != 0 || read64(header + 24) != 1U)
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
	if (read64(header + 32) > last_block || read64(header + 32) == 1U)
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

EFI_STATUS cdk2_partition_parse_gpt(const struct cdk2_partition_media *media,
	void *header_block, UINTN header_capacity, void *entry_buffer,
	UINTN entry_capacity, struct cdk2_partition *partitions,
	UINTN partition_capacity, UINTN *partition_count)
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
	status = media->read(media->context, 1U, 1U, header);
	if (EFI_ERROR(status))
		return status;
	status = validate_header(header, media->block_size, media->last_block,
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
		partition->mbr_type = 0;
		found++;
	}
	*partition_count = found;
	return EFI_SUCCESS;
}

static EFI_STATUS add_mbr_partition(struct cdk2_partition *partitions,
	UINTN capacity, UINTN *count, UINT64 start, UINT32 blocks, UINT8 type,
	UINT32 signature, UINT32 index, UINT64 last_block)
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
	partition->mbr_type = type;
	(*count)++;
	return EFI_SUCCESS;
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
			media->last_block);
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
			signature, logical_index++, media->last_block);
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
