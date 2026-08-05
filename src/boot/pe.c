/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Bounded PE32+ loading for native cdk2.
 */

#include "pe.h"

static BOOLEAN cdk2_native_range_valid(UINT64 base, UINT64 size, UINT64 limit)
{
	return base <= limit && size <= limit - base;
}

static void cdk2_native_zero(void *buffer, UINTN size)
{
	UINT8 *bytes;
	UINTN index;

	bytes = (UINT8 *)buffer;
	for (index = 0; index < size; index++) {
		bytes[index] = 0;
	}
}

static void cdk2_native_copy(void *destination, const void *source, UINTN size)
{
	UINT8 *destination_bytes;
	const UINT8 *source_bytes;
	UINTN index;

	destination_bytes = (UINT8 *)destination;
	source_bytes = (const UINT8 *)source;
	for (index = 0; index < size; index++) {
		destination_bytes[index] = source_bytes[index];
	}
}

static EFI_STATUS cdk2_native_apply_relocations(UINT8 *loaded_image, UINT32 image_size,
						UINT64 preferred_base, UINT64 destination_base,
						const EFI_IMAGE_DATA_DIRECTORY *relocations)
{
	UINT64 adjust;
	UINT32 offset;
	UINT32 block_size;
	UINT32 block_end;
	UINT64 fixup_rva;
	UINTN entry_count;
	UINTN entry_index;
	UINT16 entry;
	EFI_IMAGE_BASE_RELOCATION *block;
	UINT16 *entries;
	UINT64 *fixup;

	if (relocations->size == 0) {
		return (preferred_base == destination_base) ? EFI_SUCCESS : EFI_UNSUPPORTED;
	}

	if (!cdk2_native_range_valid(relocations->virtual_address, relocations->size,
				     image_size)) {
		return EFI_COMPROMISED_DATA;
	}

	adjust = destination_base - preferred_base;
	if (adjust == 0) {
		return EFI_SUCCESS;
	}

	offset = relocations->virtual_address;
	block_end = relocations->virtual_address + relocations->size;
	while (offset < block_end) {
		if (block_end - offset < sizeof(EFI_IMAGE_BASE_RELOCATION)) {
			return EFI_COMPROMISED_DATA;
		}

		block = (EFI_IMAGE_BASE_RELOCATION *)(void *)(loaded_image + offset);
		block_size = block->size_of_block;
		if (block_size < sizeof(*block) || block_size > block_end - offset ||
		    ((block_size - sizeof(*block)) & 1U) != 0) {
			return EFI_COMPROMISED_DATA;
		}

		entry_count = (block_size - sizeof(*block)) / sizeof(UINT16);
		entries = (UINT16 *)(void *)((UINT8 *)block + sizeof(*block));
		for (entry_index = 0; entry_index < entry_count; entry_index++) {
			entry = entries[entry_index];
			if ((entry >> 12) == EFI_IMAGE_REL_BASED_ABSOLUTE) {
				continue;
			}

			if ((entry >> 12) != EFI_IMAGE_REL_BASED_DIR64) {
				return EFI_UNSUPPORTED;
			}

			fixup_rva = (UINT64)block->virtual_address + (entry & 0x0fffU);
			if ((fixup_rva > MAX_UINT32) ||
			    !cdk2_native_range_valid(fixup_rva, sizeof(UINT64), image_size)) {
				return EFI_COMPROMISED_DATA;
			}

			fixup = (UINT64 *)(void *)(loaded_image + (UINT32)fixup_rva);
			*fixup = *fixup + adjust;
		}

		offset += block_size;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_native_load_pe32_plus(const void *image, unsigned long long image_size,
			   unsigned long long destination, unsigned long long destination_size,
			   unsigned long long *loaded_base, unsigned long long *loaded_size,
			   unsigned long long *entry_point)
{
	const UINT8 *image_bytes;
	const EFI_IMAGE_DOS_HEADER *dos_header;
	const EFI_IMAGE_NT_HEADERS64 *nt_headers;
	const EFI_IMAGE_SECTION_HEADER *sections;
	const EFI_IMAGE_SECTION_HEADER *section;
	const EFI_IMAGE_OPTIONAL_HEADER64 *optional;
	UINTN pe_offset;
	UINTN optional_offset;
	UINTN section_offset;
	UINTN section_table_size;
	UINTN index;
	UINTN other_index;
	UINTN virtual_size;
	UINTN section_span;
	UINTN raw_offset;
	UINTN raw_size;
	UINT32 end_rva;
	UINT32 entry_rva;
	EFI_STATUS status;

	if (image == NULL || image_size == 0 || destination == 0 || loaded_base == NULL ||
	    loaded_size == NULL || entry_point == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	image_bytes = (const UINT8 *)image;
	pe_offset = 0;
	if (image_size >= sizeof(EFI_IMAGE_DOS_HEADER) &&
	    ((const EFI_IMAGE_DOS_HEADER *)image)->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
		dos_header = (const EFI_IMAGE_DOS_HEADER *)image;
		pe_offset = dos_header->e_lfanew;
	}

	if (pe_offset > image_size ||
	    image_size - pe_offset < sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER)) {
		return EFI_COMPROMISED_DATA;
	}

	nt_headers = (const EFI_IMAGE_NT_HEADERS64 *)(void *)(image_bytes + pe_offset);
	if (nt_headers->signature != EFI_IMAGE_NT_SIGNATURE ||
	    nt_headers->file_header.machine != IMAGE_FILE_MACHINE_X64 ||
	    nt_headers->file_header.number_of_sections == 0 ||
	    nt_headers->file_header.number_of_sections > 96 ||
	    nt_headers->file_header.size_of_optional_header < sizeof(EFI_IMAGE_OPTIONAL_HEADER64)) {
		return EFI_UNSUPPORTED;
	}

	optional_offset = pe_offset + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER);
	if (optional_offset > image_size ||
	    nt_headers->file_header.size_of_optional_header > image_size - optional_offset) {
		return EFI_COMPROMISED_DATA;
	}

	optional = &nt_headers->optional_header;
	if (optional->magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
	    optional->section_alignment == 0 ||
	    (optional->section_alignment & (optional->section_alignment - 1)) != 0 ||
	    optional->size_of_image == 0 || optional->size_of_headers == 0 ||
	    optional->size_of_headers > optional->size_of_image ||
	    optional->size_of_headers > image_size ||
	    optional->address_of_entry_point >= optional->size_of_image ||
	    optional->size_of_image > destination_size ||
	    !cdk2_native_range_valid(destination, optional->size_of_image, MAX_UINTN)) {
		return EFI_COMPROMISED_DATA;
	}

	section_offset = optional_offset + nt_headers->file_header.size_of_optional_header;
	section_table_size = (UINTN)nt_headers->file_header.number_of_sections *
			   sizeof(EFI_IMAGE_SECTION_HEADER);
	if (section_offset > image_size || section_table_size > image_size - section_offset) {
		return EFI_COMPROMISED_DATA;
	}

	sections = (const EFI_IMAGE_SECTION_HEADER *)(void *)(image_bytes + section_offset);
	for (index = 0; index < nt_headers->file_header.number_of_sections; index++) {
		section = &sections[index];
		virtual_size = section->misc.virtual_size;
		section_span = (virtual_size > section->size_of_raw_data) ? virtual_size :
								       section->size_of_raw_data;
		end_rva = section->virtual_address + (UINT32)section_span;
		if (section_span == 0 || end_rva < section->virtual_address ||
		    end_rva > optional->size_of_image ||
		    (section->virtual_address & (optional->section_alignment - 1)) != 0) {
			return EFI_COMPROMISED_DATA;
		}

		raw_offset = section->pointer_to_raw_data;
		raw_size = section->size_of_raw_data;
		if (raw_size > image_size || raw_offset > image_size - raw_size) {
			return EFI_COMPROMISED_DATA;
		}

		for (other_index = 0; other_index < index; other_index++) {
			UINTN other_size;
			UINT32 other_end;

			other_size = (sections[other_index].misc.virtual_size >
				     sections[other_index].size_of_raw_data) ?
					    sections[other_index].misc.virtual_size :
					    sections[other_index].size_of_raw_data;
			other_end = sections[other_index].virtual_address + (UINT32)other_size;
			if ((section->virtual_address < other_end) &&
			    (sections[other_index].virtual_address < end_rva)) {
				return EFI_COMPROMISED_DATA;
			}
		}
	}

	cdk2_native_zero((void *)(UINTN)destination, optional->size_of_image);
	cdk2_native_copy((void *)(UINTN)destination, image, optional->size_of_headers);
	for (index = 0; index < nt_headers->file_header.number_of_sections; index++) {
		section = &sections[index];
		if (section->size_of_raw_data != 0) {
			cdk2_native_copy((void *)(UINTN)(destination + section->virtual_address),
					 image_bytes + section->pointer_to_raw_data,
					 section->size_of_raw_data);
		}
	}

	if (optional->number_of_rva_and_sizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
		status = cdk2_native_apply_relocations(
			(UINT8 *)(UINTN)destination, optional->size_of_image, optional->image_base,
			destination,
			&optional->data_directory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]);
		if (EFI_ERROR(status)) {
			return status;
		}
	} else if (optional->image_base != destination) {
		return EFI_UNSUPPORTED;
	}

	entry_rva = optional->address_of_entry_point;
	*loaded_base = destination;
	*loaded_size = optional->size_of_image;
	*entry_point = destination + entry_rva;
	return EFI_SUCCESS;
}
