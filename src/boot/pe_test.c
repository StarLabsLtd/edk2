/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host checks for native PE32+ loading and relocation.
 */

#include "pe.h"

#include <stdio.h>
#include <string.h>

#define TEST_IMAGE_SIZE 0x600U
#define TEST_LOAD_SIZE  0x3000U

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 PE test: %s\n", message);
		return 1;
	}

	return 0;
}

static UINTN build_image(UINT8 *storage, UINTN storage_size)
{
	EFI_IMAGE_DOS_HEADER *dos;
	EFI_IMAGE_NT_HEADERS64 *nt;
	EFI_IMAGE_SECTION_HEADER *sections;
	EFI_IMAGE_BASE_RELOCATION *reloc;
	UINT16 *reloc_entry;
	UINTN pe_offset;

	memset(storage, 0, storage_size);
	pe_offset = 0x80;
	dos = (EFI_IMAGE_DOS_HEADER *)(void *)storage;
	dos->e_magic = EFI_IMAGE_DOS_SIGNATURE;
	dos->e_lfanew = pe_offset;
	nt = (EFI_IMAGE_NT_HEADERS64 *)(void *)(storage + pe_offset);
	nt->signature = EFI_IMAGE_NT_SIGNATURE;
	nt->file_header.machine = IMAGE_FILE_MACHINE_X64;
	nt->file_header.number_of_sections = 2;
	nt->file_header.size_of_optional_header = sizeof(EFI_IMAGE_OPTIONAL_HEADER64);
	nt->optional_header.magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt->optional_header.image_base = 0x00400000;
	nt->optional_header.section_alignment = 0x1000;
	nt->optional_header.file_alignment = 0x200;
	nt->optional_header.size_of_image = 0x3000;
	nt->optional_header.size_of_headers = 0x200;
	nt->optional_header.address_of_entry_point = 0x1000;
	nt->optional_header.number_of_rva_and_sizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
	nt->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address =
		0x2000;
	nt->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].size = 12;

	sections = (EFI_IMAGE_SECTION_HEADER *)(void *)((UINT8 *)nt +
							sizeof(EFI_IMAGE_NT_HEADERS64));
	sections[0].misc.virtual_size = 0x100;
	sections[0].virtual_address = 0x1000;
	sections[0].size_of_raw_data = 0x200;
	sections[0].pointer_to_raw_data = 0x200;
	sections[1].misc.virtual_size = 0x100;
	sections[1].virtual_address = 0x2000;
	sections[1].size_of_raw_data = 0x200;
	sections[1].pointer_to_raw_data = 0x400;
	*(UINT64 *)(void *)(storage + 0x200) = 0x00400123;

	reloc = (EFI_IMAGE_BASE_RELOCATION *)(void *)(storage + 0x400);
	reloc->virtual_address = 0x1000;
	reloc->size_of_block = 12;
	reloc_entry = (UINT16 *)(void *)(reloc + 1);
	reloc_entry[0] = (UINT16)((EFI_IMAGE_REL_BASED_DIR64 << 12) | 0);
	reloc_entry[1] = 0;
	return 0x600;
}

int main(void)
{
	UINT8 image[TEST_IMAGE_SIZE];
	UINT8 loaded[TEST_LOAD_SIZE];
	EFI_PHYSICAL_ADDRESS loaded_base;
	EFI_PHYSICAL_ADDRESS entry_point;
	UINTN loaded_size;
	EFI_STATUS status;
	int failures;

	failures = 0;
	build_image(image, sizeof(image));
	status = cdk2_native_load_pe32_plus(image, sizeof(image),
					    (EFI_PHYSICAL_ADDRESS)(UINTN)loaded, sizeof(loaded),
					    &loaded_base, &loaded_size, &entry_point);
	failures += expect(status == EFI_SUCCESS, "valid PE image rejected");
	failures += expect(loaded_base == (EFI_PHYSICAL_ADDRESS)(UINTN)loaded,
			   "loaded base is wrong");
	failures += expect(loaded_size == 0x3000, "loaded size is wrong");
	failures += expect(entry_point == loaded_base + 0x1000, "entry point is wrong");
	failures += expect(*(UINT64 *)(void *)(loaded + 0x1000) == loaded_base + 0x123,
			   "DIR64 relocation is wrong");

	status = cdk2_native_load_pe32_plus(image, sizeof(image),
					    (EFI_PHYSICAL_ADDRESS)(UINTN)loaded, 0x1000,
					    &loaded_base, &loaded_size, &entry_point);
	failures += expect(status == EFI_COMPROMISED_DATA, "destination exhaustion accepted");

	status = cdk2_native_load_pe32_plus(image, sizeof(image),
					    (EFI_PHYSICAL_ADDRESS)(MAX_UINT64 - 0x1000U),
					    sizeof(loaded), &loaded_base, &loaded_size,
					    &entry_point);
	failures +=
		expect(status == EFI_COMPROMISED_DATA, "wrapping destination range accepted");

	build_image(image, sizeof(image));
	{
		EFI_IMAGE_BASE_RELOCATION *reloc;
		UINT16 *reloc_entry;

		reloc = (EFI_IMAGE_BASE_RELOCATION *)(void *)(image + 0x400);
		reloc->virtual_address = MAX_UINT32;
		reloc_entry = (UINT16 *)(void *)(reloc + 1);
		reloc_entry[0] = (UINT16)((EFI_IMAGE_REL_BASED_DIR64 << 12) | 1);
		status = cdk2_native_load_pe32_plus(image, sizeof(image),
						    (EFI_PHYSICAL_ADDRESS)(UINTN)loaded,
						    sizeof(loaded), &loaded_base, &loaded_size,
						    &entry_point);
		failures += expect(status == EFI_COMPROMISED_DATA,
				   "relocation RVA wraparound accepted");
	}

	build_image(image, sizeof(image));
	((EFI_IMAGE_SECTION_HEADER *)(void *)(image + 0x80 + sizeof(EFI_IMAGE_NT_HEADERS64)))[1]
		.virtual_address = 0x1000;
	status = cdk2_native_load_pe32_plus(image, sizeof(image),
					    (EFI_PHYSICAL_ADDRESS)(UINTN)loaded, sizeof(loaded),
					    &loaded_base, &loaded_size, &entry_point);
	failures += expect(status == EFI_COMPROMISED_DATA, "overlapping sections accepted");

	build_image(image, sizeof(image));
	status = cdk2_native_load_pe32_plus(
		image, 0x80 + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER),
		(EFI_PHYSICAL_ADDRESS)(UINTN)loaded, sizeof(loaded), &loaded_base, &loaded_size,
		&entry_point);
	failures += expect(status == EFI_COMPROMISED_DATA,
			   "truncated optional header was accepted");

	if (failures != 0) {
		return 1;
	}

	puts("cdk2 PE test: PASS");
	return 0;
}
