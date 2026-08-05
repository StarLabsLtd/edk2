/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_PE_IMAGE_H_
#define CDK2_ABI_PE_IMAGE_H_

#include <uefi.h>

#define IMAGE_FILE_MACHINE_X64 0x8664U

#define EFI_IMAGE_DOS_SIGNATURE SIGNATURE_16('M', 'Z')
#define EFI_IMAGE_NT_SIGNATURE  SIGNATURE_32('P', 'E', '\0', '\0')

typedef struct {
	UINT16 e_magic;
	UINT16 e_cblp;
	UINT16 e_cp;
	UINT16 e_crlc;
	UINT16 e_cparhdr;
	UINT16 e_minalloc;
	UINT16 e_maxalloc;
	UINT16 e_ss;
	UINT16 e_sp;
	UINT16 e_csum;
	UINT16 e_ip;
	UINT16 e_cs;
	UINT16 e_lfarlc;
	UINT16 e_ovno;
	UINT16 e_res[4];
	UINT16 e_oemid;
	UINT16 e_oeminfo;
	UINT16 e_res2[10];
	UINT32 e_lfanew;
} EFI_IMAGE_DOS_HEADER;

typedef struct {
	UINT16 machine;
	UINT16 number_of_sections;
	UINT32 time_date_stamp;
	UINT32 pointer_to_symbol_table;
	UINT32 number_of_symbols;
	UINT16 size_of_optional_header;
	UINT16 characteristics;
} EFI_IMAGE_FILE_HEADER;

#define EFI_IMAGE_FILE_EXECUTABLE_IMAGE    BIT1
#define EFI_IMAGE_FILE_LARGE_ADDRESS_AWARE BIT5

typedef struct {
	UINT32 virtual_address;
	UINT32 size;
} EFI_IMAGE_DATA_DIRECTORY;

#define EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC   5U
#define EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES 16U
#define EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC     0x20bU

typedef struct {
	UINT16 magic;
	UINT8 major_linker_version;
	UINT8 minor_linker_version;
	UINT32 size_of_code;
	UINT32 size_of_initialized_data;
	UINT32 size_of_uninitialized_data;
	UINT32 address_of_entry_point;
	UINT32 base_of_code;
	UINT64 image_base;
	UINT32 section_alignment;
	UINT32 file_alignment;
	UINT16 major_operating_system_version;
	UINT16 minor_operating_system_version;
	UINT16 major_image_version;
	UINT16 minor_image_version;
	UINT16 major_subsystem_version;
	UINT16 minor_subsystem_version;
	UINT32 win32_version_value;
	UINT32 size_of_image;
	UINT32 size_of_headers;
	UINT32 check_sum;
	UINT16 subsystem;
	UINT16 dll_characteristics;
	UINT64 size_of_stack_reserve;
	UINT64 size_of_stack_commit;
	UINT64 size_of_heap_reserve;
	UINT64 size_of_heap_commit;
	UINT32 loader_flags;
	UINT32 number_of_rva_and_sizes;
	EFI_IMAGE_DATA_DIRECTORY data_directory[EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES];
} EFI_IMAGE_OPTIONAL_HEADER64;

typedef struct {
	UINT32 signature;
	EFI_IMAGE_FILE_HEADER file_header;
	EFI_IMAGE_OPTIONAL_HEADER64 optional_header;
} EFI_IMAGE_NT_HEADERS64;

#define EFI_IMAGE_SIZEOF_SHORT_NAME 8U

typedef struct {
	UINT8 name[EFI_IMAGE_SIZEOF_SHORT_NAME];
	union {
		UINT32 physical_address;
		UINT32 virtual_size;
	} misc;
	UINT32 virtual_address;
	UINT32 size_of_raw_data;
	UINT32 pointer_to_raw_data;
	UINT32 pointer_to_relocations;
	UINT32 pointer_to_linenumbers;
	UINT16 number_of_relocations;
	UINT16 number_of_linenumbers;
	UINT32 characteristics;
} EFI_IMAGE_SECTION_HEADER;

typedef struct {
	UINT32 virtual_address;
	UINT32 size_of_block;
} EFI_IMAGE_BASE_RELOCATION;

#define EFI_IMAGE_REL_BASED_ABSOLUTE 0U
#define EFI_IMAGE_REL_BASED_DIR64    10U

#endif
