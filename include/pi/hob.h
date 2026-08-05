/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_PI_HOB_H_
#define CDK2_ABI_PI_HOB_H_

#include <uefi.h>
#include <pi/boot_mode.h>

#define EFI_HOB_TYPE_HANDOFF             0x0001U
#define EFI_HOB_TYPE_MEMORY_ALLOCATION   0x0002U
#define EFI_HOB_TYPE_RESOURCE_DESCRIPTOR 0x0003U
#define EFI_HOB_TYPE_GUID_EXTENSION      0x0004U
#define EFI_HOB_TYPE_FV                  0x0005U
#define EFI_HOB_TYPE_CPU                 0x0006U
#define EFI_HOB_TYPE_UEFI_CAPSULE        0x000bU
#define EFI_HOB_TYPE_UNUSED              0xfffeU
#define EFI_HOB_TYPE_END_OF_HOB_LIST     0xffffU

typedef struct {
	UINT16 hob_type;
	UINT16 hob_length;
	UINT32 reserved;
} EFI_HOB_GENERIC_HEADER;

#define EFI_HOB_HANDOFF_TABLE_VERSION 0x0009U

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	UINT32 version;
	EFI_BOOT_MODE boot_mode;
	EFI_PHYSICAL_ADDRESS efi_memory_top;
	EFI_PHYSICAL_ADDRESS efi_memory_bottom;
	EFI_PHYSICAL_ADDRESS efi_free_memory_top;
	EFI_PHYSICAL_ADDRESS efi_free_memory_bottom;
	EFI_PHYSICAL_ADDRESS efi_end_of_hob_list;
} EFI_HOB_HANDOFF_INFO_TABLE;

typedef struct {
	EFI_GUID name;
	EFI_PHYSICAL_ADDRESS memory_base_address;
	UINT64 memory_length;
	EFI_MEMORY_TYPE memory_type;
	UINT8 reserved[4];
} EFI_HOB_MEMORY_ALLOCATION_HEADER;

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	EFI_HOB_MEMORY_ALLOCATION_HEADER alloc_descriptor;
} EFI_HOB_MEMORY_ALLOCATION;

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	EFI_HOB_MEMORY_ALLOCATION_HEADER alloc_descriptor;
} EFI_HOB_MEMORY_ALLOCATION_STACK;

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	EFI_HOB_MEMORY_ALLOCATION_HEADER memory_allocation_header;
	EFI_GUID module_name;
	EFI_PHYSICAL_ADDRESS entry_point;
} EFI_HOB_MEMORY_ALLOCATION_MODULE;

typedef UINT32 EFI_RESOURCE_TYPE;

#define EFI_RESOURCE_SYSTEM_MEMORY    0x00000000U
#define EFI_RESOURCE_MEMORY_MAPPED_IO 0x00000001U
#define EFI_RESOURCE_MEMORY_RESERVED  0x00000005U

typedef UINT32 EFI_RESOURCE_ATTRIBUTE_TYPE;

#define EFI_RESOURCE_ATTRIBUTE_PRESENT                        0x00000001U
#define EFI_RESOURCE_ATTRIBUTE_INITIALIZED                    0x00000002U
#define EFI_RESOURCE_ATTRIBUTE_TESTED                         0x00000004U
#define EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE                    0x00000400U
#define EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE              0x00000800U
#define EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE        0x00001000U
#define EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE           0x00002000U

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	EFI_GUID owner;
	EFI_RESOURCE_TYPE resource_type;
	EFI_RESOURCE_ATTRIBUTE_TYPE resource_attribute;
	EFI_PHYSICAL_ADDRESS physical_start;
	UINT64 resource_length;
} EFI_HOB_RESOURCE_DESCRIPTOR;

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	EFI_GUID name;
} EFI_HOB_GUID_TYPE;

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	EFI_PHYSICAL_ADDRESS base_address;
	UINT64 length;
} EFI_HOB_FIRMWARE_VOLUME;

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	UINT8 size_of_memory_space;
	UINT8 size_of_io_space;
	UINT8 reserved[6];
} EFI_HOB_CPU;

typedef struct {
	EFI_HOB_GENERIC_HEADER header;
	EFI_PHYSICAL_ADDRESS base_address;
	UINT64 length;
} EFI_HOB_UEFI_CAPSULE;

typedef union {
	EFI_HOB_GENERIC_HEADER *header;
	EFI_HOB_HANDOFF_INFO_TABLE *handoff_information_table;
	EFI_HOB_MEMORY_ALLOCATION *memory_allocation;
	EFI_HOB_MEMORY_ALLOCATION_STACK *memory_allocation_stack;
	EFI_HOB_MEMORY_ALLOCATION_MODULE *memory_allocation_module;
	EFI_HOB_RESOURCE_DESCRIPTOR *resource_descriptor;
	EFI_HOB_GUID_TYPE *guid;
	EFI_HOB_FIRMWARE_VOLUME *firmware_volume;
	EFI_HOB_CPU *cpu;
	EFI_HOB_UEFI_CAPSULE *capsule;
	UINT8 *raw;
} EFI_PEI_HOB_POINTERS;

#endif
