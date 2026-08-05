/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_PI_FIRMWARE_VOLUME_H_
#define CDK2_ABI_PI_FIRMWARE_VOLUME_H_

#include <uefi.h>

typedef UINT32 EFI_FVB_ATTRIBUTES_2;

#define EFI_FVB2_ERASE_POLARITY 0x00000800U

typedef struct {
	UINT32 num_blocks;
	UINT32 length;
} __packed EFI_FV_BLOCK_MAP_ENTRY;

typedef struct {
	UINT8 zero_vector[16];
	EFI_GUID file_system_guid;
	UINT64 fv_length;
	UINT32 signature;
	EFI_FVB_ATTRIBUTES_2 attributes;
	UINT16 header_length;
	UINT16 checksum;
	UINT16 ext_header_offset;
	UINT8 reserved[1];
	UINT8 revision;
	EFI_FV_BLOCK_MAP_ENTRY block_map[1];
} __packed EFI_FIRMWARE_VOLUME_HEADER;

typedef struct {
	EFI_GUID fv_name;
	UINT32 ext_header_size;
} __packed EFI_FIRMWARE_VOLUME_EXT_HEADER;

#define EFI_FVH_SIGNATURE SIGNATURE_32('_', 'F', 'V', 'H')

#endif
