/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_PI_FIRMWARE_FILE_H_
#define CDK2_ABI_PI_FIRMWARE_FILE_H_

#include <uefi.h>

typedef union {
	struct {
		UINT8 header;
		UINT8 file;
	} checksum;
	UINT16 checksum16;
} EFI_FFS_INTEGRITY_CHECK;

#define FFS_FIXED_CHECKSUM 0xaaU

typedef UINT8 EFI_FV_FILETYPE;
typedef UINT8 EFI_FFS_FILE_ATTRIBUTES;
typedef UINT8 EFI_FFS_FILE_STATE;

#define EFI_FV_FILETYPE_SECURITY_CORE         0x03U
#define EFI_FV_FILETYPE_DXE_CORE              0x05U
#define EFI_FV_FILETYPE_DRIVER                0x07U
#define EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE 0x0bU
#define EFI_FV_FILETYPE_FFS_PAD               0xf0U

#define FFS_ATTRIB_LARGE_FILE       0x01U
#define FFS_ATTRIB_DATA_ALIGNMENT_2 0x02U
#define FFS_ATTRIB_DATA_ALIGNMENT   0x38U
#define FFS_ATTRIB_CHECKSUM         0x40U

#define EFI_FILE_HEADER_CONSTRUCTION 0x01U
#define EFI_FILE_HEADER_VALID        0x02U
#define EFI_FILE_DATA_VALID          0x04U
#define EFI_FILE_MARKED_FOR_UPDATE   0x08U
#define EFI_FILE_DELETED             0x10U
#define EFI_FILE_HEADER_INVALID      0x20U

typedef struct {
	EFI_GUID name;
	EFI_FFS_INTEGRITY_CHECK integrity_check;
	EFI_FV_FILETYPE type;
	EFI_FFS_FILE_ATTRIBUTES attributes;
	UINT8 size[3];
	EFI_FFS_FILE_STATE state;
} EFI_FFS_FILE_HEADER;

typedef struct {
	EFI_GUID name;
	EFI_FFS_INTEGRITY_CHECK integrity_check;
	EFI_FV_FILETYPE type;
	EFI_FFS_FILE_ATTRIBUTES attributes;
	UINT8 size[3];
	EFI_FFS_FILE_STATE state;
	UINT64 extended_size;
} EFI_FFS_FILE_HEADER2;

typedef UINT8 EFI_SECTION_TYPE;

#define EFI_SECTION_PE32 0x10U
#define EFI_SECTION_FIRMWARE_VOLUME_IMAGE 0x17U
#define EFI_SECTION_RAW  0x19U

typedef struct {
	UINT8 size[3];
	EFI_SECTION_TYPE type;
} EFI_COMMON_SECTION_HEADER;

typedef struct {
	UINT8 size[3];
	EFI_SECTION_TYPE type;
	UINT32 extended_size;
} EFI_COMMON_SECTION_HEADER2;

#endif
