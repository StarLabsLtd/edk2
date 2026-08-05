/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_FIRMWARE_INFO_GUID_H_
#define CDK2_ABI_FIRMWARE_INFO_GUID_H_

#include <uefi.h>

typedef struct {
	EFI_GUID type;
	CHAR8 version_str[64];
	UINT32 version;
	UINT32 lowest_supported_version;
	UINT32 image_size;
} FIRMWARE_INFO;

#endif
