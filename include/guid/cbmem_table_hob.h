/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_CBMEM_TABLE_HOB_H_
#define CDK2_ABI_CBMEM_TABLE_HOB_H_

#include <uefi.h>

typedef struct {
	UINT64 address;
	UINT32 size;
	UINT32 reserved;
} COREBOOT_TABLE_HOB;

#endif
