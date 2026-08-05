/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_SMM_STORE_INFO_GUID_H_
#define CDK2_ABI_SMM_STORE_INFO_GUID_H_

#include <uefi.h>

typedef struct {
	UINT64 com_buffer;
	UINT32 com_buffer_size;
	UINT32 num_blocks;
	UINT32 block_size;
	UINT64 mmio_address;
	UINT8 apm_cmd;
} SMMSTORE_INFO;

#endif
