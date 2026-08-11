/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_ABI_VARIABLE_FLASH_INFO_H_
#define CDK2_ABI_VARIABLE_FLASH_INFO_H_

#include <uefi.h>

typedef struct {
	UINT32 version;
	UINT32 reserved;
	EFI_PHYSICAL_ADDRESS variable_base;
	UINT64 variable_length;
	EFI_PHYSICAL_ADDRESS spare_base;
	UINT64 spare_length;
	EFI_PHYSICAL_ADDRESS working_base;
	UINT64 working_length;
} __packed CDK2_VARIABLE_FLASH_INFO;

#endif
