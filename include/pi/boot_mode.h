/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_PI_BOOT_MODE_H_
#define CDK2_ABI_PI_BOOT_MODE_H_

#include <uefi.h>

typedef UINT32 EFI_BOOT_MODE;

#define BOOT_WITH_FULL_CONFIGURATION 0x00U
#define BOOT_ON_FLASH_UPDATE         0x12U

#endif
