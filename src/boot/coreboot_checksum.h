/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_NATIVE_COREBOOT_CHECKSUM_H_
#define CDK2_NATIVE_COREBOOT_CHECKSUM_H_

#include <uefi.h>

UINT16 cdk2_coreboot_checksum16(const void *buffer, UINTN length);

UINT32 cdk2_coreboot_crc32_update(UINT32 crc, UINT8 byte);

UINT32 cdk2_coreboot_calculate_crc32(const void *buffer, UINTN length);

#endif
