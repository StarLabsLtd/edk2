/* SPDX-License-Identifier: GPL-2.0-only */

#include "coreboot_checksum.h"

UINT16 cdk2_coreboot_checksum16(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT32 sum;
	UINTN index;

	if (buffer == NULL) {
		return 0;
	}

	bytes = (const UINT8 *)buffer;
	sum = 0;
	for (index = 0; index < length; index++) {
		sum += (index & 1) ? ((UINT32)bytes[index] << 8) : bytes[index];
		if (sum >= 0x10000U) {
			sum = (sum + (sum >> 16)) & 0xffffU;
		}
	}

	return (UINT16)(~sum & 0xffffU);
}

UINT32 cdk2_coreboot_crc32_update(UINT32 crc, UINT8 byte)
{
	UINTN bit_index;

	crc ^= (UINT32)byte << 24;
	for (bit_index = 0; bit_index < 8; bit_index++) {
		if ((crc & BIT31) != 0) {
			crc = (crc << 1) ^ 0x04C11DB7U;
		} else {
			crc <<= 1;
		}
	}

	return crc;
}

UINT32 cdk2_coreboot_calculate_crc32(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT32 crc;
	UINTN index;

	if (buffer == NULL) {
		return 0;
	}

	bytes = (const UINT8 *)buffer;
	crc = 0;
	for (index = 0; index < length; index++) {
		crc = cdk2_coreboot_crc32_update(crc, bytes[index]);
	}

	return crc;
}
