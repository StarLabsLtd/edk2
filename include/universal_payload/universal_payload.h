/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_UNIVERSAL_PAYLOAD_H_
#define CDK2_ABI_UNIVERSAL_PAYLOAD_H_

#include <uefi.h>

typedef struct {
	UINT8 revision;
	UINT8 reserved;
	UINT16 length;
} __packed UNIVERSAL_PAYLOAD_GENERIC_HEADER;

#endif
