/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_H_
#define CDK2_ABI_UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_H_

#include <universal_payload/universal_payload.h>

typedef struct {
	UNIVERSAL_PAYLOAD_GENERIC_HEADER header;
	BOOLEAN use_mmio;
	UINT8 register_stride;
	UINT32 baud_rate;
	EFI_PHYSICAL_ADDRESS register_base;
} __packed UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO;

#define UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_REVISION 1U

#endif
