/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_UNIVERSAL_PAYLOAD_SMBIOS_TABLE_H_
#define CDK2_ABI_UNIVERSAL_PAYLOAD_SMBIOS_TABLE_H_

#include <universal_payload/universal_payload.h>

typedef struct {
	UNIVERSAL_PAYLOAD_GENERIC_HEADER header;
	EFI_PHYSICAL_ADDRESS sm_bios_entry_point;
} __packed UNIVERSAL_PAYLOAD_SMBIOS_TABLE;

#define UNIVERSAL_PAYLOAD_SMBIOS_TABLE_REVISION 1U

#endif
