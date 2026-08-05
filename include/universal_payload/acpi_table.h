/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_UNIVERSAL_PAYLOAD_ACPI_TABLE_H_
#define CDK2_ABI_UNIVERSAL_PAYLOAD_ACPI_TABLE_H_

#include <universal_payload/universal_payload.h>

typedef struct {
	UNIVERSAL_PAYLOAD_GENERIC_HEADER header;
	EFI_PHYSICAL_ADDRESS rsdp;
} __packed UNIVERSAL_PAYLOAD_ACPI_TABLE;

#define UNIVERSAL_PAYLOAD_ACPI_TABLE_REVISION 1U

#endif
