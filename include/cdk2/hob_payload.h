/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_HOB_PAYLOAD_H_
#define CDK2_HOB_PAYLOAD_H_

#include <uefi.h>

/*
 * Payloads for GUID HOBs derived directly from coreboot table records.
 * Keep these definitions limited to the HOB wire format; coreboot tables are
 * the authoritative platform handoff consumed by cdk2.
 */
typedef struct {
	UINT8 revision;
	UINT8 reserved;
	UINT16 length;
} __packed CDK2_HOB_PAYLOAD_HEADER;

typedef struct {
	CDK2_HOB_PAYLOAD_HEADER header;
	EFI_PHYSICAL_ADDRESS rsdp;
} __packed CDK2_ACPI_TABLE_HOB;

#define CDK2_ACPI_TABLE_HOB_REVISION 1U

typedef struct {
	CDK2_HOB_PAYLOAD_HEADER header;
	EFI_PHYSICAL_ADDRESS smbios_entry_point;
} __packed CDK2_SMBIOS_TABLE_HOB;

#define CDK2_SMBIOS_TABLE_HOB_REVISION 1U

typedef struct {
	CDK2_HOB_PAYLOAD_HEADER header;
	BOOLEAN use_mmio;
	UINT8 register_stride;
	UINT32 baud_rate;
	EFI_PHYSICAL_ADDRESS register_base;
} __packed CDK2_SERIAL_PORT_HOB;

#define CDK2_SERIAL_PORT_HOB_REVISION 1U

#endif
