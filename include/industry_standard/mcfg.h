/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_MCFG_H_
#define CDK2_ABI_MCFG_H_

#include <industry_standard/acpi.h>

typedef struct {
	UINT64 base_address;
	UINT16 pci_segment_group_number;
	UINT8 start_bus_number;
	UINT8 end_bus_number;
	UINT32 reserved;
} __packed
EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE;

typedef struct {
	EFI_ACPI_DESCRIPTION_HEADER header;
	UINT64 reserved;
} __packed EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER;

#endif
