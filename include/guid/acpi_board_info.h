/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_ACPI_BOARD_INFO_GUID_H_
#define CDK2_ABI_ACPI_BOARD_INFO_GUID_H_

#include <uefi.h>

typedef struct {
	UINT8 revision;
	UINT8 reserved0[2];
	UINT8 reset_value;
	UINT64 pm_evt_base;
	UINT64 pm_gpe_en_base;
	UINT64 pm_ctrl_reg_base;
	UINT64 pm_timer_reg_base;
	UINT64 reset_reg_address;
	UINT64 pcie_base_address;
	UINT64 pcie_base_size;
	UINT8 tpm20_present;
	UINT8 tpm12_present;
} ACPI_BOARD_INFO;

#endif
