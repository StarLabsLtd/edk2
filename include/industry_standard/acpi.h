/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_ACPI_H_
#define CDK2_ABI_ACPI_H_

#include <uefi.h>

typedef struct {
	UINT32 signature;
	UINT32 length;
	UINT8 revision;
	UINT8 checksum;
	UINT8 oem_id[6];
	UINT64 oem_table_id;
	UINT32 oem_revision;
	UINT32 creator_id;
	UINT32 creator_revision;
} __packed EFI_ACPI_DESCRIPTION_HEADER;

typedef struct {
	UINT8 address_space_id;
	UINT8 register_bit_width;
	UINT8 register_bit_offset;
	UINT8 access_size;
	UINT64 address;
} __packed EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE;

typedef struct {
	UINT64 signature;
	UINT8 checksum;
	UINT8 oem_id[6];
	UINT8 revision;
	UINT32 rsdt_address;
	UINT32 length;
	UINT64 xsdt_address;
	UINT8 extended_checksum;
	UINT8 reserved[3];
} __packed EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER;

typedef struct {
	EFI_ACPI_DESCRIPTION_HEADER header;
	UINT32 firmware_ctrl;
	UINT32 dsdt;
	UINT8 reserved0;
	UINT8 preferred_pm_profile;
	UINT16 sci_int;
	UINT32 smi_cmd;
	UINT8 acpi_enable;
	UINT8 acpi_disable;
	UINT8 s4_bios_req;
	UINT8 pstate_cnt;
	UINT32 pm1a_evt_blk;
	UINT32 pm1b_evt_blk;
	UINT32 pm1a_cnt_blk;
	UINT32 pm1b_cnt_blk;
	UINT32 pm2_cnt_blk;
	UINT32 pm_tmr_blk;
	UINT32 gpe0_blk;
	UINT32 gpe1_blk;
	UINT8 pm1_evt_len;
	UINT8 pm1_cnt_len;
	UINT8 pm2_cnt_len;
	UINT8 pm_tmr_len;
	UINT8 gpe0_blk_len;
	UINT8 gpe1_blk_len;
	UINT8 gpe1_base;
	UINT8 cst_cnt;
	UINT16 p_lvl2_lat;
	UINT16 p_lvl3_lat;
	UINT16 flush_size;
	UINT16 flush_stride;
	UINT8 duty_offset;
	UINT8 duty_width;
	UINT8 day_alrm;
	UINT8 mon_alrm;
	UINT8 century;
	UINT16 ia_pc_boot_arch;
	UINT8 reserved1;
	UINT32 flags;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE reset_reg;
	UINT8 reset_value;
	UINT8 reserved2[3];
	UINT64 x_firmware_ctrl;
	UINT64 x_dsdt;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_pm1a_evt_blk;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_pm1b_evt_blk;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_pm1a_cnt_blk;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_pm1b_cnt_blk;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_pm2_cnt_blk;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_pm_tmr_blk;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_gpe0_blk;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE x_gpe1_blk;
} __packed EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE;

#define EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE \
	SIGNATURE_64('R', 'S', 'D', ' ', 'P', 'T', 'R', ' ')
#define EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE SIGNATURE_32('R', 'S', 'D', 'T')
#define EFI_ACPI_3_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE \
	SIGNATURE_32('X', 'S', 'D', 'T')
#define EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE SIGNATURE_32('F', 'A', 'C', 'P')
#define EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE SIGNATURE_32('T', 'P', 'M', '2')
#define EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_ALLIANCE_CAPABILITIES_TABLE_SIGNATURE \
	SIGNATURE_32('T', 'C', 'P', 'A')
#define EFI_ACPI_6_6_PCI_EXPRESS_MEMORY_MAPPED_CONFIGURATION_SPACE_BASE_ADDRESS_DESCRIPTION_TABLE_SIGNATURE \
	SIGNATURE_32('M', 'C', 'F', 'G')

#endif
