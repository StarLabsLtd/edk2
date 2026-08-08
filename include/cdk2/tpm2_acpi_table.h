/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TPM2_ACPI_TABLE_H_
#define CDK2_TPM2_ACPI_TABLE_H_

#include <industry_standard/tpm2_acpi.h>
#include <protocol/tcg2.h>

struct cdk2_tcg2_acpi_export;
struct cdk2_config_table_view { EFI_GUID guid; void *table; };
typedef EFI_ACPI_DESCRIPTION_HEADER * cdk2_acpi_header_ptr[1];
typedef UINTN cdk2_uintn_ptr[1];
typedef UINT32 cdk2_uint32_ptr[1];
typedef EFI_TCG2_PROTOCOL cdk2_tcg2_protocol_ptr[1];

#define CDK2_TPM2_ACPI_INTERFACE_TIS 0U
#define CDK2_TPM2_ACPI_INTERFACE_CRB 1U
#define CDK2_TPM2_START_METHOD_TIS 6U
#define CDK2_TPM2_START_METHOD_CRB 7U
#define CDK2_TPM2_CRB_CONTROL_AREA_OFFSET 0x40U

struct cdk2_tpm2_acpi_info {
	UINT8 revision;
	UINT8 platform_class;
	UINT8 interface_type;
	UINT8 reserved;
	UINT8 oem_id[6];
	UINT16 reserved2;
	UINT64 oem_table_id;
	UINT32 oem_revision;
	UINT32 creator_id;
	UINT32 creator_revision;
	UINT64 tpm_base;
	UINT32 event_log_length;
	UINT32 reserved3;
	UINT64 event_log_address;
};

struct cdk2_tpm2_acpi_table {
	EFI_TPM2_ACPI_TABLE table;
	UINT8 parameters[EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_4];
	UINT32 event_log_length;
	UINT64 event_log_address;
} __packed;

typedef EFI_STATUS CDK2_MS_ABI cdk2_acpi_get_table_fn(UINTN index,
	cdk2_acpi_header_ptr table, cdk2_uintn_ptr table_key);
typedef EFI_STATUS CDK2_MS_ABI cdk2_acpi_uninstall_table_fn(UINTN table_key);
typedef EFI_STATUS CDK2_MS_ABI cdk2_acpi_install_table_fn(const void *table,
	UINTN size, cdk2_uintn_ptr table_key);
typedef EFI_STATUS CDK2_MS_ABI cdk2_acpi_sdt_get_table_fn(UINTN index,
	cdk2_acpi_header_ptr table, cdk2_uint32_ptr version,
	cdk2_uintn_ptr table_key);

struct cdk2_acpi_table_services {
	cdk2_acpi_get_table_fn *get_table;
	cdk2_acpi_uninstall_table_fn *uninstall_table;
	cdk2_acpi_install_table_fn *install_table;
};

struct cdk2_acpi_table_protocol {
	cdk2_acpi_install_table_fn *install;
	cdk2_acpi_uninstall_table_fn *uninstall;
};

struct cdk2_acpi_sdt_protocol {
	cdk2_acpi_sdt_get_table_fn *get_table;
};

EFI_STATUS cdk2_tpm2_acpi_build(const struct cdk2_tpm2_acpi_info *info,
	struct cdk2_tpm2_acpi_table *table);
EFI_STATUS cdk2_tpm2_acpi_replace(const struct cdk2_tpm2_acpi_info *info,
	const struct cdk2_acpi_table_services *services, UINTN *table_key);
EFI_STATUS cdk2_tpm2_acpi_from_export(const struct cdk2_tcg2_acpi_export *export,
	const EFI_ACPI_DESCRIPTION_HEADER *platform_table,
	const EFI_TPM2_ACPI_TABLE *existing, struct cdk2_tpm2_acpi_info *info);
EFI_STATUS cdk2_tpm2_acpi_install_from_protocols(cdk2_tcg2_protocol_ptr tcg2,
	struct cdk2_acpi_table_protocol *table_protocol,
	struct cdk2_acpi_sdt_protocol *sdt_protocol);
EFI_STATUS cdk2_tpm2_acpi_find_config(
	const struct cdk2_config_table_view *tables, UINTN table_count,
	const EFI_ACPI_DESCRIPTION_HEADER **platform,
	const EFI_TPM2_ACPI_TABLE **tpm2);

#endif
