/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TPM2_ACPI_TABLE_H_
#define CDK2_TPM2_ACPI_TABLE_H_

#include <industry_standard/tpm2_acpi.h>
#include <protocol/tcg2.h>

struct cdk2_tcg2_acpi_export;

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

struct cdk2_acpi_table_services {
	EFI_STATUS (*get_table)(UINTN index, EFI_ACPI_DESCRIPTION_HEADER **table,
		UINTN *table_key) CDK2_MS_ABI;
	EFI_STATUS (*uninstall_table)(UINTN table_key) CDK2_MS_ABI;
	EFI_STATUS (*install_table)(const void *table, UINTN size,
		UINTN *table_key) CDK2_MS_ABI;
};

struct cdk2_acpi_table_protocol {
	EFI_STATUS (CDK2_MS_ABI *install)(const void *table, UINTN size,
		UINTN *table_key);
	EFI_STATUS (CDK2_MS_ABI *uninstall)(UINTN table_key);
};

struct cdk2_acpi_sdt_protocol {
	EFI_STATUS (CDK2_MS_ABI *get_table)(UINTN index,
		EFI_ACPI_DESCRIPTION_HEADER **table, UINT32 *version, UINTN *table_key);
};

EFI_STATUS cdk2_tpm2_acpi_build(const struct cdk2_tpm2_acpi_info *info,
	struct cdk2_tpm2_acpi_table *table);
EFI_STATUS cdk2_tpm2_acpi_replace(const struct cdk2_tpm2_acpi_info *info,
	const struct cdk2_acpi_table_services *services, UINTN *table_key);
EFI_STATUS cdk2_tpm2_acpi_from_export(const struct cdk2_tcg2_acpi_export *export,
	const EFI_ACPI_DESCRIPTION_HEADER *platform_table,
	const EFI_TPM2_ACPI_TABLE *existing, struct cdk2_tpm2_acpi_info *info);

#endif
