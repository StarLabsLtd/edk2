/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Construct and replace the TPM2 ACPI table without platform register policy. */

#include <cdk2/tpm2_acpi_table.h>
#include <cdk2/tcg2_service.h>

static void zero_bytes(void *buffer, UINTN size)
{
	UINT8 *bytes = buffer;
	UINTN index;
	for (index = 0; index < size; index++)
		bytes[index] = 0;
}

static void copy_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *out = destination;
	const UINT8 *in = source;
	UINTN index;
	for (index = 0; index < size; index++)
		out[index] = in[index];
}

static UINT8 checksum8(const void *buffer, UINTN size)
{
	const UINT8 *bytes = buffer;
	UINT8 sum = 0;
	UINTN index;
	for (index = 0; index < size; index++)
		sum = (UINT8)(sum + bytes[index]);
	return (UINT8)(0U - sum);
}

EFI_STATUS cdk2_tpm2_acpi_from_export(const struct cdk2_tcg2_acpi_export *export,
	const EFI_ACPI_DESCRIPTION_HEADER *platform_table,
	const EFI_TPM2_ACPI_TABLE *existing, struct cdk2_tpm2_acpi_info *info)
{
	if (export == NULL || platform_table == NULL || existing == NULL || info == NULL)
		return EFI_INVALID_PARAMETER;
	if (export->revision != CDK2_TCG2_EXPORT_REVISION ||
	    export->size != sizeof(*export) || export->reserved2 != 0 ||
	    export->log_base == 0 || export->log_capacity == 0 ||
	    export->tpm_base == 0 || export->active_interface > 1 ||
	    existing->header.length < sizeof(*existing))
		return EFI_COMPROMISED_DATA;
	*info = (struct cdk2_tpm2_acpi_info){
		.revision = EFI_TPM2_ACPI_TABLE_REVISION_4,
		.platform_class = (UINT8)existing->flags,
		.interface_type = export->active_interface,
		.oem_table_id = platform_table->oem_table_id,
		.oem_revision = platform_table->oem_revision,
		.creator_id = platform_table->creator_id,
		.creator_revision = platform_table->creator_revision,
		.tpm_base = export->tpm_base,
		.event_log_length = export->log_capacity,
		.event_log_address = export->log_base,
	};
	copy_bytes(info->oem_id, platform_table->oem_id, sizeof(info->oem_id));
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_acpi_build(const struct cdk2_tpm2_acpi_info *info,
	struct cdk2_tpm2_acpi_table *table)
{
	if (info == NULL || table == NULL)
		return EFI_INVALID_PARAMETER;
	if (info->reserved != 0U || info->reserved2 != 0U || info->reserved3 != 0U)
		return EFI_COMPROMISED_DATA;
	if (info->event_log_length == 0U || info->event_log_address == 0U)
		return EFI_NOT_READY;
	if (info->interface_type == CDK2_TPM2_ACPI_INTERFACE_CRB &&
	    info->tpm_base > MAX_UINT64 - CDK2_TPM2_CRB_CONTROL_AREA_OFFSET)
		return EFI_COMPROMISED_DATA;

	zero_bytes(table, sizeof(*table));
	table->table.header.signature =
		EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE;
	table->table.header.length = sizeof(*table);
	/* The admitted driver clamps every configured revision to revision 4. */
	table->table.header.revision = EFI_TPM2_ACPI_TABLE_REVISION_4;
	copy_bytes(table->table.header.oem_id, info->oem_id,
		sizeof(table->table.header.oem_id));
	table->table.header.oem_table_id = info->oem_table_id;
	table->table.header.oem_revision = info->oem_revision;
	table->table.header.creator_id = info->creator_id;
	table->table.header.creator_revision = info->creator_revision;
	table->table.flags = info->platform_class;
	if (info->interface_type == CDK2_TPM2_ACPI_INTERFACE_CRB) {
		table->table.address_of_control_area =
			info->tpm_base + CDK2_TPM2_CRB_CONTROL_AREA_OFFSET;
		table->table.start_method = CDK2_TPM2_START_METHOD_CRB;
	} else {
		table->table.start_method = CDK2_TPM2_START_METHOD_TIS;
	}
	table->event_log_length = info->event_log_length;
	table->event_log_address = info->event_log_address;
	table->table.header.checksum = checksum8(table, sizeof(*table));
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_acpi_replace(const struct cdk2_tpm2_acpi_info *info,
	const struct cdk2_acpi_table_services *services, UINTN *table_key)
{
	struct cdk2_tpm2_acpi_table table;
	EFI_ACPI_DESCRIPTION_HEADER *existing;
	UINTN existing_key;
	UINTN index = 0;
	EFI_STATUS status;

	if (services == NULL || services->get_table == NULL ||
	    services->uninstall_table == NULL || services->install_table == NULL ||
	    table_key == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_tpm2_acpi_build(info, &table);
	if (EFI_ERROR(status))
		return status;
	while (!EFI_ERROR(services->get_table(index, &existing, &existing_key))) {
		if (existing == NULL)
			return EFI_COMPROMISED_DATA;
		if (existing->signature !=
		    EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE) {
			index++;
			continue;
		}
		status = services->uninstall_table(existing_key);
		if (EFI_ERROR(status))
			index++;
	}
	*table_key = 0;
	return services->install_table(&table, sizeof(table), table_key);
}
