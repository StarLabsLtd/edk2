/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Construct and replace the TPM2 ACPI table without platform register policy. */

#include <cdk2/tpm2_acpi_table.h>

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

EFI_STATUS cdk2_tpm2_acpi_build(const struct cdk2_tpm2_acpi_info *info,
	struct cdk2_tpm2_acpi_table *table)
{
	if (info == NULL || table == NULL)
		return EFI_INVALID_PARAMETER;
	if (info->reserved != 0U || info->reserved2 != 0U || info->reserved3 != 0U)
		return EFI_COMPROMISED_DATA;
	if (info->event_log_length == 0U || info->event_log_address == 0U)
		return EFI_NOT_READY;
	if (info->interface_type == CDK2_TPM2_INTERFACE_CRB &&
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
	if (info->interface_type == CDK2_TPM2_INTERFACE_CRB) {
		table->table.address_of_control_area =
			info->tpm_base + CDK2_TPM2_CRB_CONTROL_AREA_OFFSET;
		table->table.start_method = CDK2_TPM2_START_METHOD_CRB;
	} else {
		table->table.start_method = CDK2_TPM2_START_METHOD_TIS;
	}
	table->event_log_length = info->event_log_length;
	table->event_log_address = info->event_log_address;
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
