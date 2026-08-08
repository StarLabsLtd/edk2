/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_service.h>
#include <cdk2/tpm2_acpi_table.h>

typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);

struct boot_services_view {
	UINT8 before_locate_protocol[320];
	locate_protocol_fn *locate_protocol;
};

struct system_table_view {
	UINT8 before_boot_services[96];
	struct boot_services_view *boot_services;
	UINTN table_count;
	struct cdk2_config_table_view *tables;
};

typedef char locate_protocol_offset_check[
	OFFSET_OF(struct boot_services_view, locate_protocol) == 320 ? 1 : -1];
typedef char boot_services_offset_check[
	OFFSET_OF(struct system_table_view, boot_services) == 96 ? 1 : -1];

static const EFI_GUID acpi_table_protocol_guid = {
	0xffe06bdd, 0x6107, 0x46a6,
	{ 0x7b, 0xb2, 0x5a, 0x9c, 0x7e, 0xc5, 0x27, 0x5c }
};
static const EFI_GUID acpi_sdt_protocol_guid = {
	0xeb97088e, 0xc6df, 0x49cf,
	{ 0xbe, 0x4b, 0xd9, 0x06, 0xa5, 0xb2, 0x0e, 0x86 }
};
static const EFI_GUID tcg2_protocol_guid = {
	0x607f766c, 0x7455, 0x42be,
	{ 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }
};
static const EFI_GUID acpi20_table_guid = {
	0x8868e871, 0xe4f1, 0x11d3,
	{ 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 }
};

static struct cdk2_acpi_table_protocol *acpi_table;
static struct cdk2_acpi_sdt_protocol *acpi_sdt;

static BOOLEAN guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left;
	const UINT8 *b = (const UINT8 *)right;
	UINTN index;
	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return FALSE;
	return TRUE;
}

static BOOLEAN checksum_ok(const void *data, UINT32 size)
{
	const UINT8 *bytes = data;
	UINT8 sum = 0;
	UINT32 index;
	for (index = 0; index < size; index++)
		sum = (UINT8)(sum + bytes[index]);
	return sum == 0;
}

EFI_STATUS cdk2_tpm2_acpi_find_config(
	const struct cdk2_config_table_view *tables, UINTN table_count,
	const EFI_ACPI_DESCRIPTION_HEADER **platform,
	const EFI_TPM2_ACPI_TABLE **tpm2)
{
	const EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *rsdp = NULL;
	const EFI_ACPI_DESCRIPTION_HEADER *xsdt;
	const EFI_ACPI_DESCRIPTION_HEADER *header;
	const UINT64 *entries;
	UINTN count;
	UINTN index;

	if (tables == NULL || platform == NULL || tpm2 == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < table_count; index++)
		if (guid_equal(&tables[index].guid, &acpi20_table_guid))
			rsdp = tables[index].table;
	if (rsdp == NULL || rsdp->signature !=
	    EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE ||
	    rsdp->length != sizeof(*rsdp) || rsdp->xsdt_address == 0 ||
	    !checksum_ok(rsdp, 20) || !checksum_ok(rsdp, rsdp->length))
		return EFI_COMPROMISED_DATA;
	xsdt = (const void *)(UINTN)rsdp->xsdt_address;
	if (xsdt->signature != EFI_ACPI_3_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE ||
	    xsdt->length < sizeof(*xsdt) || xsdt->length > 1024U * 1024U ||
	    !checksum_ok(xsdt, xsdt->length))
		return EFI_COMPROMISED_DATA;
	*platform = xsdt;
	entries = (const UINT64 *)(xsdt + 1);
	count = (xsdt->length - sizeof(*xsdt)) / sizeof(*entries);
	for (index = 0; index < count; index++) {
		header = (const void *)(UINTN)entries[index];
		if (header->signature ==
		    EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE &&
		    header->length >= sizeof(EFI_TPM2_ACPI_TABLE) &&
		    header->length <= 1024U * 1024U && checksum_ok(header, header->length)) {
			*tpm2 = (const EFI_TPM2_ACPI_TABLE *)header;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI get_table(UINTN index,
	cdk2_acpi_header_ptr table, cdk2_uintn_ptr key)
{
	UINT32 version;
	return acpi_sdt->get_table(index, table, &version, key);
}

static EFI_STATUS CDK2_MS_ABI uninstall_table(UINTN key)
{
	return acpi_table->uninstall(key);
}

static EFI_STATUS CDK2_MS_ABI install_table(const void *table, UINTN size,
	cdk2_uintn_ptr key)
{
	return acpi_table->install(table, size, key);
}

static EFI_STATUS install_from_protocols(cdk2_tcg2_protocol_ptr tcg2,
	struct cdk2_acpi_table_protocol *table_protocol,
	struct cdk2_acpi_sdt_protocol *sdt_protocol,
	const EFI_ACPI_DESCRIPTION_HEADER *fallback_platform,
	const EFI_TPM2_ACPI_TABLE *fallback_tpm2)
{
	const struct cdk2_tcg2_service *tcg2_service;
	const EFI_ACPI_DESCRIPTION_HEADER *platform = NULL;
	const EFI_TPM2_ACPI_TABLE *existing = NULL;
	struct cdk2_acpi_table_services services = {
		.get_table = get_table,
		.uninstall_table = uninstall_table,
		.install_table = install_table,
	};
	EFI_ACPI_DESCRIPTION_HEADER *header;
	struct cdk2_tpm2_acpi_info info;
	UINTN table_key;
	UINTN key;
	UINTN index;
	UINT32 version;
	EFI_STATUS status;

	if (tcg2 == NULL || table_protocol == NULL || sdt_protocol == NULL)
		return EFI_INVALID_PARAMETER;
	acpi_table = table_protocol;
	acpi_sdt = sdt_protocol;
	for (index = 0; !EFI_ERROR(acpi_sdt->get_table(index, &header,
	     &version, &key)); index++) {
		if (header == NULL || header->length < sizeof(*header))
			return EFI_COMPROMISED_DATA;
		if (platform == NULL)
			platform = header;
		if (header->signature ==
		    EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE &&
		    header->length >= sizeof(EFI_TPM2_ACPI_TABLE))
			existing = (const EFI_TPM2_ACPI_TABLE *)header;
	}
	if (platform == NULL)
		platform = fallback_platform;
	if (existing == NULL)
		existing = fallback_tpm2;
	if (platform == NULL || existing == NULL)
		return EFI_NOT_FOUND;
	tcg2_service = (const struct cdk2_tcg2_service *)tcg2;
	status = cdk2_tpm2_acpi_from_export(&tcg2_service->export,
		platform, existing, &info);
	if (EFI_ERROR(status))
		return status;
	return cdk2_tpm2_acpi_replace(&info, &services, &table_key);
}

EFI_STATUS cdk2_tpm2_acpi_install_from_protocols(cdk2_tcg2_protocol_ptr tcg2,
	struct cdk2_acpi_table_protocol *table_protocol,
	struct cdk2_acpi_sdt_protocol *sdt_protocol)
{
	return install_from_protocols(tcg2, table_protocol, sdt_protocol, NULL, NULL);
}

EFI_STATUS CDK2_MS_ABI cdk2_tpm2_acpi_entry(void *image,
	struct system_table_view *system)
{
	EFI_TCG2_PROTOCOL *tcg2;
	const EFI_ACPI_DESCRIPTION_HEADER *platform = NULL;
	const EFI_TPM2_ACPI_TABLE *existing = NULL;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	status = system->boot_services->locate_protocol(&acpi_table_protocol_guid,
		NULL, (void **)&acpi_table);
	if (EFI_ERROR(status))
		return status;
	status = system->boot_services->locate_protocol(&acpi_sdt_protocol_guid,
		NULL, (void **)&acpi_sdt);
	if (EFI_ERROR(status))
		return status;
	status = system->boot_services->locate_protocol(&tcg2_protocol_guid,
		NULL, (void **)&tcg2);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_tpm2_acpi_find_config(system->tables, system->table_count,
		&platform, &existing);
	if (EFI_ERROR(status) && status != EFI_NOT_FOUND)
		return status;
	return install_from_protocols(tcg2, acpi_table, acpi_sdt, platform, existing);
}
