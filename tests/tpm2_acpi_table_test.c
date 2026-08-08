/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tpm2_acpi_table.h>
#include <cdk2/tcg2_service.h>
#include <stdio.h>
#include <string.h>

struct mock_table { EFI_ACPI_DESCRIPTION_HEADER header; UINTN key; };
static struct mock_table tables[4];
static UINTN table_count, fail_key, installed_size;
static EFI_STATUS install_status;
static struct cdk2_tpm2_acpi_table installed;
static EFI_ACPI_DESCRIPTION_HEADER driver_platform;
static EFI_TPM2_ACPI_TABLE driver_tpm;

static EFI_STATUS CDK2_MS_ABI get_table(UINTN index,
	cdk2_acpi_header_ptr table, cdk2_uintn_ptr key)
{
	if (index >= table_count)
		return EFI_NOT_FOUND;
	*table = &tables[index].header; *key = tables[index].key;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI uninstall_table(UINTN key)
{
	UINTN index;
	if (key == fail_key)
		return EFI_DEVICE_ERROR;
	for (index = 0; index < table_count; index++) {
		if (tables[index].key != key)
			continue;
		memmove(&tables[index], &tables[index + 1],
			(table_count - index - 1U) * sizeof(tables[0]));
		table_count--; return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI install_table(const void *table, UINTN size,
	cdk2_uintn_ptr key)
{
	if (size == sizeof(installed))
		memcpy(&installed, table, size);
	installed_size = size; *key = 0x55U; return install_status;
}

static struct cdk2_acpi_table_protocol *seen_table_this;

static EFI_STATUS CDK2_MS_ABI protocol_install(
	struct cdk2_acpi_table_protocol *this, const void *table, UINTN size,
	cdk2_uintn_ptr key)
{
	seen_table_this = this;
	return install_table(table, size, key);
}

static EFI_STATUS CDK2_MS_ABI protocol_uninstall(
	struct cdk2_acpi_table_protocol *this, UINTN key)
{
	seen_table_this = this;
	return uninstall_table(key);
}

static EFI_STATUS CDK2_MS_ABI sdt_get_table(
	UINTN index, cdk2_acpi_header_ptr table, cdk2_uint32_ptr version,
	cdk2_uintn_ptr key)
{
	*version = 0;
	*key = index + 20;
	if (index == 0)
		*table = &driver_platform;
	else if (index == 1)
		*table = &driver_tpm.header;
	else
		return EFI_NOT_FOUND;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "tpm2-acpi-table test: %s\n", message);
	return !condition;
}

static struct cdk2_tpm2_acpi_info valid_info(void)
{
	struct cdk2_tpm2_acpi_info info = {
		.revision = 5, .platform_class = 2,
		.interface_type = CDK2_TPM2_ACPI_INTERFACE_CRB,
		.oem_id = { 'C', 'D', 'K', '2', ' ', ' ' },
		.oem_table_id = 0x1122334455667788ULL, .oem_revision = 3,
		.creator_id = 0x43444b32U, .creator_revision = 7,
		.tpm_base = 0xfed40000U, .event_log_length = 0x10000U,
		.event_log_address = 0x12345000U,
	};
	return info;
}

static void reset_mocks(void)
{
	memset(tables, 0, sizeof(tables)); table_count = 0;
	fail_key = MAX_UINTN; install_status = EFI_SUCCESS; installed_size = 0;
	memset(&installed, 0, sizeof(installed));
}

int main(void)
{
	static const EFI_GUID expected_sdt_guid = {
		0xeb97088e, 0xcfdf, 0x49c6,
		{ 0xbe, 0x4b, 0xd9, 0x06, 0xa5, 0xb2, 0x0e, 0x86 }
	};
	const struct cdk2_acpi_table_services services = {
		.get_table = get_table, .uninstall_table = uninstall_table,
		.install_table = install_table,
	};
	struct cdk2_tpm2_acpi_info info = valid_info();
	struct cdk2_tpm2_acpi_table table;
	UINTN key = 0, index;
	int failures = 0;
	UINT8 checksum = 0;
	failures += expect(memcmp(&cdk2_acpi_sdt_protocol_guid, &expected_sdt_guid,
		sizeof(expected_sdt_guid)) == 0, "ACPI SDT protocol GUID is wrong");

	failures += expect(sizeof(table) == 76U, "revision-4 table size changed");
	failures += expect(cdk2_tpm2_acpi_build(&info, &table) == EFI_SUCCESS,
		"CRB build failed");
	failures += expect(table.table.header.signature ==
		EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE &&
		table.table.header.length == sizeof(table) &&
		table.table.header.revision == EFI_TPM2_ACPI_TABLE_REVISION_4,
		"ACPI identity is wrong");
	failures += expect(memcmp(table.table.header.oem_id, info.oem_id, 6) == 0 &&
		table.table.header.oem_table_id == info.oem_table_id &&
		table.table.header.oem_revision == info.oem_revision &&
		table.table.header.creator_id == info.creator_id &&
		table.table.header.creator_revision == info.creator_revision,
		"OEM metadata is wrong");
	failures += expect(table.table.flags == info.platform_class &&
		table.table.address_of_control_area == info.tpm_base + 0x40U &&
		table.table.start_method == CDK2_TPM2_START_METHOD_CRB,
		"CRB fields are wrong");
	for (index = 0; index < sizeof(table.parameters); index++)
		failures += expect(table.parameters[index] == 0, "parameters not zero");
	failures += expect(table.event_log_length == info.event_log_length &&
		table.event_log_address == info.event_log_address, "event log is wrong");
	for (index = 0; index < sizeof(table); index++)
		checksum = (UINT8)(checksum + ((const UINT8 *)&table)[index]);
	failures += expect(checksum == 0, "ACPI checksum is wrong");
	{
		struct {
			EFI_ACPI_DESCRIPTION_HEADER header;
			UINT64 entry;
		} __packed xsdt = {0};
		EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER rsdp = {0};
		struct cdk2_config_table_view config = {
			.guid = { 0x8868e871, 0xe4f1, 0x11d3,
				{ 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 } },
			.table = &rsdp,
		};
		const EFI_ACPI_DESCRIPTION_HEADER *found_platform = NULL;
		const EFI_TPM2_ACPI_TABLE *found_tpm2 = NULL;
		UINT8 *bytes;
		UINT8 sum;

		xsdt.header.signature =
			EFI_ACPI_3_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE;
		xsdt.header.length = sizeof(xsdt);
		xsdt.entry = (UINT64)(UINTN)&table.table;
		bytes = (UINT8 *)&xsdt;
		for (sum = 0, index = 0; index < sizeof(xsdt); index++)
			sum = (UINT8)(sum + bytes[index]);
		xsdt.header.checksum = (UINT8)(0U - sum);
		rsdp.signature = EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE;
		rsdp.revision = 2;
		rsdp.length = sizeof(rsdp);
		rsdp.xsdt_address = (UINT64)(UINTN)&xsdt;
		bytes = (UINT8 *)&rsdp;
		for (sum = 0, index = 0; index < 20; index++)
			sum = (UINT8)(sum + bytes[index]);
		rsdp.checksum = (UINT8)(0U - sum);
		for (sum = 0, index = 0; index < sizeof(rsdp); index++)
			sum = (UINT8)(sum + bytes[index]);
		rsdp.extended_checksum = (UINT8)(0U - sum);
		failures += expect(cdk2_tpm2_acpi_find_config(&config, 1,
			&found_platform, &found_tpm2) == EFI_SUCCESS &&
			found_platform == &xsdt.header && found_tpm2 == &table.table,
			"XSDT-only TPM2 table was not discovered");
		xsdt.header.checksum++;
		failures += expect(cdk2_tpm2_acpi_find_config(&config, 1,
			&found_platform, &found_tpm2) == EFI_COMPROMISED_DATA,
			"corrupt XSDT checksum was accepted");
	}
	{
		struct cdk2_tcg2_acpi_export export = {
			.revision = CDK2_TCG2_EXPORT_REVISION, .size = sizeof(export),
			.active_interface = 1, .tpm_base = 0xfed40000,
			.log_base = 0x12345000, .log_capacity = 0x10000,
		};
		EFI_ACPI_DESCRIPTION_HEADER platform = table.table.header;
		struct cdk2_tpm2_acpi_info derived;
		failures += expect(cdk2_tpm2_acpi_from_export(&export, &platform,
			&table.table, &derived) == EFI_SUCCESS &&
			derived.interface_type == 1 && derived.tpm_base == export.tpm_base &&
			derived.event_log_address == export.log_base &&
			derived.event_log_length == export.log_capacity &&
			memcmp(derived.oem_id, platform.oem_id, sizeof(derived.oem_id)) == 0,
			"native TCG2 export was not converted authoritatively");
		export.reserved2 = 1;
		failures += expect(cdk2_tpm2_acpi_from_export(&export, &platform,
			&table.table, &derived) == EFI_COMPROMISED_DATA,
			"corrupt native TCG2 export was accepted");
	}

	info.interface_type = CDK2_TPM2_ACPI_INTERFACE_TIS;
	failures += expect(cdk2_tpm2_acpi_build(&info, &table) == EFI_SUCCESS &&
		table.table.start_method == CDK2_TPM2_START_METHOD_TIS &&
		table.table.address_of_control_area == 0, "TIS fields are wrong");
	failures += expect(cdk2_tpm2_acpi_build(NULL, &table) == EFI_INVALID_PARAMETER &&
		cdk2_tpm2_acpi_build(&info, NULL) == EFI_INVALID_PARAMETER,
		"NULL build input accepted");
	info.reserved = 1;
	failures += expect(cdk2_tpm2_acpi_build(&info, &table) == EFI_COMPROMISED_DATA,
		"reserved input accepted");
	info = valid_info(); info.event_log_length = 0;
	failures += expect(cdk2_tpm2_acpi_build(&info, &table) == EFI_NOT_READY,
		"empty event log accepted");
	info = valid_info();
	info.tpm_base = MAX_UINT64 - CDK2_TPM2_CRB_CONTROL_AREA_OFFSET + 1U;
	failures += expect(cdk2_tpm2_acpi_build(&info, &table) == EFI_COMPROMISED_DATA,
		"overflowing CRB base accepted");

	reset_mocks();
	tables[0] = (struct mock_table){ .header.signature = 0x50434146U, .key = 1 };
	tables[1] = (struct mock_table){
		.header.signature = EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE,
		.key = 2 };
	tables[2] = (struct mock_table){
		.header.signature = EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE,
		.key = 3 };
	table_count = 3; info = valid_info();
	failures += expect(cdk2_tpm2_acpi_replace(&info, &services, &key) == EFI_SUCCESS,
		"replacement failed");
	failures += expect(table_count == 1U && tables[0].key == 1U,
		"shifted TPM2 table was skipped");
	failures += expect(installed_size == sizeof(installed) && key == 0x55U &&
		installed.table.start_method == CDK2_TPM2_START_METHOD_CRB,
		"wrong table installed");

	reset_mocks();
	tables[0] = (struct mock_table){
		.header.signature = EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE,
		.key = 9 };
	table_count = 1; fail_key = 9; info = valid_info();
	failures += expect(cdk2_tpm2_acpi_replace(&info, &services, &key) == EFI_SUCCESS &&
		table_count == 1U && installed_size == sizeof(installed),
		"uninstall failure did not advance");
	install_status = EFI_OUT_OF_RESOURCES;
	failures += expect(cdk2_tpm2_acpi_replace(&info, &services, &key) ==
		EFI_OUT_OF_RESOURCES, "install status lost");
	failures += expect(cdk2_tpm2_acpi_replace(&info, NULL, &key) ==
		EFI_INVALID_PARAMETER, "NULL services accepted");
	{
		struct cdk2_tcg2_service native_service = {0};
		struct cdk2_acpi_table_protocol table_protocol = {
			.install = protocol_install, .uninstall = protocol_uninstall,
		};
		struct cdk2_acpi_sdt_protocol sdt_protocol = {
			.acpi_version = 0x510,
			.get_table = sdt_get_table,
		};
		reset_mocks();
		seen_table_this = NULL;
		driver_platform = table.table.header;
		driver_platform.length = sizeof(driver_platform);
		driver_tpm = table.table;
		driver_tpm.header.length = sizeof(driver_tpm);
		native_service.export = (struct cdk2_tcg2_acpi_export){
			.revision = CDK2_TCG2_EXPORT_REVISION,
			.size = sizeof(native_service.export), .active_interface = 1,
			.tpm_base = 0xfed40000, .log_base = 0x22345000,
			.log_capacity = 0x8000,
		};
		failures += expect(cdk2_tpm2_acpi_install_from_protocols(
			&native_service.protocol, &table_protocol, &sdt_protocol) ==
			EFI_SUCCESS && installed.event_log_address == 0x22345000 &&
			installed.event_log_length == 0x8000 &&
			installed.table.start_method == CDK2_TPM2_START_METHOD_CRB,
			"DXE adapter did not consume native TCG2 export");
		failures += expect(seen_table_this == &table_protocol &&
			sdt_protocol.acpi_version == 0x510,
			"ACPI protocol ABI was not preserved");
	}
	return failures == 0 ? 0 : 1;
}
