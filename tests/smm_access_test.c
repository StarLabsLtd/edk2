/* SPDX-License-Identifier: GPL-2.0-only */

#include "../src/modules/smm_access/smm_access.c"

#include <stdio.h>
#include <string.h>

static void *installed_interface;

static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{
	__builtin_ms_va_list arguments;
	const EFI_GUID *guid;

	*handle = (void *)1;
	__builtin_ms_va_start(arguments, handle);
	guid = __builtin_va_arg(arguments, const EFI_GUID *);
	installed_interface = __builtin_va_arg(arguments, void *);
	__builtin_ms_va_end(arguments);
	return guid == &smm_access2_guid ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "smm-access test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct boot_services_view boot;
	struct system_table_view system;
	struct config_table table;
	struct {
		struct guid_hob guid_hob;
		EFI_SMRAM_HOB_DESCRIPTOR_BLOCK block;
		struct hob_header end;
	} hobs;
	EFI_SMRAM_DESCRIPTOR map;
	UINTN map_size;
	int failures = 0;

	memset(&boot, 0, sizeof(boot));
	memset(&system, 0, sizeof(system));
	memset(&hobs, 0, sizeof(hobs));
	boot.install_multiple = install_multiple;
	hobs.guid_hob.header.type = HOB_TYPE_GUID_EXTENSION;
	hobs.guid_hob.header.length = sizeof(hobs.guid_hob) + sizeof(hobs.block);
	hobs.guid_hob.name = smram_memory_guid;
	hobs.block.number_of_smm_reserved_regions = 1;
	hobs.block.descriptor[0].physical_start = 0x1ff00000;
	hobs.block.descriptor[0].cpu_start = 0x1ff00000;
	hobs.block.descriptor[0].physical_size = 0x100000;
	hobs.end.type = HOB_TYPE_END_OF_LIST;
	hobs.end.length = sizeof(hobs.end);
	table.guid = hob_list_guid;
	table.table = &hobs;
	system.boot_services = &boot;
	system.table_count = 1;
	system.tables = &table;

	failures += expect(cdk2_smm_access_entry(NULL, NULL) == EFI_INVALID_PARAMETER,
		"NULL system table was accepted");
	system.table_count = 0;
	failures += expect(cdk2_smm_access_entry(NULL, &system) == EFI_NOT_FOUND,
		"missing SMRAM HOB was accepted");
	system.table_count = 1;
	failures += expect(cdk2_smm_access_entry(NULL, &system) == EFI_SUCCESS,
		"entry failed");
	failures += expect(installed_interface == &smm_access,
		"SMM Access protocol was not installed");

	map_size = 0;
	failures += expect(smm_access.get_capabilities(&smm_access, &map_size, NULL) ==
		EFI_BUFFER_TOO_SMALL && map_size == sizeof(map),
		"capability sizing is wrong");
	failures += expect(smm_access.get_capabilities(&smm_access, &map_size, &map) ==
		EFI_SUCCESS && map.physical_start == 0x1ff00000 &&
		map.physical_size == 0x100000 &&
		(map.region_state & (EFI_SMRAM_CLOSED | EFI_CACHEABLE)) ==
		(EFI_SMRAM_CLOSED | EFI_CACHEABLE), "SMRAM descriptor is wrong");
	failures += expect(smm_access.open(&smm_access) == EFI_SUCCESS &&
		smm_access.open_state == TRUE &&
		(descriptors[0].region_state & EFI_SMRAM_OPEN) != 0U,
		"SMRAM open failed");
	failures += expect(smm_access.lock(&smm_access) == EFI_DEVICE_ERROR,
		"open SMRAM was locked");
	failures += expect(smm_access.close(&smm_access) == EFI_SUCCESS &&
		smm_access.open_state == FALSE &&
		(descriptors[0].region_state & EFI_ALLOCATED) != 0U,
		"SMRAM close failed");
	failures += expect(smm_access.close(&smm_access) == EFI_DEVICE_ERROR,
		"closed SMRAM was closed again");
	failures += expect(smm_access.lock(&smm_access) == EFI_SUCCESS &&
		smm_access.lock_state == TRUE, "SMRAM lock failed");
	failures += expect(smm_access.open(&smm_access) == EFI_DEVICE_ERROR,
		"locked SMRAM was opened");

	hobs.guid_hob.header.length = sizeof(hobs.guid_hob) +
		OFFSET_OF(EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, descriptor);
	failures += expect(cdk2_smm_access_entry(NULL, &system) == EFI_COMPROMISED_DATA,
		"truncated descriptor block was accepted");
	return failures == 0 ? 0 : 1;
}
