/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#define CDK2_SMM_CONTROL_TEST
#include "../src/modules/smm_control/smm_control.c"

#include <stdio.h>
#include <string.h>

static UINT32 io_value;
static UINT16 last_port;
static UINT8 last_data;
static UINTN install_calls;
static UINTN event_calls;
static UINTN convert_calls;

UINT32 cdk2_smm_control_test_in32(UINT16 port)
{
	last_port = port;
	return io_value;
}

void cdk2_smm_control_test_out32(UINT16 port, UINT32 value)
{
	last_port = port;
	io_value = value;
}

void cdk2_smm_control_test_out8(UINT16 port, UINT8 value)
{
	last_port = port;
	last_data = value;
}

static EFI_STATUS CDK2_MS_ABI mock_install(void **handle, ...)
{
	install_calls++;
	*handle = (void *)0x1234;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_create_event(UINT32 type, UINTN tpl,
	event_notify_function notify, void *context, cdk2_guid_const_ptr group,
	cdk2_void_ptr_ptr event)
{
	(void)type;
	(void)tpl;
	(void)notify;
	(void)context;
	(void)group;
	event_calls++;
	*event = (void *)0x5678;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_convert(UINTN disposition, void **address)
{
	(void)disposition;
	(void)address;
	convert_calls++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "FAIL: %s\n", message);
	return condition ? 0 : 1;
}

int main(void)
{
	struct {
		struct guid_hob hob;
		struct cdk2_smm_register_info info;
		struct cdk2_smm_generic_register registers[2];
		struct hob_header end;
	} __packed list = {0};
	struct boot_services_view boot = {0};
	struct runtime_services_view runtime = {0};
	struct config_table table = {0};
	struct system_table_view system = {0};
	UINT8 command = 0xed;
	UINT8 data = 0x5a;
	int failures = 0;

	list.hob.header.type = HOB_TYPE_GUID_EXTENSION;
	list.hob.header.length = sizeof(list.hob) + sizeof(list.info) +
		sizeof(list.registers);
	list.hob.name = smm_register_info_guid;
	list.info.revision = CDK2_SMM_REGISTER_INFO_REVISION;
	list.info.count = 2;
	list.registers[0].id = CDK2_SMM_REGISTER_ID_GLOBAL_ENABLE;
	list.registers[0].value = 1;
	list.registers[0].address.address_space_id = CDK2_ACPI_SYSTEM_IO;
	list.registers[0].address.register_bit_width = 1;
	list.registers[0].address.register_bit_offset = 0;
	list.registers[0].address.access_size = CDK2_ACPI_ACCESS_DWORD;
	list.registers[0].address.address = 0x630;
	list.registers[1] = list.registers[0];
	list.registers[1].id = CDK2_SMM_REGISTER_ID_APM_ENABLE;
	list.registers[1].address.register_bit_offset = 5;
	list.end.type = HOB_TYPE_END_OF_LIST;
	list.end.length = sizeof(list.end);
	table.guid = hob_list_guid;
	table.table = &list;
	boot.install_multiple = mock_install;
	boot.create_event_ex = mock_create_event;
	runtime.convert_pointer = mock_convert;
	system.boot_services = &boot;
	system.runtime_services = &runtime;
	system.table_count = 1;
	system.tables = &table;

	failures += expect(cdk2_smm_control_entry(NULL, &system) == EFI_SUCCESS,
		"valid register HOB rejected");
	failures += expect(install_calls == 1 && event_calls == 1,
		"protocol/event were not installed");
	io_value = 0;
	failures += expect(smm_control.trigger(&smm_control, &command, &data, FALSE, 0) ==
		EFI_SUCCESS, "trigger failed");
	failures += expect(io_value == (BIT0 | BIT5), "SMI enable bits not set");
	failures += expect(last_port == SMM_CONTROL_PORT && last_data == command,
		"software SMI command not written");
	failures += expect(smm_control.trigger(&smm_control, NULL, NULL, TRUE, 0) ==
		EFI_INVALID_PARAMETER, "periodic trigger accepted");
	failures += expect(smm_control.clear(&smm_control, TRUE) == EFI_INVALID_PARAMETER,
		"periodic clear accepted");
	virtual_address_change(NULL, NULL);
	failures += expect(convert_calls == 2, "runtime pointers not converted");

	list.registers[1].address.address = 0x631;
	failures += expect(cdk2_smm_control_entry(NULL, &system) == EFI_UNSUPPORTED,
		"mismatched enable registers accepted");
	list.registers[1].address.address = 0x630;
	list.info.count = CDK2_SMM_REGISTER_MAX_COUNT + 1;
	failures += expect(cdk2_smm_control_entry(NULL, &system) == EFI_COMPROMISED_DATA,
		"oversized register count accepted");

	if (failures == 0)
		puts("native SMM Control test: PASS");
	return failures != 0;
}
