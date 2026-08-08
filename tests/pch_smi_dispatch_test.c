/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#define CDK2_PCH_SMI_DISPATCH_TEST
#include "../src/modules/pch_smi_dispatch/pch_smi_dispatch.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static UINT8 ports8[0x10000];
static UINT32 status_value;
static UINT32 enable_value;
static UINTN child_calls;
static UINTN child_cpu;
static UINT8 child_data;
static UINTN save_state_calls;
static cdk2_smm_handler *root_handler;
static void *installed_interface;

UINT8 cdk2_pch_smi_test_in8(UINT16 port)
{
	return ports8[port];
}

UINT32 cdk2_pch_smi_test_in32(UINT16 port)
{
	return port == 0x630U ? status_value : enable_value;
}

void cdk2_pch_smi_test_out32(UINT16 port, UINT32 value)
{
	if (port == 0x630U)
		status_value = value;
	else
		enable_value = value;
}

static EFI_STATUS CDK2_MS_ABI mock_allocate(EFI_MEMORY_TYPE type, UINTN size,
	void **buffer)
{
	(void)type;
	*buffer = calloc(1, (size_t)size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_free(void *buffer)
{
	free(buffer);
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_read_save_state(
	const struct smm_cpu_protocol *protocol, UINTN width, UINT32 reg,
	UINTN cpu_index, void *buffer)
{
	struct smm_save_state_io_info *io = buffer;
	(void)protocol;
	(void)width;
	(void)reg;
	save_state_calls++;
	if (cpu_index != 2U)
		return EFI_NOT_FOUND;
	memset(io, 0, sizeof(*io));
	io->io_port = SMM_CONTROL_PORT;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_smm_locate(const EFI_GUID *guid,
	void *registration, void **protocol)
{
	static struct smm_cpu_protocol cpu = { mock_read_save_state, NULL };
	(void)registration;
	if (!guid_equal(guid, &smm_cpu_guid))
		return EFI_NOT_FOUND;
	*protocol = &cpu;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_register_root(cdk2_smm_handler *handler,
	const EFI_GUID *handler_type, void **dispatch_handle)
{
	(void)handler_type;
	root_handler = handler;
	*dispatch_handle = (void *)0x1111;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_install(void **handle, const EFI_GUID *guid,
	UINT32 interface_type, void *interface)
{
	(void)guid;
	(void)interface_type;
	installed_interface = interface;
	*handle = (void *)0x2222;
	return EFI_SUCCESS;
}

static struct smm_system_table mock_smst;

static EFI_STATUS CDK2_MS_ABI mock_get_smst(const struct smm_base_protocol *protocol,
	struct smm_system_table **table)
{
	(void)protocol;
	*table = &mock_smst;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_boot_locate(const EFI_GUID *guid,
	void *registration, void **protocol)
{
	static struct smm_base_protocol base = { NULL, mock_get_smst };
	(void)registration;
	if (!guid_equal(guid, &smm_base_guid))
		return EFI_NOT_FOUND;
	*protocol = &base;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI child_handler(void *dispatch_handle,
	const void *register_context, void *communication_buffer,
	UINTN *communication_buffer_size)
{
	const struct cdk2_smm_sw_register_context *reg = register_context;
	const struct cdk2_smm_sw_context *sw = communication_buffer;
	(void)dispatch_handle;
	if (reg->sw_smi_input_value != 0x42U ||
	    *communication_buffer_size != sizeof(*sw))
		return EFI_COMPROMISED_DATA;
	child_calls++;
	child_cpu = sw->sw_smi_cpu_index;
	child_data = sw->data_port;
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
	struct config_table table = {0};
	struct system_table_view system = {0};
	struct cdk2_smm_sw_register_context context = { 0x42U };
	struct cdk2_smm_sw_register_context automatic = { CDK2_SMM_SW_SMI_AUTO };
	struct cdk2_smm_sw_dispatch2_protocol *protocol;
	void *handle = NULL;
	void *auto_handle = NULL;
	int failures = 0;

	list.hob.header.type = HOB_TYPE_GUID_EXTENSION;
	list.hob.header.length = sizeof(list.hob) + sizeof(list.info) + sizeof(list.registers);
	list.hob.name = register_info_guid;
	list.info.revision = CDK2_SMM_REGISTER_INFO_REVISION;
	list.info.count = 2;
	list.registers[0].id = CDK2_SMM_REGISTER_ID_APM_STATUS;
	list.registers[0].value = 1;
	list.registers[0].address.address_space_id = CDK2_ACPI_SYSTEM_IO;
	list.registers[0].address.register_bit_width = 1;
	list.registers[0].address.register_bit_offset = 5;
	list.registers[0].address.access_size = CDK2_ACPI_ACCESS_DWORD;
	list.registers[0].address.address = 0x630;
	list.registers[1] = list.registers[0];
	list.registers[1].id = CDK2_SMM_REGISTER_ID_EOS;
	list.registers[1].address.register_bit_offset = 1;
	list.registers[1].address.address = 0x634;
	list.end.type = HOB_TYPE_END_OF_LIST;
	list.end.length = sizeof(list.end);
	table.guid = hob_list_guid;
	table.table = &list;
	boot.locate_protocol = mock_boot_locate;
	system.boot_services = &boot;
	system.table_count = 1;
	system.tables = &table;
	mock_smst.allocate_pool = mock_allocate;
	mock_smst.free_pool = mock_free;
	mock_smst.number_of_cpus = 4;
	mock_smst.locate_protocol = mock_smm_locate;
	mock_smst.register_smi_handler = mock_register_root;
	mock_smst.install_protocol = mock_install;

	failures += expect(cdk2_pch_smi_dispatch_entry(NULL, &system) == EFI_SUCCESS,
		"valid dispatcher entry rejected");
	failures += expect(root_handler != NULL && installed_interface != NULL,
		"root handler or dispatch protocol not installed");
	protocol = installed_interface;
	failures += expect(protocol->maximum_swi_value == CDK2_SMM_SW_SMI_MAX,
		"incorrect maximum software SMI value");
	failures += expect(protocol->register_handler(protocol, child_handler, &context,
		&handle) == EFI_SUCCESS && handle != NULL, "explicit handler registration failed");
	failures += expect(protocol->register_handler(protocol, child_handler, &context,
		&auto_handle) == EFI_INVALID_PARAMETER, "duplicate software SMI accepted");
	failures += expect(protocol->register_handler(protocol, child_handler, &automatic,
		&auto_handle) == EFI_SUCCESS && automatic.sw_smi_input_value == 1U,
		"automatic software SMI allocation failed");
	ports8[SMM_CONTROL_PORT] = 0x42;
	ports8[SMM_DATA_PORT] = 0x5a;
	status_value = BIT7;
	enable_value = BIT3;
	failures += expect(root_handler(root_dispatch_handle, NULL, NULL, NULL) == EFI_SUCCESS,
		"root dispatcher failed");
	failures += expect(child_calls == 1 && child_cpu == 2U && child_data == 0x5a,
		"child did not receive complete software-SMI context");
	failures += expect(save_state_calls == 3, "triggering CPU search was incomplete");
	failures += expect(status_value == (BIT7 | BIT5) && enable_value == (BIT3 | BIT1),
		"APM status clear or EOS update was not issued");
	failures += expect(protocol->unregister_handler(protocol, handle) == EFI_SUCCESS,
		"valid unregister failed");
	failures += expect(protocol->unregister_handler(protocol, handle) == EFI_INVALID_PARAMETER,
		"stale dispatch handle accepted");
	ports8[SMM_CONTROL_PORT] = 0;
	failures += expect(root_handler(root_dispatch_handle, NULL, NULL, NULL) == EFI_SUCCESS,
		"non-software SMI handling failed");
	failures += expect(child_calls == 1, "zero command dispatched a child handler");
	list.info.count = CDK2_SMM_REGISTER_MAX_COUNT + 1;
	failures += expect(cdk2_pch_smi_dispatch_entry(NULL, &system) == EFI_COMPROMISED_DATA,
		"oversized register list accepted");

	if (failures == 0)
		puts("native PCH SMI dispatch test: PASS");
	return failures != 0;
}
