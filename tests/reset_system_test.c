/* SPDX-License-Identifier: GPL-2.0-only */

#define CDK2_RESET_TEST
#include "../src/modules/reset_system/reset_system.c"

#include <stdio.h>
#include <string.h>

struct io_write {
	UINT16 port;
	UINT16 value;
	UINT8 width;
};

static struct io_write writes[8];
static UINTN write_count;
static UINTN calls[3];
static UINTN order[3];
static UINTN order_count;
static const EFI_GUID *installed_guids[4];
static void *installed_interfaces[4];

void cdk2_reset_test_out8(UINT16 port, UINT8 value)
{
	writes[write_count++] = (struct io_write){ port, value, 1 };
}

void cdk2_reset_test_out16(UINT16 port, UINT16 value)
{
	writes[write_count++] = (struct io_write){ port, value, 2 };
}

static void CDK2_MS_ABI filter_callback(CDK2_RESET_TYPE type,
	EFI_STATUS status, UINTN size, void *data)
{
	(void)type;
	(void)status;
	(void)size;
	(void)data;
	calls[0]++;
	order[order_count++] = 0;
}

static void CDK2_MS_ABI notification_callback(CDK2_RESET_TYPE type,
	EFI_STATUS status, UINTN size, void *data)
{
	(void)type;
	(void)status;
	(void)size;
	(void)data;
	calls[1]++;
	order[order_count++] = 1;
}

static void CDK2_MS_ABI handler_callback(CDK2_RESET_TYPE type,
	EFI_STATUS status, UINTN size, void *data)
{
	(void)type;
	(void)status;
	(void)size;
	(void)data;
	calls[2]++;
	order[order_count++] = 2;
}

static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{
	__builtin_ms_va_list arguments;
	const EFI_GUID *guid;
	UINTN count = 0;

	*handle = (void *)1;
	__builtin_ms_va_start(arguments, handle);
	while ((guid = __builtin_va_arg(arguments, const EFI_GUID *)) != NULL) {
		installed_guids[count] = guid;
		installed_interfaces[count] = __builtin_va_arg(arguments, void *);
		count++;
	}
	__builtin_ms_va_end(arguments);
	return count == 4U ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "reset-system test: %s\n", message);
	return !condition;
}

static void reset_test_state(void)
{
	memset(writes, 0, sizeof(writes));
	memset(calls, 0, sizeof(calls));
	memset(order, 0, sizeof(order));
	write_count = 0;
	order_count = 0;
	reset_depth = 0;
}

int main(void)
{
	struct boot_services_view boot;
	struct runtime_services_view runtime;
	struct system_table_view system;
	struct config_table table;
	struct {
		struct guid_hob board_hob;
		ACPI_BOARD_INFO board;
		struct hob_header end;
	} hobs;
	int failures = 0;

	memset(&boot, 0, sizeof(boot));
	memset(&runtime, 0, sizeof(runtime));
	memset(&system, 0, sizeof(system));
	memset(&hobs, 0, sizeof(hobs));
	boot.install_multiple = install_multiple;
	hobs.board_hob.header.type = HOB_TYPE_GUID_EXTENSION;
	hobs.board_hob.header.length = sizeof(hobs.board_hob) + sizeof(hobs.board);
	hobs.board_hob.name = board_info_guid;
	hobs.board.pm_gpe_en_base = 0x620;
	hobs.board.pm_evt_base = 0x600;
	hobs.board.pm_ctrl_reg_base = 0x604;
	hobs.board.reset_reg_address = 0xcf9;
	hobs.board.reset_value = 0x06;
	hobs.end.type = HOB_TYPE_END_OF_LIST;
	hobs.end.length = sizeof(hobs.end);
	table.guid = hob_list_guid;
	table.table = &hobs;
	system.boot_services = &boot;
	system.runtime_services = &runtime;
	system.table_count = 1;
	system.tables = &table;

	failures += expect(cdk2_reset_system_entry(NULL, NULL) == EFI_INVALID_PARAMETER,
		"NULL system table was accepted");
	system.table_count = 0;
	failures += expect(cdk2_reset_system_entry(NULL, &system) == EFI_NOT_FOUND,
		"missing HOB list was accepted");
	system.table_count = 1;
	failures += expect(cdk2_reset_system_entry(NULL, &system) == EFI_SUCCESS,
		"entry failed");
	failures += expect(runtime.reset_system == reset_system,
		"runtime ResetSystem hook was not installed");
	failures += expect(installed_interfaces[0] == NULL &&
		installed_interfaces[1] == &notification_list.protocol &&
		installed_interfaces[2] == &filter_list.protocol &&
		installed_interfaces[3] == &handler_list.protocol,
		"protocol interfaces were installed incorrectly");

	failures += expect(filter_list.protocol.register_reset_notify(
		&filter_list.protocol, filter_callback) == EFI_SUCCESS,
		"filter registration failed");
	failures += expect(notification_list.protocol.register_reset_notify(
		&notification_list.protocol, notification_callback) == EFI_SUCCESS,
		"notification registration failed");
	failures += expect(handler_list.protocol.register_reset_notify(
		&handler_list.protocol, handler_callback) == EFI_SUCCESS,
		"handler registration failed");
	failures += expect(notification_list.protocol.register_reset_notify(
		&notification_list.protocol, notification_callback) == EFI_ALREADY_STARTED,
		"duplicate registration was accepted");

	reset_test_state();
	runtime.reset_system(cdk2_reset_shutdown, EFI_SUCCESS, 0, NULL);
	failures += expect(calls[0] == 1U && calls[1] == 1U && calls[2] == 1U &&
		order[0] == 0U && order[1] == 1U && order[2] == 2U,
		"reset notification order is wrong");
	failures += expect(write_count == 3U && writes[0].port == 0x620 &&
		writes[1].port == 0x600 && writes[2].port == 0x604 &&
		writes[2].value == (ACPI_PM1_SLP_TYP_S5 | ACPI_PM1_SLP_EN),
		"ACPI shutdown sequence is wrong");

	reset_test_state();
	runtime.reset_system(cdk2_reset_warm, EFI_SUCCESS, 0, NULL);
	failures += expect(write_count == 3U && writes[0].port == 0xcf9 &&
		writes[0].value == 0x06 && writes[1].value == 0x02 &&
		writes[2].value == 0x06, "warm reset sequence is wrong");
	failures += expect(notification_list.protocol.unregister_reset_notify(
		&notification_list.protocol, notification_callback) == EFI_SUCCESS,
		"notification unregister failed");
	failures += expect(notification_list.protocol.unregister_reset_notify(
		&notification_list.protocol, notification_callback) == EFI_INVALID_PARAMETER,
		"missing notification unregister succeeded");

	return failures == 0 ? 0 : 1;
}
