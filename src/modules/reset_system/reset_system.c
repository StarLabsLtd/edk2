/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Native architectural reset and reset-notification services.
 * Copyright (c) 2006-2018 Intel Corporation. */

#include <cdk2/reset_system.h>
#include <guid/acpi_board_info.h>
#include <stddef.h>
#include <stdint.h>

#define EFI_ALREADY_STARTED EFIERR(20)
#define HOB_TYPE_GUID_EXTENSION 0x0004U
#define HOB_TYPE_END_OF_LIST 0xffffU
#define MAX_HOB_LIST_SIZE SIZE_1MB
#define MAX_RESET_NOTIFY 16U
#define MAX_RESET_DEPTH 10U
#define ACPI_PM1_WAK_STS BIT8
#define ACPI_PM1_SLP_TYP_S5 (5U << 10)
#define ACPI_PM1_SLP_EN BIT13

struct table_header {
	UINT64 signature;
	UINT32 revision;
	UINT32 header_size;
	UINT32 crc32;
	UINT32 reserved;
};

struct config_table {
	EFI_GUID guid;
	void *table;
};

struct system_table_view {
	struct table_header header;
	CHAR16 *firmware_vendor;
	UINT32 firmware_revision;
	UINT32 padding;
	void *console_fields[6];
	void *runtime_services;
	void *boot_services;
	UINTN table_count;
	struct config_table *tables;
};

typedef EFI_STATUS CDK2_MS_ABI install_multiple_function(void **handle, ...);

struct boot_services_view {
	UINT8 unused[328];
	install_multiple_function *install_multiple;
};

struct runtime_services_view {
	UINT8 unused[104];
	cdk2_reset_fn reset_system;
};

struct hob_header {
	UINT16 type;
	UINT16 length;
	UINT32 reserved;
};

struct guid_hob {
	struct hob_header header;
	EFI_GUID name;
};

struct notification_list {
	struct cdk2_reset_notification_protocol protocol;
	cdk2_reset_fn functions[MAX_RESET_NOTIFY];
	UINTN count;
};

static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4,
	{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID board_info_guid = {
	0x0ad3d31b, 0xb3d8, 0x4506,
	{ 0xae, 0x71, 0x2e, 0xf1, 0x10, 0x06, 0xd9, 0x0f }
};
static const EFI_GUID reset_arch_guid = {
	0x27cfac88, 0x46cc, 0x11d4,
	{ 0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID reset_notification_guid = {
	0x9da34ae0, 0xeaf9, 0x4bbf,
	{ 0x8e, 0xc3, 0xfd, 0x60, 0x22, 0x6c, 0x44, 0xbe }
};
static const EFI_GUID platform_filter_guid = {
	0x695d7835, 0x8d47, 0x4c11,
	{ 0xab, 0x22, 0xfa, 0x8a, 0xcc, 0xe7, 0xae, 0x7a }
};
static const EFI_GUID platform_handler_guid = {
	0x2df6ba0b, 0x7092, 0x440d,
	{ 0xbd, 0x04, 0xfb, 0x09, 0x1e, 0xc3, 0xf3, 0xc1 }
};

static ACPI_BOARD_INFO board_info;
static UINTN reset_depth;
static void *driver_handle;

static int guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left;
	const UINT8 *b = (const UINT8 *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++) {
		if (a[index] != b[index])
			return 0;
	}
	return 1;
}

static EFI_STATUS CDK2_MS_ABI register_notification(
	struct cdk2_reset_notification_protocol *protocol, cdk2_reset_fn function)
{
	struct notification_list *list = (struct notification_list *)protocol;
	UINTN index;

	if (function == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < list->count; index++) {
		if (list->functions[index] == function)
			return EFI_ALREADY_STARTED;
	}
	if (list->count == ARRAY_SIZE(list->functions))
		return EFI_OUT_OF_RESOURCES;
	list->functions[list->count++] = function;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI unregister_notification(
	struct cdk2_reset_notification_protocol *protocol, cdk2_reset_fn function)
{
	struct notification_list *list = (struct notification_list *)protocol;
	UINTN index;

	if (function == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < list->count; index++) {
		if (list->functions[index] != function)
			continue;
		for (; index + 1U < list->count; index++)
			list->functions[index] = list->functions[index + 1U];
		list->count--;
		return EFI_SUCCESS;
	}
	return EFI_INVALID_PARAMETER;
}

#define NOTIFICATION_LIST_INITIALIZER \
	{ { register_notification, unregister_notification }, { NULL }, 0 }

static struct notification_list filter_list = NOTIFICATION_LIST_INITIALIZER;
static struct notification_list notification_list = NOTIFICATION_LIST_INITIALIZER;
static struct notification_list handler_list = NOTIFICATION_LIST_INITIALIZER;

#ifdef CDK2_RESET_TEST
extern void cdk2_reset_test_out8(UINT16 port, UINT8 value);
extern void cdk2_reset_test_out16(UINT16 port, UINT16 value);
#define io_out8 cdk2_reset_test_out8
#define io_out16 cdk2_reset_test_out16
static void stop_cpu(void)
{
}
#else
static void io_out8(UINT16 port, UINT8 value)
{
	__asm__ volatile("outb %b0, %w1" : : "a"(value), "Nd"(port));
}

static void io_out16(UINT16 port, UINT16 value)
{
	__asm__ volatile("outw %w0, %w1" : : "a"(value), "Nd"(port));
}

static __noreturn void stop_cpu(void)
{
	for (;;)
		__asm__ volatile("cli; hlt");
}
#endif

static void signal_notifications(struct notification_list *list,
	CDK2_RESET_TYPE type, EFI_STATUS status, UINTN data_size, void *reset_data)
{
	UINTN index;

	for (index = 0; index < list->count; index++)
		list->functions[index](type, status, data_size, reset_data);
}

static void CDK2_MS_ABI reset_system(CDK2_RESET_TYPE type, EFI_STATUS status,
	UINTN data_size, void *reset_data)
{
	reset_depth++;
	if (reset_depth <= MAX_RESET_DEPTH) {
		signal_notifications(&filter_list, type, status, data_size, reset_data);
		signal_notifications(&notification_list, type, status, data_size, reset_data);
		signal_notifications(&handler_list, type, status, data_size, reset_data);
	}

	if (type == cdk2_reset_shutdown && board_info.pm_ctrl_reg_base != 0U) {
		if (board_info.pm_gpe_en_base != 0U)
			io_out16((UINT16)board_info.pm_gpe_en_base, 0);
		if (board_info.pm_evt_base != 0U)
			io_out16((UINT16)board_info.pm_evt_base, ACPI_PM1_WAK_STS);
		io_out16((UINT16)board_info.pm_ctrl_reg_base,
			 ACPI_PM1_SLP_TYP_S5 | ACPI_PM1_SLP_EN);
		stop_cpu();
	}

	if (board_info.reset_reg_address != 0U && board_info.reset_value != 0U)
		io_out8((UINT16)board_info.reset_reg_address, board_info.reset_value);
	io_out8(0xcf9, type == cdk2_reset_warm ? 0x02 : 0x0a);
	io_out8(0xcf9, type == cdk2_reset_warm ? 0x06 : 0x0e);
	stop_cpu();
}

static const ACPI_BOARD_INFO *find_board_info(const struct system_table_view *system)
{
	const UINT8 *hob_list = NULL;
	const struct hob_header *hob;
	UINTN index;
	UINTN walked = 0;

	if (system->table_count != 0U && system->tables == NULL)
		return NULL;
	for (index = 0; index < system->table_count; index++) {
		if (guid_equal(&system->tables[index].guid, &hob_list_guid)) {
			hob_list = system->tables[index].table;
			break;
		}
	}
	if (hob_list == NULL)
		return NULL;

	hob = (const struct hob_header *)(const void *)hob_list;
	while (walked + sizeof(*hob) <= MAX_HOB_LIST_SIZE) {
		const struct guid_hob *guid_hob;

		if (hob->type == HOB_TYPE_END_OF_LIST)
			return NULL;
		if (hob->length < sizeof(*hob) || hob->length > MAX_HOB_LIST_SIZE - walked)
			return NULL;
		if (hob->type == HOB_TYPE_GUID_EXTENSION &&
		    hob->length >= sizeof(*guid_hob) + sizeof(ACPI_BOARD_INFO)) {
			guid_hob = (const struct guid_hob *)(const void *)hob;
			if (guid_equal(&guid_hob->name, &board_info_guid))
				return (const ACPI_BOARD_INFO *)(const void *)(guid_hob + 1);
		}
		walked += hob->length;
		hob = (const struct hob_header *)(const void *)(hob_list + walked);
	}
	return NULL;
}

EFI_STATUS CDK2_MS_ABI cdk2_reset_system_entry(void *image,
					       struct system_table_view *system)
{
	const ACPI_BOARD_INFO *board;
	struct boot_services_view *boot;
	struct runtime_services_view *runtime;

	(void)image;
	if (system == NULL || system->boot_services == NULL ||
	    system->runtime_services == NULL)
		return EFI_INVALID_PARAMETER;
	board = find_board_info(system);
	if (board == NULL)
		return EFI_NOT_FOUND;
	board_info = *board;
	boot = system->boot_services;
	runtime = system->runtime_services;
	runtime->reset_system = reset_system;
	return boot->install_multiple(&driver_handle,
		&reset_arch_guid, NULL,
		&reset_notification_guid, &notification_list.protocol,
		&platform_filter_guid, &filter_list.protocol,
		&platform_handler_guid, &handler_list.protocol, NULL);
}
