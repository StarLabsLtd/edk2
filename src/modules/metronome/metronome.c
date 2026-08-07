/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * Native form of the pre-standalone Metronome and ACPI timer implementations.
 * The original sources are Copyright (c) 2008-2018 and 2014, Intel Corporation.
 */

#include <cdk2/metronome.h>

#include <stddef.h>
#include <stdint.h>

#define HOB_TYPE_GUID_EXTENSION 0x0004U
#define HOB_TYPE_END_OF_HOB_LIST 0xffffU
#define ACPI_TIMER_FREQUENCY 3579545ULL
#define ACPI_TIMER_MASK 0x00ffffffU

struct guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

struct table_header {
	uint64_t signature;
	uint32_t revision;
	uint32_t header_size;
	uint32_t crc32;
	uint32_t reserved;
};

struct configuration_table {
	struct guid vendor_guid;
	void *vendor_table;
};

struct system_table {
	struct table_header header;
	uint16_t *firmware_vendor;
	uint32_t firmware_revision;
	uint32_t pad;
	void *console_in_handle;
	void *console_in;
	void *console_out_handle;
	void *console_out;
	void *standard_error_handle;
	void *standard_error;
	void *runtime_services;
	void *boot_services;
	size_t configuration_table_count;
	struct configuration_table *configuration_table;
};

struct hob_header {
	uint16_t type;
	uint16_t length;
	uint32_t reserved;
};

struct guid_hob {
	struct hob_header header;
	struct guid name;
};

struct acpi_board_info {
	uint8_t revision;
	uint8_t reserved[2];
	uint8_t reset_value;
	uint64_t pm_evt_base;
	uint64_t pm_gpe_en_base;
	uint64_t pm_ctrl_reg_base;
	uint64_t pm_timer_reg_base;
};

typedef uint64_t (CDK2_MS_ABI * install_multiple_protocols_fn)(
	void **handle, const struct guid *protocol, void *interface, ...);

struct boot_services_install_view {
	uint8_t unused[328];
	install_multiple_protocols_fn install_multiple_protocols;
};

static const struct guid hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const struct guid acpi_board_info_guid = {
	0x0ad3d31b, 0xb3d8, 0x4506, { 0xae, 0x71, 0x2e, 0xf1, 0x10, 0x06, 0xd9, 0x0f }
};
static const struct guid metronome_protocol_guid = {
	0x26baccb2, 0x6f42, 0x11d4, { 0xbc, 0xe7, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 }
};

static uint16_t pm_timer_port;
static void *metronome_handle;
static struct cdk2_metronome metronome = {
	.wait_for_tick = cdk2_metronome_wait_for_tick,
	.tick_period = 1,
};

static int guid_equal(const struct guid *left, const struct guid *right)
{
	const uint8_t *a = (const uint8_t *)left;
	const uint8_t *b = (const uint8_t *)right;
	size_t index;

	for (index = 0; index < sizeof(*left); index++) {
		if (a[index] != b[index])
			return 0;
	}
	return 1;
}

#ifdef CDK2_METRONOME_TEST
extern uint32_t cdk2_metronome_test_io_read32(uint16_t port);
#define io_read32 cdk2_metronome_test_io_read32
#else
static uint32_t io_read32(uint16_t port)
{
	uint32_t value;

	__asm__ volatile("inl %w1, %0" : "=a" (value) : "Nd" (port));
	return value;
}
#endif

static void delay_ticks(uint32_t timer_ticks)
{
	uint32_t start = io_read32(pm_timer_port) & ACPI_TIMER_MASK;

	while (((io_read32(pm_timer_port) - start) & ACPI_TIMER_MASK) < timer_ticks)
		__asm__ volatile("pause");
}

uint64_t CDK2_MS_ABI
cdk2_metronome_wait_for_tick(struct cdk2_metronome *unused, uint32_t ticks)
{
	uint64_t nanoseconds = (uint64_t)ticks * 100ULL;
	uint64_t timer_ticks = (nanoseconds * ACPI_TIMER_FREQUENCY + 999999999ULL) /
			       1000000000ULL;

	(void)unused;
	while (timer_ticks > 0) {
		uint32_t chunk = timer_ticks > 0x003fffffU ? 0x003fffffU : (uint32_t)timer_ticks;
		delay_ticks(chunk);
		timer_ticks -= chunk;
	}
	return EFI_SUCCESS;
}

static void *find_hob_list(const struct system_table *system_table)
{
	size_t index;

	for (index = 0; index < system_table->configuration_table_count; index++) {
		if (guid_equal(&system_table->configuration_table[index].vendor_guid,
			       &hob_list_guid))
			return system_table->configuration_table[index].vendor_table;
	}
	return NULL;
}

static const struct acpi_board_info *find_acpi_board_info(void *hob_list)
{
	struct hob_header *hob = hob_list;

	while (hob != NULL && hob->type != HOB_TYPE_END_OF_HOB_LIST) {
		if (hob->length < sizeof(*hob))
			return NULL;
		if (hob->type == HOB_TYPE_GUID_EXTENSION &&
		    hob->length >= sizeof(struct guid_hob) + sizeof(struct acpi_board_info)) {
			struct guid_hob *guid_hob = (struct guid_hob *)hob;

			if (guid_equal(&guid_hob->name, &acpi_board_info_guid))
				return (const struct acpi_board_info *)(guid_hob + 1);
		}
		hob = (struct hob_header *)((uint8_t *)hob + hob->length);
	}
	return NULL;
}

uint64_t CDK2_MS_ABI
cdk2_metronome_entry(void *image_handle, struct system_table *system_table)
{
	const struct acpi_board_info *board_info;
	struct boot_services_install_view *boot_services;

	(void)image_handle;
	board_info = find_acpi_board_info(find_hob_list(system_table));
	if (board_info == NULL || board_info->pm_timer_reg_base == 0 ||
	    board_info->pm_timer_reg_base > UINT16_MAX)
		return EFI_NOT_FOUND;
	pm_timer_port = (uint16_t)board_info->pm_timer_reg_base;
	boot_services = system_table->boot_services;
	return boot_services->install_multiple_protocols(&metronome_handle,
						  &metronome_protocol_guid, &metronome, NULL);
}
