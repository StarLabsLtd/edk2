/* SPDX-License-Identifier: GPL-2.0-only */

#define CDK2_METRONOME_TEST
#include "../src/modules/metronome/metronome.c"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static uint16_t observed_port;
static uint32_t timer_value;
static const struct guid *installed_guid;
static void *installed_interface;

uint32_t cdk2_metronome_test_io_read32(uint16_t port)
{
	observed_port = port;
	return timer_value++;
}

static uint64_t EFIAPI mock_install(void **handle, const struct guid *guid,
						     void *interface, ...)
{
	*handle = (void *)1;
	installed_guid = guid;
	installed_interface = interface;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 metronome test: %s\n", message);
		return 1;
	}
	return 0;
}

int main(void)
{
	struct {
		struct guid_hob acpi;
		struct acpi_board_info info;
		struct hob_header end;
	} hobs;
	struct configuration_table configuration;
	struct system_table system_table;
	struct boot_services_install_view boot_services;
	int failures = 0;

	memset(&hobs, 0, sizeof(hobs));
	memset(&system_table, 0, sizeof(system_table));
	memset(&boot_services, 0, sizeof(boot_services));
	hobs.acpi.header.type = HOB_TYPE_GUID_EXTENSION;
	hobs.acpi.header.length = sizeof(hobs.acpi) + sizeof(hobs.info);
	hobs.acpi.name = acpi_board_info_guid;
	hobs.info.pm_timer_reg_base = 0x608;
	hobs.end.type = HOB_TYPE_END_OF_HOB_LIST;
	hobs.end.length = sizeof(hobs.end);
	configuration.vendor_guid = hob_list_guid;
	configuration.vendor_table = &hobs;
	system_table.configuration_table_count = 1;
	system_table.configuration_table = &configuration;
	boot_services.install_multiple_protocols = mock_install;
	system_table.boot_services = &boot_services;

	failures += expect(cdk2_metronome_entry(NULL, &system_table) == EFI_SUCCESS,
			   "entry succeeds");
	failures += expect(guid_equal(installed_guid, &metronome_protocol_guid),
			   "architectural protocol GUID installed");
	failures += expect(installed_interface == &metronome, "protocol interface installed");
	failures += expect(metronome.tick_period == 1, "100 ns tick period published");
	timer_value = 0;
	failures += expect(metronome.wait_for_tick(&metronome, 100) == EFI_SUCCESS,
			   "wait succeeds");
	failures += expect(observed_port == 0x608, "ACPI timer port used");
	return failures == 0 ? 0 : 1;
}
