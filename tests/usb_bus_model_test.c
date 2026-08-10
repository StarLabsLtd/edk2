/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_bus.h>

#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

int main(void)
{
	UINT8 descriptors[] = { 9U, 2U, 41U, 0U, 2U, 1U, 0U, 0x80U, 50U,
		9U, 4U, 0U, 0U, 1U, 8U, 6U, 80U, 0U,
		7U, 5U, 0x81U, 2U, 0x00U, 2U, 0U,
		9U, 4U, 1U, 0U, 1U, 3U, 1U, 1U, 0U,
		7U, 5U, 0x82U, 3U, 8U, 0U, 10U };
	struct cdk2_usb_configuration configuration;
	const struct cdk2_usb_interface *interface;
	struct cdk2_usb_device_path_node node;
	struct cdk2_usb_address_pool pool = { 0 };
	UINT8 port, number, address;

	CHECK(sizeof(node) == 6U && cdk2_usb_parse_configuration(descriptors,
		sizeof(descriptors), &configuration) == EFI_SUCCESS &&
		configuration.value == 1U && configuration.interface_count == 2U &&
		configuration.interfaces[0].endpoints[0].maximum_packet == 512U);
	CHECK(cdk2_usb_find_interface(&configuration, 1U, 0U, &interface) ==
		EFI_SUCCESS && interface->class_code == 3U &&
		interface->endpoints[0].address == 0x82U);
	CHECK(cdk2_usb_build_path(4U, 1U, &node) == EFI_SUCCESS &&
		cdk2_usb_parse_path(&node, sizeof(node), &port, &number) == EFI_SUCCESS &&
		port == 4U && number == 1U);
	for (UINT8 value = 1U; value < 128U; value++)
		CHECK(cdk2_usb_allocate_address(&pool, &address) == EFI_SUCCESS &&
			address == value);
	CHECK(cdk2_usb_allocate_address(&pool, &address) == EFI_OUT_OF_RESOURCES &&
		cdk2_usb_release_address(&pool, 64U) == EFI_SUCCESS &&
		cdk2_usb_allocate_address(&pool, &address) == EFI_SUCCESS && address == 64U);
	descriptors[2]--;
	CHECK(cdk2_usb_parse_configuration(descriptors, sizeof(descriptors),
		&configuration) == EFI_COMPROMISED_DATA);
	puts("usb bus model tests: PASS");
	return 0;
}
