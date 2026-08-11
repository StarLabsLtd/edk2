/* SPDX-License-Identifier: GPL-2.0-only */

#include "../src/modules/usb_keyboard/entry.c"

#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

int main(void)
{
	CHECK(sizeof(struct driver_binding) == 48U);
	CHECK(offsetof(struct boot_services, allocate_pool) == 64U);
	CHECK(offsetof(struct boot_services, create_event) == 80U);
	CHECK(offsetof(struct boot_services, signal_event) == 104U);
	CHECK(offsetof(struct boot_services, close_event) == 112U);
	CHECK(offsetof(struct boot_services, handle_protocol) == 152U);
	CHECK(offsetof(struct boot_services, open_protocol) == 280U);
	CHECK(offsetof(struct boot_services, close_protocol) == 288U);
	CHECK(offsetof(struct boot_services, install_multiple) == 328U);
	CHECK(cdk2_usb_keyboard_entry(NULL, NULL) == EFI_INVALID_PARAMETER);
	puts("usb keyboard entry tests: PASS");
	return 0;
}
