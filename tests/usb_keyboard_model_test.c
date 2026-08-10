/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_keyboard.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

int main(void)
{
	struct cdk2_usb_keyboard keyboard;
	struct cdk2_usb_keyboard_report report = { .keys = { 4U, 30U, 79U } };
	struct cdk2_usb_keyboard_key key;

	CHECK(cdk2_usb_keyboard_init(&keyboard) == EFI_SUCCESS);
	CHECK(cdk2_usb_keyboard_report(&keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS && keyboard.count == 3U);
	CHECK(cdk2_usb_keyboard_read(&keyboard, &key) == EFI_SUCCESS &&
		key.unicode_char == 'a');
	CHECK(cdk2_usb_keyboard_read(&keyboard, &key) == EFI_SUCCESS &&
		key.unicode_char == '1');
	CHECK(cdk2_usb_keyboard_read(&keyboard, &key) == EFI_SUCCESS &&
		key.scan_code == 3U);
	CHECK(cdk2_usb_keyboard_report(&keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS && keyboard.count == 0U);
	memset(&report, 0, sizeof(report));
	CHECK(cdk2_usb_keyboard_report(&keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS);
	report.modifiers = 2U; report.keys[0] = 4U;
	CHECK(cdk2_usb_keyboard_report(&keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS && cdk2_usb_keyboard_read(&keyboard, &key) == EFI_SUCCESS &&
		key.unicode_char == 'A' &&
		(key.shift_state & CDK2_KEY_LEFT_SHIFT) != 0U);
	memset(&report, 0, sizeof(report));
	CHECK(cdk2_usb_keyboard_report(&keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS);
	report.keys[0] = 57U;
	CHECK(cdk2_usb_keyboard_report(&keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS && keyboard.caps_lock);
	puts("usb keyboard model tests: PASS");
	return 0;
}
