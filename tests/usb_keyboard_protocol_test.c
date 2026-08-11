/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_keyboard.h>

#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct input_key { UINT16 scan_code, unicode_char; };

int main(void)
{
	struct cdk2_usb_keyboard_device device;
	struct cdk2_usb_keyboard_report report = { .modifiers = 0x22U,
		.keys = { 4U } };
	struct cdk2_usb_keyboard_key extended;
	struct input_key key;
	UINT8 state = 0x86U;

	CHECK(sizeof(device.input) == 24U && sizeof(device.input_ex) == 48U);
	CHECK(cdk2_usb_keyboard_init(&device.keyboard) == EFI_SUCCESS);
	CHECK(cdk2_usb_keyboard_protocol_init(&device, &device, &report) ==
		EFI_SUCCESS && device.input.wait_for_key == &device &&
		device.input_ex.wait_for_key_ex == &report);
	CHECK(cdk2_usb_keyboard_report(&device.keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS && device.input.read_key_stroke(&device.input, &key) ==
		EFI_SUCCESS && key.unicode_char == 'A');
	CHECK(device.input_ex.set_state(&device.input_ex, &state) == EFI_SUCCESS &&
		device.keyboard.num_lock && device.keyboard.caps_lock);
	report.keys[0] = 0U;
	CHECK(cdk2_usb_keyboard_report(&device.keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS);
	report.keys[0] = 4U;
	CHECK(cdk2_usb_keyboard_report(&device.keyboard, &report, sizeof(report)) ==
		EFI_SUCCESS && device.input_ex.read_key_stroke_ex(&device.input_ex,
		&extended) == EFI_SUCCESS && extended.unicode_char == 'a');
	CHECK(device.input.reset(&device.input, FALSE) == EFI_SUCCESS &&
		device.input.read_key_stroke(&device.input, &key) == EFI_NOT_READY);
	puts("usb keyboard protocol tests: PASS");
	return 0;
}
