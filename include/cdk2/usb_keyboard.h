/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_USB_KEYBOARD_H
#define CDK2_USB_KEYBOARD_H

#include <cdk2/partition.h>

#define CDK2_USB_KEYBOARD_KEYS 6U
#define CDK2_USB_KEYBOARD_QUEUE 32U
#define CDK2_KEY_SHIFT_VALID 0x80000000U
#define CDK2_KEY_LEFT_SHIFT 0x00000002U
#define CDK2_KEY_RIGHT_SHIFT 0x00000020U
#define CDK2_KEY_LEFT_CONTROL 0x00000001U
#define CDK2_KEY_RIGHT_CONTROL 0x00000010U
#define CDK2_KEY_LEFT_ALT 0x00000004U
#define CDK2_KEY_RIGHT_ALT 0x00000040U

struct cdk2_usb_keyboard_report {
	UINT8 modifiers, reserved, keys[CDK2_USB_KEYBOARD_KEYS];
};

struct cdk2_usb_keyboard_key {
	UINT16 scan_code, unicode_char;
	UINT32 shift_state, toggle_state;
};

struct cdk2_usb_keyboard {
	struct cdk2_usb_keyboard_report previous;
	struct cdk2_usb_keyboard_key queue[CDK2_USB_KEYBOARD_QUEUE];
	UINTN head, count;
	BOOLEAN caps_lock, num_lock, scroll_lock;
};

EFI_STATUS cdk2_usb_keyboard_init(struct cdk2_usb_keyboard *keyboard);
EFI_STATUS cdk2_usb_keyboard_report(struct cdk2_usb_keyboard *keyboard,
	const void *report, UINTN length);
EFI_STATUS cdk2_usb_keyboard_read(struct cdk2_usb_keyboard *keyboard,
	struct cdk2_usb_keyboard_key *key);

#endif
