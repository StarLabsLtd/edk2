/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_keyboard.h>

#include <string.h>

static BOOLEAN contains(const UINT8 keys[CDK2_USB_KEYBOARD_KEYS], UINT8 code)
{
	for (UINTN index = 0U; index < CDK2_USB_KEYBOARD_KEYS; index++)
		if (keys[index] == code)
			return TRUE;
	return FALSE;
}

static UINT32 shift_state(UINT8 modifiers)
{
	UINT32 state = CDK2_KEY_SHIFT_VALID;

	if ((modifiers & 0x01U) != 0U)
		state |= CDK2_KEY_LEFT_CONTROL;
	if ((modifiers & 0x02U) != 0U)
		state |= CDK2_KEY_LEFT_SHIFT;
	if ((modifiers & 0x04U) != 0U)
		state |= CDK2_KEY_LEFT_ALT;
	if ((modifiers & 0x10U) != 0U)
		state |= CDK2_KEY_RIGHT_CONTROL;
	if ((modifiers & 0x20U) != 0U)
		state |= CDK2_KEY_RIGHT_SHIFT;
	if ((modifiers & 0x40U) != 0U)
		state |= CDK2_KEY_RIGHT_ALT;
	return state;
}

static void translate(struct cdk2_usb_keyboard *keyboard, UINT8 code,
	UINT8 modifiers, struct cdk2_usb_keyboard_key *key)
{
	static const CHAR8 letters[] = "abcdefghijklmnopqrstuvwxyz";
	static const CHAR8 digits[] = "1234567890";
	BOOLEAN shifted = (modifiers & 0x22U) != 0U;

	memset(key, 0, sizeof(*key));
	key->shift_state = shift_state(modifiers);
	key->toggle_state = 0x80U | (keyboard->scroll_lock ? 1U : 0U) |
		(keyboard->num_lock ? 2U : 0U) | (keyboard->caps_lock ? 4U : 0U);
	if (code >= 4U && code <= 29U) {
		key->unicode_char = letters[code - 4U];
		if (shifted != keyboard->caps_lock)
			key->unicode_char -= 'a' - 'A';
	} else if (code >= 30U && code <= 39U) {
		key->unicode_char = digits[code - 30U];
	} else if (code == 40U) {
		key->unicode_char = '\r';
	} else if (code == 42U) {
		key->unicode_char = '\b';
	} else if (code == 43U) {
		key->unicode_char = '\t';
	} else if (code == 44U) {
		key->unicode_char = ' ';
	} else if (code >= 79U && code <= 82U) {
		static const UINT16 scans[] = { 3U, 4U, 1U, 2U };
		key->scan_code = scans[code - 79U];
	}
}

EFI_STATUS cdk2_usb_keyboard_init(struct cdk2_usb_keyboard *keyboard)
{
	if (keyboard == NULL)
		return EFI_INVALID_PARAMETER;
	memset(keyboard, 0, sizeof(*keyboard));
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_keyboard_report(struct cdk2_usb_keyboard *keyboard,
	const void *buffer, UINTN length)
{
	const struct cdk2_usb_keyboard_report *report = buffer;

	if (keyboard == NULL || buffer == NULL || length != sizeof(*report))
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0U; index < CDK2_USB_KEYBOARD_KEYS; index++) {
		UINT8 code = report->keys[index];
		struct cdk2_usb_keyboard_key key;
		UINTN tail;

		if (code <= 3U || contains(keyboard->previous.keys, code))
			continue;
		if (code == 57U)
			keyboard->caps_lock = !keyboard->caps_lock;
		else if (code == 83U)
			keyboard->num_lock = !keyboard->num_lock;
		else if (code == 71U)
			keyboard->scroll_lock = !keyboard->scroll_lock;
		translate(keyboard, code, report->modifiers, &key);
		if (key.scan_code == 0U && key.unicode_char == 0U)
			continue;
		if (keyboard->count == CDK2_USB_KEYBOARD_QUEUE)
			return EFI_OUT_OF_RESOURCES;
		tail = (keyboard->head + keyboard->count) % CDK2_USB_KEYBOARD_QUEUE;
		keyboard->queue[tail] = key;
		keyboard->count++;
	}
	keyboard->previous = *report;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_keyboard_read(struct cdk2_usb_keyboard *keyboard,
	struct cdk2_usb_keyboard_key *key)
{
	if (keyboard == NULL || key == NULL)
		return EFI_INVALID_PARAMETER;
	if (keyboard->count == 0U)
		return EFI_NOT_READY;
	*key = keyboard->queue[keyboard->head];
	keyboard->head = (keyboard->head + 1U) % CDK2_USB_KEYBOARD_QUEUE;
	keyboard->count--;
	return EFI_SUCCESS;
}
