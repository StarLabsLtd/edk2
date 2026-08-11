/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_keyboard.h>

#include <stddef.h>

struct input_key { UINT16 scan_code, unicode_char; };

static struct cdk2_usb_keyboard_device *input_owner(
	struct cdk2_simple_text_input *protocol)
{
	return (void *)((UINT8 *)protocol -
		offsetof(struct cdk2_usb_keyboard_device, input));
}

static struct cdk2_usb_keyboard_device *input_ex_owner(
	struct cdk2_simple_text_input_ex *protocol)
{
	return (void *)((UINT8 *)protocol -
		offsetof(struct cdk2_usb_keyboard_device, input_ex));
}

static EFI_STATUS CDK2_MS_ABI reset_input(struct cdk2_simple_text_input *protocol,
	BOOLEAN extended)
{
	struct cdk2_usb_keyboard_device *device;

	(void)extended;
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	device = input_owner(protocol);
	return cdk2_usb_keyboard_init(&device->keyboard);
}

static EFI_STATUS CDK2_MS_ABI read_input(struct cdk2_simple_text_input *protocol,
	void *result)
{
	struct cdk2_usb_keyboard_key key;
	struct input_key *input = result;
	EFI_STATUS status;

	if (protocol == NULL || result == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_usb_keyboard_read(&input_owner(protocol)->keyboard, &key);
	if (!EFI_ERROR(status)) {
		input->scan_code = key.scan_code;
		input->unicode_char = key.unicode_char;
	}
	return status;
}

static EFI_STATUS CDK2_MS_ABI reset_input_ex(
	struct cdk2_simple_text_input_ex *protocol, BOOLEAN extended)
{
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	return reset_input(&input_ex_owner(protocol)->input, extended);
}

static EFI_STATUS CDK2_MS_ABI read_input_ex(
	struct cdk2_simple_text_input_ex *protocol,
	struct cdk2_usb_keyboard_key *key)
{
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_usb_keyboard_read(&input_ex_owner(protocol)->keyboard, key);
}

static EFI_STATUS CDK2_MS_ABI set_state(
	struct cdk2_simple_text_input_ex *protocol, UINT8 *state)
{
	struct cdk2_usb_keyboard *keyboard;

	if (protocol == NULL || state == NULL || (*state & 0x80U) == 0U)
		return EFI_INVALID_PARAMETER;
	keyboard = &input_ex_owner(protocol)->keyboard;
	keyboard->scroll_lock = (*state & 1U) != 0U;
	keyboard->num_lock = (*state & 2U) != 0U;
	keyboard->caps_lock = (*state & 4U) != 0U;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI register_notify(
	struct cdk2_simple_text_input_ex *protocol,
	struct cdk2_usb_keyboard_key *key, cdk2_key_notify_fn *notify, void **handle)
{
	(void)protocol; (void)key; (void)notify; (void)handle;
	return EFI_UNSUPPORTED;
}

static EFI_STATUS CDK2_MS_ABI unregister_notify(
	struct cdk2_simple_text_input_ex *protocol, void *handle)
{
	(void)protocol; (void)handle;
	return EFI_INVALID_PARAMETER;
}

EFI_STATUS cdk2_usb_keyboard_protocol_init(
	struct cdk2_usb_keyboard_device *device, void *wait, void *wait_ex)
{
	if (device == NULL || wait == NULL || wait_ex == NULL)
		return EFI_INVALID_PARAMETER;
	device->input = (struct cdk2_simple_text_input) {
		reset_input, read_input, wait };
	device->input_ex = (struct cdk2_simple_text_input_ex) {
		reset_input_ex, read_input_ex, wait_ex, set_state, register_notify,
		unregister_notify };
	return EFI_SUCCESS;
}
