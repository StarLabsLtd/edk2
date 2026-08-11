/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_USB_KEYBOARD_H
#define CDK2_USB_KEYBOARD_H

#include <cdk2/usb_bus.h>

#define CDK2_USB_KEYBOARD_KEYS 6U
#define CDK2_USB_KEYBOARD_QUEUE 32U
#define CDK2_USB_KEYBOARD_CONTROLLERS 16U
#define CDK2_KEY_SHIFT_VALID 0x80000000U
#define CDK2_KEY_LEFT_SHIFT 0x00000002U
#define CDK2_KEY_RIGHT_SHIFT 0x00000001U
#define CDK2_KEY_LEFT_CONTROL 0x00000008U
#define CDK2_KEY_RIGHT_CONTROL 0x00000004U
#define CDK2_KEY_LEFT_ALT 0x00000020U
#define CDK2_KEY_RIGHT_ALT 0x00000010U

struct cdk2_usb_keyboard_report {
	UINT8 modifiers, reserved, keys[CDK2_USB_KEYBOARD_KEYS];
};

struct cdk2_usb_keyboard_key {
	UINT16 scan_code, unicode_char;
	UINT32 shift_state, toggle_state;
};

struct cdk2_simple_text_input;
struct cdk2_simple_text_input_ex;
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_reset_fn(
	struct cdk2_simple_text_input *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_read_fn(
	struct cdk2_simple_text_input *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_reset_ex_fn(
	struct cdk2_simple_text_input_ex *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_read_ex_fn(
	struct cdk2_simple_text_input_ex *, struct cdk2_usb_keyboard_key *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_set_state_fn(
	struct cdk2_simple_text_input_ex *, UINT8 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_key_notify_fn(
	struct cdk2_usb_keyboard_key *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_register_fn(
	struct cdk2_simple_text_input_ex *, struct cdk2_usb_keyboard_key *,
	cdk2_key_notify_fn *, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_unregister_fn(
	struct cdk2_simple_text_input_ex *, void *);
struct cdk2_simple_text_input {
	cdk2_text_reset_fn *reset;
	cdk2_text_read_fn *read_key_stroke;
	void *wait_for_key;
};
struct cdk2_simple_text_input_ex {
	cdk2_text_reset_ex_fn *reset;
	cdk2_text_read_ex_fn *read_key_stroke_ex;
	void *wait_for_key_ex;
	cdk2_text_set_state_fn *set_state;
	cdk2_text_register_fn *register_key_notify;
	cdk2_text_unregister_fn *unregister_key_notify;
};

struct cdk2_usb_keyboard {
	struct cdk2_usb_keyboard_report previous;
	struct cdk2_usb_keyboard_key queue[CDK2_USB_KEYBOARD_QUEUE];
	UINTN head, count;
	BOOLEAN caps_lock, num_lock, scroll_lock;
};

struct cdk2_usb_keyboard_device {
	struct cdk2_usb_keyboard keyboard;
	struct cdk2_simple_text_input input;
	struct cdk2_simple_text_input_ex input_ex;
	struct cdk2_usb_io_protocol *usb;
	UINT8 endpoint, interval;
	UINT16 packet_size;
	BOOLEAN active;
};

struct cdk2_usb_keyboard_controller {
	struct cdk2_usb_keyboard_device device;
	void *handle, *wait, *wait_ex;
	BOOLEAN installed;
};
typedef EFI_STATUS cdk2_usb_keyboard_open_fn(void *, void *,
	struct cdk2_usb_io_protocol **);
typedef EFI_STATUS cdk2_usb_keyboard_close_fn(void *, void *);
typedef EFI_STATUS cdk2_usb_keyboard_event_fn(void *, void **);
typedef EFI_STATUS cdk2_usb_keyboard_close_event_fn(void *, void *);
typedef EFI_STATUS cdk2_usb_keyboard_publish_fn(void *, void *,
	struct cdk2_usb_keyboard_controller *);
typedef EFI_STATUS cdk2_usb_keyboard_remove_fn(void *, void *,
	struct cdk2_usb_keyboard_controller *);
typedef EFI_STATUS cdk2_usb_keyboard_allocate_fn(void *, UINTN, void **);
typedef void cdk2_usb_keyboard_release_fn(void *, void *);
struct cdk2_usb_keyboard_binding_services {
	void *context;
	cdk2_usb_keyboard_open_fn *open;
	cdk2_usb_keyboard_close_fn *close;
	cdk2_usb_keyboard_event_fn *create_event;
	cdk2_usb_keyboard_close_event_fn *close_event;
	cdk2_usb_keyboard_publish_fn *publish;
	cdk2_usb_keyboard_remove_fn *remove;
	cdk2_usb_keyboard_allocate_fn *allocate;
	cdk2_usb_keyboard_release_fn *release;
};
struct cdk2_usb_keyboard_binding {
	struct cdk2_usb_keyboard_binding_services services;
	struct cdk2_usb_keyboard_controller *controllers[
		CDK2_USB_KEYBOARD_CONTROLLERS];
	UINTN count;
};

EFI_STATUS cdk2_usb_keyboard_init(struct cdk2_usb_keyboard *keyboard);
EFI_STATUS cdk2_usb_keyboard_report(struct cdk2_usb_keyboard *keyboard,
	const void *report, UINTN length);
EFI_STATUS cdk2_usb_keyboard_read(struct cdk2_usb_keyboard *keyboard,
	struct cdk2_usb_keyboard_key *key);
EFI_STATUS cdk2_usb_keyboard_start_io(struct cdk2_usb_keyboard_device *device,
	struct cdk2_usb_io_protocol *usb);
EFI_STATUS cdk2_usb_keyboard_stop_io(struct cdk2_usb_keyboard_device *device);
EFI_STATUS cdk2_usb_keyboard_protocol_init(
	struct cdk2_usb_keyboard_device *device, void *wait, void *wait_ex);
EFI_STATUS cdk2_usb_keyboard_binding_init(
	struct cdk2_usb_keyboard_binding *binding,
	const struct cdk2_usb_keyboard_binding_services *services);
EFI_STATUS cdk2_usb_keyboard_binding_supported(
	struct cdk2_usb_keyboard_binding *binding, void *controller);
EFI_STATUS cdk2_usb_keyboard_binding_start(
	struct cdk2_usb_keyboard_binding *binding, void *controller);
EFI_STATUS cdk2_usb_keyboard_binding_stop(
	struct cdk2_usb_keyboard_binding *binding, void *controller);

#endif
