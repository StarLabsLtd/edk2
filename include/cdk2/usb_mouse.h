/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_USB_MOUSE_H_
#define CDK2_USB_MOUSE_H_

#include <cdk2/usb_bus.h>

#define CDK2_USB_CLASS_HID 3U
#define CDK2_USB_SUBCLASS_BOOT 1U
#define CDK2_USB_PROTOCOL_MOUSE 2U
#define CDK2_USB_INTERRUPT 3U
#define CDK2_USB_ENDPOINT_IN 0x80U
#define CDK2_USB_ERR_STALL 0x02U
#define CDK2_OPEN_BY_DRIVER 0x10U
#define CDK2_OPEN_GET_PROTOCOL 0x02U

struct cdk2_usb_interface_descriptor {
	UINT8 length;
	UINT8 descriptor_type;
	UINT8 interface_number;
	UINT8 alternate_setting;
	UINT8 endpoint_count;
	UINT8 interface_class;
	UINT8 interface_subclass;
	UINT8 interface_protocol;
	UINT8 interface;
} __packed;

struct cdk2_usb_endpoint_descriptor {
	UINT8 length;
	UINT8 descriptor_type;
	UINT8 endpoint_address;
	UINT8 attributes;
	UINT16 maximum_packet_size;
	UINT8 interval;
} __packed;

struct cdk2_usb_config_descriptor { UINT8 length; UINT8 descriptor_type;
	UINT16 total_length; UINT8 interface_count; UINT8 configuration_value;
	UINT8 configuration; UINT8 attributes; UINT8 maximum_power; } __packed;
#define cdk2_usb_io cdk2_usb_io_protocol
#define cdk2_usb_async_callback_fn cdk2_usb2_async_callback_fn

struct cdk2_simple_pointer_state {
	INT32 relative_movement_x;
	INT32 relative_movement_y;
	INT32 relative_movement_z;
	BOOLEAN left_button;
	BOOLEAN right_button;
};

struct cdk2_simple_pointer_mode {
	UINT64 resolution_x;
	UINT64 resolution_y;
	UINT64 resolution_z;
	BOOLEAN left_button;
	BOOLEAN right_button;
};

struct cdk2_simple_pointer;
typedef EFI_STATUS CDK2_MS_ABI cdk2_pointer_reset_fn(struct cdk2_simple_pointer *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pointer_state_fn(struct cdk2_simple_pointer *,
	struct cdk2_simple_pointer_state *);

struct cdk2_simple_pointer {
	cdk2_pointer_reset_fn *reset;
	cdk2_pointer_state_fn *get_state;
	void *wait_for_input;
	struct cdk2_simple_pointer_mode *mode;
};

struct cdk2_hid_item {
	UINT16 format;
	UINT8 size;
	UINT8 type;
	UINT8 tag;
	union { UINT8 u8; UINT16 u16; UINT32 u32; const UINT8 *long_data; } data;
};

struct cdk2_usb_mouse;
struct cdk2_mouse_driver_binding;
struct cdk2_mouse_component_name;
typedef EFI_STATUS CDK2_MS_ABI cdk2_mouse_supported_fn(
	struct cdk2_mouse_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_mouse_start_fn(
	struct cdk2_mouse_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_mouse_stop_fn(
	struct cdk2_mouse_driver_binding *, void *, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_mouse_name_fn(struct cdk2_mouse_component_name *,
	CHAR8 *, CHAR16 * *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_mouse_controller_name_fn(
	struct cdk2_mouse_component_name *, void *, void *, CHAR8 *, CHAR16 * *);

struct cdk2_mouse_driver_binding {
	cdk2_mouse_supported_fn *supported;
	cdk2_mouse_start_fn *start;
	cdk2_mouse_stop_fn *stop;
	UINT32 version;
	void *image_handle;
	void *driver_binding_handle;
};

struct cdk2_mouse_component_name {
	cdk2_mouse_name_fn *get_driver_name;
	cdk2_mouse_controller_name_fn *get_controller_name;
	CHAR8 *supported_languages;
};
typedef EFI_STATUS cdk2_mouse_open_fn(void *, void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS cdk2_mouse_close_fn(void *, void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS cdk2_mouse_install_fn(void *, void *, const EFI_GUID *, void *);
typedef EFI_STATUS cdk2_mouse_event_fn(void *, UINT32, UINTN, void *, void *, void **);
typedef EFI_STATUS cdk2_mouse_close_event_fn(void *, void *);
typedef EFI_STATUS cdk2_mouse_signal_fn(void *, void *);
typedef EFI_STATUS cdk2_mouse_timer_fn(void *, void *, UINT32, UINT64);
typedef EFI_STATUS cdk2_mouse_allocate_fn(void *, UINTN, void **);
typedef void cdk2_mouse_free_fn(void *, void *);

struct cdk2_usb_mouse_ops {
	cdk2_mouse_open_fn *open;
	cdk2_mouse_close_fn *close;
	cdk2_mouse_install_fn *install;
	cdk2_mouse_install_fn *uninstall;
	cdk2_mouse_event_fn *create_event;
	cdk2_mouse_close_event_fn *close_event;
	cdk2_mouse_signal_fn *signal_event;
	cdk2_mouse_timer_fn *set_timer;
	cdk2_mouse_allocate_fn *allocate;
	cdk2_mouse_free_fn *free;
};

struct cdk2_usb_mouse {
	struct cdk2_usb_mouse *next;
	const struct cdk2_usb_mouse_ops *ops;
	void *context;
	void *image;
	void *controller;
	struct cdk2_usb_io *usb_io;
	void *device_path;
	struct cdk2_usb_interface_descriptor interface;
	struct cdk2_usb_endpoint_descriptor endpoint;
	struct cdk2_simple_pointer pointer;
	struct cdk2_simple_pointer_state state;
	struct cdk2_simple_pointer_mode mode;
	void *recovery_event;
	UINT8 button_count;
	UINT8 button_min;
	UINT8 button_max;
	BOOLEAN button_page;
	BOOLEAN state_changed;
	BOOLEAN usb_open;
	BOOLEAN pointer_installed;
	BOOLEAN polling;
};

struct cdk2_usb_mouse_binding {
	const struct cdk2_usb_mouse_ops *ops;
	void *context;
	void *image;
	struct cdk2_usb_mouse *instances;
	struct cdk2_mouse_driver_binding driver;
	struct cdk2_mouse_component_name component_name;
	struct cdk2_mouse_component_name component_name2;
};

extern const EFI_GUID cdk2_usb_io_guid;
extern const EFI_GUID cdk2_device_path_guid;
extern const EFI_GUID cdk2_simple_pointer_guid;

const UINT8 *cdk2_usb_mouse_next_item(const UINT8 *position, const UINT8 *end,
	struct cdk2_hid_item *item);
EFI_STATUS cdk2_usb_mouse_parse_report(struct cdk2_usb_mouse *mouse,
	const UINT8 *report, UINTN size);
EFI_STATUS CDK2_MS_ABI cdk2_usb_mouse_interrupt(void *data, UINTN length, void *context,
	UINT32 result);
EFI_STATUS cdk2_usb_mouse_start(struct cdk2_usb_mouse *mouse, void *controller);
EFI_STATUS cdk2_usb_mouse_stop(struct cdk2_usb_mouse *mouse);
BOOLEAN cdk2_is_usb_mouse(struct cdk2_usb_io *usb_io);
void cdk2_usb_mouse_binding_init(struct cdk2_usb_mouse_binding *binding,
	const struct cdk2_usb_mouse_ops *ops, void *context, void *image);

#endif
