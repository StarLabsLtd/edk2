/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GRAPHICS_CONSOLE_BINDING_H_
#define CDK2_GRAPHICS_CONSOLE_BINDING_H_

#include <cdk2/graphics_console.h>

#define CDK2_OPEN_BY_DRIVER 0x10U

struct cdk2_graphics_console_binding;
struct cdk2_simple_text_output_view;
struct cdk2_driver_binding_view;
struct cdk2_component_name_view;
struct cdk2_gop_view;
struct cdk2_hii_font_view;
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_reset_fn(struct cdk2_simple_text_output_view *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_string_fn(struct cdk2_simple_text_output_view *, CHAR16 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_query_fn(struct cdk2_simple_text_output_view *, UINTN, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_value_fn(struct cdk2_simple_text_output_view *, UINTN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_clear_fn(struct cdk2_simple_text_output_view *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_cursor_fn(struct cdk2_simple_text_output_view *, UINTN, UINTN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_text_visible_fn(struct cdk2_simple_text_output_view *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_driver_supported_fn(struct cdk2_driver_binding_view *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_driver_start_fn(struct cdk2_driver_binding_view *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_driver_stop_fn(struct cdk2_driver_binding_view *, void *, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_component_driver_name_fn(struct cdk2_component_name_view *, CHAR8 *, CHAR16 **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_component_controller_name_fn(struct cdk2_component_name_view *, void *, void *, CHAR8 *, CHAR16 **);
typedef EFI_STATUS cdk2_binding_open_fn(void *context, void *controller,
	const EFI_GUID * protocol, UINT32 attributes, void **interface);
typedef EFI_STATUS cdk2_binding_close_fn(void *context, void *controller,
	const EFI_GUID * protocol);
typedef EFI_STATUS cdk2_binding_install_fn(void *context, void *controller,
	const EFI_GUID * protocol, void *interface);
typedef EFI_STATUS cdk2_binding_uninstall_fn(void *context, void *controller,
	const EFI_GUID * protocol, void *interface);
typedef EFI_STATUS cdk2_binding_blt_fn(void *gop, void *buffer, UINTN operation,
	UINTN source_x, UINTN source_y, UINTN destination_x, UINTN destination_y,
	UINTN width, UINTN height, UINTN delta);

struct cdk2_graphics_console_binding_ops {
	cdk2_binding_open_fn *open;
	cdk2_binding_close_fn *close;
	cdk2_binding_install_fn *install;
	cdk2_binding_uninstall_fn *uninstall;
};

struct cdk2_gop_view {
	void *query_mode;
	void *set_mode;
	cdk2_binding_blt_fn *blt;
	void *mode;
};

struct cdk2_simple_text_output_view {
	cdk2_text_reset_fn *reset;
	cdk2_text_string_fn *output_string;
	cdk2_text_string_fn *test_string;
	cdk2_text_query_fn *query_mode;
	cdk2_text_value_fn *set_mode;
	cdk2_text_value_fn *set_attribute;
	cdk2_text_clear_fn *clear_screen;
	cdk2_text_cursor_fn *set_cursor_position;
	cdk2_text_visible_fn *enable_cursor;
	void *mode;
};

struct cdk2_driver_binding_view {
	cdk2_driver_supported_fn *supported;
	cdk2_driver_start_fn *start;
	cdk2_driver_stop_fn *stop;
	UINT32 version;
	void *image_handle;
	void *driver_binding_handle;
};

struct cdk2_component_name_view {
	cdk2_component_driver_name_fn *get_driver_name;
	cdk2_component_controller_name_fn *get_controller_name;
	CHAR8 *supported_languages;
};

struct cdk2_hii_font_view {
	void *string_to_image;
	void *string_id_to_image;
	void *get_glyph;
	void *get_font_info;
};

struct cdk2_graphics_console_binding {
	const struct cdk2_graphics_console_binding_ops *ops;
	void *context;
	void *controller;
	struct cdk2_gop_view *gop;
	struct cdk2_hii_font_view *font;
	struct cdk2_simple_text_output_view text;
	BOOLEAN device_path_open;
	BOOLEAN gop_open;
	BOOLEAN font_open;
	BOOLEAN text_installed;
};

EFI_STATUS cdk2_graphics_binding_supported(struct cdk2_graphics_console_binding *binding,
	void *controller);
EFI_STATUS cdk2_graphics_binding_start(struct cdk2_graphics_console_binding *binding,
	void *controller);
EFI_STATUS cdk2_graphics_binding_stop(struct cdk2_graphics_console_binding *binding);
EFI_STATUS cdk2_graphics_gop_blt(struct cdk2_graphics_console_binding *binding,
	void *buffer, UINTN operation, UINTN source_x, UINTN source_y,
	UINTN destination_x, UINTN destination_y, UINTN width, UINTN height, UINTN delta);

#endif
