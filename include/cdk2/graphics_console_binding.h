/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GRAPHICS_CONSOLE_BINDING_H_
#define CDK2_GRAPHICS_CONSOLE_BINDING_H_

#include <cdk2/graphics_console.h>

#define CDK2_OPEN_BY_DRIVER 0x10U
#define CDK2_HII_IGNORE_IF_NO_GLYPH 0x20U
#define CDK2_HII_IGNORE_LINE_BREAK 0x40U
#define CDK2_HII_DIRECT_TO_SCREEN 0x80U

struct cdk2_graphics_console_binding;
struct cdk2_simple_text_output_view;
struct cdk2_driver_binding_view;
struct cdk2_component_name_view;
struct cdk2_gop_view;
struct cdk2_hii_font_view;
struct cdk2_gop_mode_info;
struct cdk2_gop_protocol_mode;
struct cdk2_image_output;
struct cdk2_font_display_info;
struct cdk2_hii_row_info;
struct cdk2_font_info;
typedef CHAR16 * cdk2_char16_ptr;
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_string_id_to_image_fn(
	const struct cdk2_hii_font_view *, UINT32, void *, UINT16, const CHAR8 *,
	const struct cdk2_font_display_info *, struct cdk2_image_output **,
	UINTN, UINTN, struct cdk2_hii_row_info **, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_glyph_fn(
	const struct cdk2_hii_font_view *, CHAR16,
	const struct cdk2_font_display_info *, struct cdk2_image_output **, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_font_info_fn(
	const struct cdk2_hii_font_view *, void **,
	const struct cdk2_font_display_info *, struct cdk2_font_display_info **,
	const CHAR16 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_gop_query_fn(struct cdk2_gop_view *, UINT32,
	UINTN *, struct cdk2_gop_mode_info **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_gop_set_fn(struct cdk2_gop_view *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_string_to_image_fn(
	const struct cdk2_hii_font_view *, UINT32, const CHAR16 *,
	const struct cdk2_font_display_info *, struct cdk2_image_output **,
	UINTN, UINTN, struct cdk2_hii_row_info **, UINTN *, UINTN *);
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
typedef EFI_STATUS CDK2_MS_ABI cdk2_component_driver_name_fn(
	struct cdk2_component_name_view *, CHAR8 *, cdk2_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_component_controller_name_fn(
	struct cdk2_component_name_view *, void *, void *, CHAR8 *, cdk2_char16_ptr *);
typedef EFI_STATUS cdk2_binding_open_fn(void *context, void *controller,
	const EFI_GUID * protocol, UINT32 attributes, void **interface);
typedef EFI_STATUS cdk2_binding_close_fn(void *context, void *controller,
	const EFI_GUID * protocol);
typedef EFI_STATUS cdk2_binding_locate_fn(void *context, const EFI_GUID * protocol,
	void **interface);
typedef EFI_STATUS cdk2_binding_install_fn(void *context, void *controller,
	const EFI_GUID * protocol, void *interface);
typedef EFI_STATUS cdk2_binding_uninstall_fn(void *context, void *controller,
	const EFI_GUID * protocol, void *interface);
typedef EFI_STATUS cdk2_binding_blt_fn(void *gop, void *buffer, UINTN operation,
	UINTN source_x, UINTN source_y, UINTN destination_x, UINTN destination_y,
	UINTN width, UINTN height, UINTN delta);
typedef EFI_STATUS cdk2_binding_publish_fn(void *, void *, const EFI_GUID *, void *);
typedef EFI_STATUS cdk2_binding_notify_fn(void *, const EFI_GUID *);

struct cdk2_graphics_console_binding_ops {
	cdk2_binding_open_fn *open;
	cdk2_binding_close_fn *close;
	cdk2_binding_locate_fn *locate;
	cdk2_binding_install_fn *install;
	cdk2_binding_uninstall_fn *uninstall;
};

struct cdk2_gop_view {
	cdk2_gop_query_fn *query_mode;
	cdk2_gop_set_fn *set_mode;
	cdk2_binding_blt_fn *blt;
	struct cdk2_gop_protocol_mode *mode;
};

struct cdk2_gop_mode_info {
	UINT32 version;
	UINT32 horizontal_resolution;
	UINT32 vertical_resolution;
	UINT32 pixel_format;
	UINT32 pixel_information[4];
	UINT32 pixels_per_scan_line;
};

struct cdk2_gop_protocol_mode {
	UINT32 max_mode;
	UINT32 mode;
	struct cdk2_gop_mode_info *info;
	UINTN size_of_info;
	UINT64 frame_buffer_base;
	UINTN frame_buffer_size;
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
	struct cdk2_simple_text_output_mode_view *mode;
};

struct cdk2_simple_text_output_mode_view {
	INT32 max_mode;
	INT32 mode;
	INT32 attribute;
	INT32 cursor_column;
	INT32 cursor_row;
	BOOLEAN cursor_visible;
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
	cdk2_hii_string_to_image_fn *string_to_image;
	cdk2_hii_string_id_to_image_fn *string_id_to_image;
	cdk2_hii_get_glyph_fn *get_glyph;
	cdk2_hii_get_font_info_fn *get_font_info;
};

struct cdk2_graphics_pixel {
	UINT8 blue;
	UINT8 green;
	UINT8 red;
	UINT8 reserved;
};

struct cdk2_font_info {
	UINT32 style;
	UINT16 size;
	CHAR16 name[1];
};

struct cdk2_font_display_info {
	struct cdk2_graphics_pixel foreground;
	struct cdk2_graphics_pixel background;
	UINT32 mask;
	struct cdk2_font_info font;
};

struct cdk2_image_output {
	UINT16 width;
	UINT16 height;
	union {
		struct cdk2_graphics_pixel *bitmap;
		struct cdk2_gop_view *screen;
	} image;
};

struct cdk2_graphics_console_binding {
	const struct cdk2_graphics_console_binding_ops *ops;
	void *context;
	void *controller;
	struct cdk2_gop_view *gop;
	struct cdk2_hii_font_view *font;
	struct cdk2_simple_text_output_view text;
	struct cdk2_simple_text_output_mode_view text_mode;
	struct cdk2_graphics_console console;
	struct cdk2_driver_binding_view driver;
	struct cdk2_component_name_view component_name;
	struct cdk2_component_name_view component_name2;
	BOOLEAN device_path_open;
	BOOLEAN gop_open;
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
EFI_STATUS cdk2_graphics_render_string(struct cdk2_graphics_console_binding *binding,
	const CHAR16 *string, const struct cdk2_font_display_info *display,
	struct cdk2_image_output **image, UINTN x, UINTN y, UINTN width, UINTN height);
EFI_STATUS cdk2_graphics_binding_publish(struct cdk2_graphics_console_binding *binding,
	void *image, cdk2_binding_publish_fn *publish, cdk2_binding_notify_fn *notify,
	void *context);
EFI_STATUS cdk2_graphics_binding_prepare_text(struct cdk2_graphics_console_binding *binding,
	const struct cdk2_graphics_console_ops *ops, void *context);

#endif
