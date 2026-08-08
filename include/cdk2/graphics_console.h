/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GRAPHICS_CONSOLE_H_
#define CDK2_GRAPHICS_CONSOLE_H_

#include <uefi.h>

#define CDK2_GRAPHICS_CONSOLE_MAX_MODES 16U
#define CDK2_GRAPHICS_CONSOLE_WIDE_ATTRIBUTE 0x80U

struct cdk2_graphics_text_mode {
	UINT32 columns;
	UINT32 rows;
	UINT32 glyph_width;
	UINT32 glyph_height;
	UINT32 horizontal_delta;
	UINT32 vertical_delta;
	UINT32 gop_mode;
};

typedef EFI_STATUS cdk2_graphics_draw_fn(void *context, CHAR16 character,
	UINT32 column, UINT32 row, UINT8 attribute, BOOLEAN wide);
typedef EFI_STATUS cdk2_graphics_fill_fn(void *context, UINT32 column,
	UINT32 row, UINT32 columns, UINT32 rows, UINT8 attribute);
typedef EFI_STATUS cdk2_graphics_scroll_fn(void *context, UINT32 rows,
	UINT8 attribute);
typedef EFI_STATUS cdk2_graphics_cursor_fn(void *context, UINT32 column,
	UINT32 row, BOOLEAN visible, UINT8 attribute);

struct cdk2_graphics_console_ops {
	cdk2_graphics_draw_fn *draw;
	cdk2_graphics_fill_fn *fill;
	cdk2_graphics_scroll_fn *scroll;
	cdk2_graphics_cursor_fn *cursor;
};

struct cdk2_graphics_console {
	const struct cdk2_graphics_console_ops *ops;
	void *context;
	struct cdk2_graphics_text_mode modes[CDK2_GRAPHICS_CONSOLE_MAX_MODES];
	UINT32 mode_count;
	UINT32 mode;
	UINT32 column;
	UINT32 row;
	UINT8 attribute;
	BOOLEAN cursor_visible;
	BOOLEAN wide;
};

EFI_STATUS cdk2_graphics_console_add_mode(struct cdk2_graphics_console *console,
	UINT32 width, UINT32 height, UINT32 glyph_width, UINT32 glyph_height);
EFI_STATUS cdk2_graphics_console_add_mode_geometry(struct cdk2_graphics_console *console,
	UINT32 width, UINT32 height, UINT32 columns, UINT32 rows,
	UINT32 glyph_width, UINT32 glyph_height, UINT32 gop_mode);
EFI_STATUS cdk2_graphics_console_init(struct cdk2_graphics_console *console,
	const struct cdk2_graphics_console_ops *ops, void *context);
EFI_STATUS cdk2_graphics_console_set_mode(struct cdk2_graphics_console *console,
	UINT32 mode);
EFI_STATUS cdk2_graphics_console_set_attribute(struct cdk2_graphics_console *console,
	UINTN attribute);
EFI_STATUS cdk2_graphics_console_set_cursor(struct cdk2_graphics_console *console,
	UINTN column, UINTN row);
EFI_STATUS cdk2_graphics_console_enable_cursor(struct cdk2_graphics_console *console,
	BOOLEAN visible);
EFI_STATUS cdk2_graphics_console_test_string(const CHAR16 *string);
EFI_STATUS cdk2_graphics_console_output(struct cdk2_graphics_console *console,
	const CHAR16 *string);

#endif
