/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_console.h>

#define EFI_WARN_UNKNOWN_GLYPH 1U
#define EFI_UNSUPPORTED EFIERR(3)
#define EFI_ALREADY_STARTED EFIERR(20)

static const struct cdk2_graphics_text_mode *current_mode(
	const struct cdk2_graphics_console *console)
{
	return &console->modes[console->mode];
}

static EFI_STATUS update_cursor(struct cdk2_graphics_console *console, BOOLEAN visible)
{
	return console->ops->cursor(console->context, console->column, console->row,
		visible && console->cursor_visible, console->attribute);
}

static EFI_STATUS scroll(struct cdk2_graphics_console *console)
{
	return console->ops->scroll(console->context, 1U, console->attribute);
}

EFI_STATUS cdk2_graphics_console_add_mode(struct cdk2_graphics_console *console,
	UINT32 width, UINT32 height, UINT32 glyph_width, UINT32 glyph_height)
{
	UINT32 columns, rows;

	if (console == NULL || glyph_width == 0U || glyph_height == 0U)
		return EFI_INVALID_PARAMETER;
	columns = width / glyph_width;
	rows = height / glyph_height;
	if (columns == 0U || rows == 0U)
		return EFI_UNSUPPORTED;
	return cdk2_graphics_console_add_mode_geometry(console, width, height,
		columns, rows, glyph_width, glyph_height, 0U);
}

EFI_STATUS cdk2_graphics_console_add_mode_geometry(struct cdk2_graphics_console *console,
	UINT32 width, UINT32 height, UINT32 columns, UINT32 rows,
	UINT32 glyph_width, UINT32 glyph_height, UINT32 gop_mode)
{
	struct cdk2_graphics_text_mode *mode;
	UINT32 index;

	if (console == NULL || columns == 0U || rows == 0U || glyph_width == 0U ||
	    glyph_height == 0U || columns > width / glyph_width ||
	    rows > height / glyph_height)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < console->mode_count; index++)
		if (console->modes[index].columns == columns && console->modes[index].rows == rows)
			return EFI_ALREADY_STARTED;
	if (console->mode_count == CDK2_GRAPHICS_CONSOLE_MAX_MODES)
		return EFI_OUT_OF_RESOURCES;
	mode = &console->modes[console->mode_count++];
	*mode = (struct cdk2_graphics_text_mode) {
		.columns = columns,
		.rows = rows,
		.glyph_width = glyph_width,
		.glyph_height = glyph_height,
		.horizontal_delta = (width - columns * glyph_width) / 2U,
		.vertical_delta = (height - rows * glyph_height) / 2U,
		.gop_mode = gop_mode,
	};
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_graphics_console_init(struct cdk2_graphics_console *console,
	const struct cdk2_graphics_console_ops *ops, void *context)
{
	if (console == NULL || ops == NULL || ops->draw == NULL || ops->fill == NULL ||
	    ops->scroll == NULL || ops->cursor == NULL || console->mode_count == 0U)
		return EFI_INVALID_PARAMETER;
	console->ops = ops;
	console->context = context;
	console->mode = 0;
	console->column = 0;
	console->row = 0;
	console->attribute = 7U;
	console->cursor_visible = TRUE;
	console->wide = FALSE;
	return cdk2_graphics_console_set_mode(console, 0);
}

EFI_STATUS cdk2_graphics_console_set_mode(struct cdk2_graphics_console *console,
	UINT32 mode)
{
	const struct cdk2_graphics_text_mode *text_mode;
	BOOLEAN visible;
	EFI_STATUS status;

	if (console == NULL || mode >= console->mode_count)
		return EFI_UNSUPPORTED;
	status = update_cursor(console, FALSE);
	if (EFI_ERROR(status))
		return status;
	visible = console->cursor_visible;
	console->cursor_visible = FALSE;
	console->mode = mode;
	console->column = 0;
	console->row = 0;
	console->wide = FALSE;
	text_mode = current_mode(console);
	status = console->ops->fill(console->context, 0, 0, text_mode->columns,
		text_mode->rows, console->attribute);
	console->cursor_visible = visible;
	if (EFI_ERROR(status))
		return status;
	return update_cursor(console, TRUE);
}

EFI_STATUS cdk2_graphics_console_set_attribute(struct cdk2_graphics_console *console,
	UINTN attribute)
{
	if (console == NULL || (attribute & ~0x7fU) != 0U)
		return EFI_UNSUPPORTED;
	console->attribute = (UINT8)attribute;
	return update_cursor(console, TRUE);
}

EFI_STATUS cdk2_graphics_console_set_cursor(struct cdk2_graphics_console *console,
	UINTN column, UINTN row)
{
	const struct cdk2_graphics_text_mode *mode;
	EFI_STATUS status;

	if (console == NULL)
		return EFI_INVALID_PARAMETER;
	mode = current_mode(console);
	if (column >= mode->columns || row >= mode->rows)
		return EFI_UNSUPPORTED;
	status = update_cursor(console, FALSE);
	if (EFI_ERROR(status))
		return status;
	console->column = (UINT32)column;
	console->row = (UINT32)row;
	return update_cursor(console, TRUE);
}

EFI_STATUS cdk2_graphics_console_enable_cursor(struct cdk2_graphics_console *console,
	BOOLEAN visible)
{
	EFI_STATUS status;

	if (console == NULL)
		return EFI_INVALID_PARAMETER;
	status = update_cursor(console, FALSE);
	if (EFI_ERROR(status))
		return status;
	console->cursor_visible = visible;
	return update_cursor(console, TRUE);
}

EFI_STATUS cdk2_graphics_console_test_string(const CHAR16 *string)
{
	if (string == NULL)
		return EFI_INVALID_PARAMETER;
	while (*string != 0U) {
		if ((*string < 0x20U && *string != L'\b' && *string != L'\n' &&
		     *string != L'\r') || *string == 0xffffU)
			return EFI_UNSUPPORTED;
		string++;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_graphics_console_output(struct cdk2_graphics_console *console,
	const CHAR16 *string)
{
	const struct cdk2_graphics_text_mode *mode;
	EFI_STATUS result = EFI_SUCCESS, status;

	if (console == NULL || string == NULL)
		return EFI_INVALID_PARAMETER;
	mode = current_mode(console);
	status = update_cursor(console, FALSE);
	if (EFI_ERROR(status))
		return status;
	while (*string != 0U) {
		CHAR16 character = *string++;

		if (character == L'\b') {
			if (console->column != 0U)
				console->column--;
			continue;
		}
		if (character == L'\r') {
			console->column = 0;
			continue;
		}
		if (character == L'\n') {
			console->row++;
		} else if (character == 0xFFF1U) {
			console->wide = TRUE;
			continue;
		} else if (character == 0xFFF0U) {
			console->wide = FALSE;
			continue;
		} else {
			UINT32 cells = console->wide ? 2U : 1U;

			if (console->column + cells > mode->columns) {
				console->column = 0;
				console->row++;
			}
			if (console->row >= mode->rows) {
				status = scroll(console);
				if (EFI_ERROR(status))
					return status;
				console->row = mode->rows - 1U;
			}
			status = console->ops->draw(console->context, character,
				console->column, console->row, console->attribute, console->wide);
			if (status == EFI_WARN_UNKNOWN_GLYPH)
				result = status;
			else if (EFI_ERROR(status)) {
				(void)update_cursor(console, TRUE);
				return status;
			}
			console->column += cells;
		}
		if (console->column >= mode->columns) {
			console->column = 0;
			console->row++;
		}
		if (console->row >= mode->rows) {
			status = scroll(console);
			if (EFI_ERROR(status))
				return status;
			console->row = mode->rows - 1U;
		}
	}
	status = update_cursor(console, TRUE);
	return EFI_ERROR(status) ? status : result;
}
