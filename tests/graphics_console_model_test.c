/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_console.h>
#include <stdio.h>

#define EFI_ALREADY_STARTED EFIERR(20)

static UINTN draws, fills, scrolls, cursors;
static CHAR16 last_character;
static UINT32 last_column, last_row;
static BOOLEAN last_wide, last_cursor_visible;

static EFI_STATUS draw(void *context, CHAR16 character, UINT32 column, UINT32 row,
	UINT8 attribute, BOOLEAN wide)
{
	(void)context;
	(void)attribute;
	draws++;
	last_character = character;
	last_column = column;
	last_row = row;
	last_wide = wide;
	return character == L'?' ? 1U : EFI_SUCCESS;
}

static EFI_STATUS fill(void *context, UINT32 column, UINT32 row, UINT32 columns,
	UINT32 rows, UINT8 attribute)
{
	(void)context; (void)column; (void)row; (void)columns; (void)rows; (void)attribute;
	fills++;
	return EFI_SUCCESS;
}

static EFI_STATUS cursor(void *context, UINT32 column, UINT32 row, BOOLEAN visible,
	UINT8 attribute)
{
	(void)context; (void)attribute;
	cursors++;
	last_column = column;
	last_row = row;
	last_cursor_visible = visible;
	return EFI_SUCCESS;
}

static EFI_STATUS scroll(void *context, UINT32 rows, UINT8 attribute)
{
	(void)context;
	(void)rows;
	(void)attribute;
	scrolls++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "graphics-console model test: %s\n", message);
	return !condition;
}

int main(void)
{
	static const struct cdk2_graphics_console_ops ops = { draw, fill, scroll, cursor };
	struct cdk2_graphics_console console = {0};
	int failures = 0;

	failures += expect(cdk2_graphics_console_add_mode(&console, 800, 600, 8, 19) ==
		EFI_SUCCESS && console.modes[0].columns == 100U &&
		console.modes[0].rows == 31U && console.modes[0].vertical_delta == 5U,
		"mode geometry was not centered");
	failures += expect(cdk2_graphics_console_add_mode(&console, 800, 600, 8, 19) ==
		EFI_ALREADY_STARTED, "duplicate mode was accepted");
	failures += expect(cdk2_graphics_console_init(&console, &ops, NULL) == EFI_SUCCESS &&
		fills == 1U && console.attribute == 7U, "console initialization failed");
	failures += expect(cdk2_graphics_console_output(&console, L"AB\bC\r\nD") ==
		EFI_SUCCESS && draws == 4U && last_character == L'D' && last_column == 1U &&
		last_row == 1U, "control-character cursor movement is wrong");
	failures += expect(cdk2_graphics_console_output(&console, L"\xFFF1Z\xFFF0") ==
		EFI_SUCCESS && last_wide && console.column == 3U && !console.wide,
		"wide/narrow glyph state is wrong");
	failures += expect(cdk2_graphics_console_output(&console, L"?") == 1U,
		"unknown-glyph warning was lost");
	failures += expect(cdk2_graphics_console_set_cursor(&console, 99, 30) == EFI_SUCCESS &&
		last_column == 99U && last_row == 30U, "valid cursor position was rejected");
	failures += expect(cdk2_graphics_console_output(&console, L"XY") == EFI_SUCCESS &&
		scrolls == 1U && console.row == 30U, "bottom-row wrap did not scroll");
	failures += expect(cdk2_graphics_console_set_cursor(&console, 100, 0) == EFI_UNSUPPORTED,
		"out-of-range cursor was accepted");
	failures += expect(cdk2_graphics_console_set_attribute(&console, 0x80) ==
		EFI_UNSUPPORTED, "invalid attribute was accepted");
	failures += expect(cdk2_graphics_console_enable_cursor(&console, FALSE) == EFI_SUCCESS &&
		!last_cursor_visible && cursors != 0U, "cursor disable was not rendered");
	failures += expect(cdk2_graphics_console_test_string(L"ok\n") == EFI_SUCCESS &&
		cdk2_graphics_console_test_string(L"\x1") == EFI_UNSUPPORTED,
		"string validation is wrong");
	return failures == 0 ? 0 : 1;
}
