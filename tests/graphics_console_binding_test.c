/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_console_binding.h>
#include <stdio.h>
#include <stdlib.h>

static UINTN opens, closes, installs, uninstalls, blts, fail_open, allocations, releases;
static UINTN last_blt_operation, last_blt_x, last_blt_y, last_blt_width, last_blt_height;
static EFI_STATUS uninstall_status;
static struct cdk2_gop_view gop;
static struct cdk2_gop_mode_info gop_info = {
	.horizontal_resolution = 800U,
	.vertical_resolution = 600U,
};
static struct cdk2_gop_protocol_mode gop_mode = { .info = &gop_info };
static struct cdk2_hii_font_view font;
static UINTN renders;
static UINTN publishes;
static UINTN unpublishes, fail_publish;
static UINTN notifications;
static UINTN draws, fills, scrolls, cursors;
static UINT32 last_draw_row;
static BOOLEAN last_cursor_visible;
static EFI_STATUS draw_character(void *context, CHAR16 character, UINT32 column,
	UINT32 row, UINT8 attribute, BOOLEAN wide)
{ (void)context; (void)character; (void)column; (void)attribute; (void)wide; draws++; last_draw_row = row; return EFI_SUCCESS; }
static EFI_STATUS fill_cells(void *context, UINT32 column, UINT32 row, UINT32 columns,
	UINT32 rows, UINT8 attribute)
{ (void)context; (void)column; (void)row; (void)columns; (void)rows; (void)attribute; fills++; return EFI_SUCCESS; }
static EFI_STATUS scroll_cells(void *context, UINT32 rows, UINT8 attribute)
{ (void)context; (void)rows; (void)attribute; scrolls++; return EFI_SUCCESS; }
static EFI_STATUS cursor(void *context, UINT32 column, UINT32 row, BOOLEAN visible,
	UINT8 attribute)
{ (void)context; (void)column; (void)row; (void)attribute; cursors++; last_cursor_visible = visible; return EFI_SUCCESS; }
static EFI_STATUS publish(void *context, void *handle, const EFI_GUID *guid, void *interface)
{
	(void)context; (void)guid;
	if (handle == NULL || interface == NULL)
		return EFI_INVALID_PARAMETER;
	publishes++;
	if (publishes == fail_publish)
		return EFI_DEVICE_ERROR;
	return EFI_SUCCESS;
}
static EFI_STATUS unpublish(void *context, void *handle, const EFI_GUID *guid,
	void *interface)
{
	(void)context; (void)guid;
	if (handle == NULL || interface == NULL)
		return EFI_INVALID_PARAMETER;
	unpublishes++;
	return EFI_SUCCESS;
}
static EFI_STATUS notify(void *context, const EFI_GUID *guid)
{ (void)context; if (guid == NULL) return EFI_INVALID_PARAMETER; notifications++; return EFI_SUCCESS; }

static EFI_STATUS open_protocol(void *context, void *controller, const EFI_GUID *guid,
	UINT32 attributes, void **interface)
{
	(void)context; (void)controller; (void)guid;
	if (attributes != CDK2_OPEN_BY_DRIVER)
		return EFI_INVALID_PARAMETER;
	opens++;
	if (opens == fail_open)
		return EFI_DEVICE_ERROR;
	*interface = (opens & 1U) == 0U ? (void *)&gop : (void *)&font;
	return EFI_SUCCESS;
}
static EFI_STATUS allocate_binding(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = calloc(1, size); allocations++; return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release_binding(void *context, void *buffer)
{ (void)context; releases++; free(buffer); }

static EFI_STATUS close_protocol(void *context, void *controller, const EFI_GUID *guid)
{ (void)context; (void)controller; (void)guid; closes++; return EFI_SUCCESS; }
static EFI_STATUS install(void *context, void *controller, const EFI_GUID *guid, void *interface)
{ (void)context; (void)controller; (void)guid; (void)interface; installs++; return EFI_SUCCESS; }
static EFI_STATUS uninstall(void *context, void *controller, const EFI_GUID *guid, void *interface)
{ (void)context; (void)controller; (void)guid; (void)interface; uninstalls++; return uninstall_status; }
static EFI_STATUS locate(void *context, const EFI_GUID *guid, void **interface)
{ (void)context; (void)guid; *interface = &font; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI blt(void *graphics, void *buffer, UINTN operation,
	UINTN sx, UINTN sy,
	UINTN dx, UINTN dy, UINTN width, UINTN height, UINTN delta)
{ (void)graphics; (void)buffer; (void)sx; (void)sy; (void)delta; blts++; last_blt_operation = operation; last_blt_x = dx; last_blt_y = dy; last_blt_width = width; last_blt_height = height; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI render(const struct cdk2_hii_font_view *hii, UINT32 flags,
	const CHAR16 *string, const struct cdk2_font_display_info *display,
	struct cdk2_image_output **image, UINTN x, UINTN y,
	struct cdk2_hii_row_info **rows, UINTN *row_count, UINTN *columns)
{
	(void)hii; (void)display; (void)rows; (void)row_count; (void)columns;
	if (flags != (CDK2_HII_IGNORE_IF_NO_GLYPH | CDK2_HII_IGNORE_LINE_BREAK |
	    CDK2_HII_DIRECT_TO_SCREEN) || string == NULL || image == NULL ||
	    (*image)->image.screen != &gop || (*image)->width != 800U ||
	    (*image)->height != 600U || (x != 2U && x != 4U) || y != 3U)
		return EFI_INVALID_PARAMETER;
	renders++;
	if (x == 4U && (string[0] != 0xfff1U || string[1] != L'A'))
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_glyph(const struct cdk2_hii_font_view *hii,
	CHAR16 character, const struct cdk2_font_display_info *display,
	struct cdk2_image_output **image, UINTN *baseline)
{
	(void)hii; (void)display;
	*image = NULL;
	*baseline = 0U;
	return character == L'A' ? EFI_SUCCESS : EFI_NOT_FOUND;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "graphics binding test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_graphics_console_binding_ops ops = {
		.open = open_protocol,
		.close = close_protocol,
		.locate = locate,
		.install = install,
		.uninstall = uninstall,
		.allocate = allocate_binding,
		.release = release_binding,
	};
	static const struct cdk2_graphics_console_ops text_ops = {
		draw_character, fill_cells, scroll_cells, cursor
	};
	struct cdk2_graphics_console_binding binding = { .ops = &ops };
	cdk2_char16_ptr name = NULL;
	int failures = 0;

	gop.blt = blt;
	gop.mode = &gop_mode;
	font.string_to_image = render;
	font.get_glyph = get_glyph;
	binding.console.mode_count = 0U;
	failures += expect(cdk2_graphics_console_add_mode(&binding.console, 800U, 600U,
		8U, 19U) == EFI_SUCCESS &&
		cdk2_graphics_binding_prepare_text(&binding, &text_ops, &binding) == EFI_SUCCESS &&
		binding.text.mode->max_mode == 1 && binding.text.mode->mode == 0 && fills == 1U,
		"SimpleTextOut methods and mode were not prepared");
	failures += expect(binding.text.output_string(&binding.text, L"A") == EFI_SUCCESS &&
		draws == 1U && binding.text.mode->cursor_column == 1 && cursors == 4U,
		"SimpleTextOut OutputString did not delegate to the text model");
	binding.font = &font;
	failures += expect(binding.text.test_string(&binding.text, L"A") == EFI_SUCCESS &&
		binding.text.test_string(&binding.text, L"Z") == EFI_UNSUPPORTED,
		"TestString did not validate HII glyph availability");
	binding.console.column = binding.console.modes[0].columns - 1U;
	binding.console.row = binding.console.modes[0].rows - 1U;
	{
		CHAR16 wide_string[] = { 0xfff1U, L'A', 0U };

		failures += expect(binding.text.output_string(&binding.text, wide_string) ==
			EFI_SUCCESS && scrolls == 1U &&
			last_draw_row == binding.console.modes[0].rows - 1U,
			"wide wrapped glyph was drawn before bottom-row scrolling");
	}
	failures += expect(binding.text.clear_screen(&binding.text) == EFI_SUCCESS &&
		last_cursor_visible,
		"ClearScreen did not restore the visible cursor after clearing");
	failures += expect(binding.text.set_attribute(&binding.text, 0x40U) == EFI_SUCCESS &&
		binding.text.reset(&binding.text, FALSE) == EFI_SUCCESS &&
		binding.text.mode->attribute == 7,
		"Reset did not restore the default text attribute");
	failures += expect(cdk2_graphics_binding_publish(&binding, &binding, publish, unpublish,
		notify, NULL) == EFI_SUCCESS && publishes == 3U && notifications == 1U &&
		binding.driver.version == 0x10U &&
		binding.driver.image_handle == &binding &&
		binding.component_name.get_driver_name(&binding.component_name, "eng", &name) ==
		EFI_SUCCESS && name != NULL,
		"entry glue did not publish DriverBinding and ComponentName");
	publishes = unpublishes = 0U; fail_publish = 3U;
	failures += expect(cdk2_graphics_binding_publish(&binding, &binding, publish, unpublish,
		notify, NULL) == EFI_DEVICE_ERROR && publishes == 3U && unpublishes == 2U,
		"partial protocol publication was not rolled back");
	fail_publish = 0U;
	fail_open = 2;
	failures += expect(EFI_ERROR(cdk2_graphics_binding_start(&binding, &binding)) &&
		closes == 1U && !binding.device_path_open, "failed Start leaked ownership");
	opens = closes = 0; fail_open = 0;
	failures += expect(cdk2_graphics_binding_start(&binding, &binding) == EFI_SUCCESS &&
		opens == 2U && installs == 1U && binding.text_installed &&
		binding.console.modes[0].columns == 80U &&
		binding.console.modes[0].rows == 25U,
		"Start did not acquire and publish protocols");
	failures += expect(cdk2_graphics_gop_blt(&binding, NULL, 0, 0, 0, 0, 0, 8, 19, 0) ==
		EFI_SUCCESS && blts == 1U, "GOP BLT bridge failed");
	{
		struct cdk2_image_output *image = NULL;
		failures += expect(cdk2_graphics_render_string(&binding, L"A", NULL, &image,
			2, 3, 8, 19) == EFI_SUCCESS && renders == 1U && blts == 1U,
			"HII StringToImage was not directed to the GOP");
	}
	{
		struct cdk2_image_output *image = NULL;
		CHAR16 wide[] = { 0xfff1U, L'A', 0U };
		failures += expect(cdk2_graphics_render_string(&binding, wide, NULL, &image,
			4, 3, 16, 19) == EFI_SUCCESS, "wide HII directive was not preserved");
	}
	uninstall_status = EFI_DEVICE_ERROR;
	failures += expect(cdk2_graphics_binding_stop(&binding) == EFI_DEVICE_ERROR &&
		binding.text_installed && binding.gop_open && closes == 0U,
		"failed uninstall tore down controller ownership");
	uninstall_status = EFI_SUCCESS;
	failures += expect(cdk2_graphics_binding_stop(&binding) == EFI_SUCCESS &&
		uninstalls == 2U && closes == 2U && !binding.text_installed,
		"Stop did not release protocols symmetrically");
	opens = closes = installs = uninstalls = 0U;
	failures += expect(binding.driver.start(&binding.driver, (void *)1, NULL) == EFI_SUCCESS &&
		binding.driver.start(&binding.driver, (void *)2, NULL) == EFI_SUCCESS &&
		binding.instances != NULL && binding.instances->next != NULL &&
		binding.instances->controller != binding.instances->next->controller,
		"controllers did not receive independent binding state");
	failures += expect(binding.driver.stop(&binding.driver, (void *)1, 0, NULL) == EFI_SUCCESS &&
		binding.driver.stop(&binding.driver, (void *)2, 0, NULL) == EFI_SUCCESS &&
		binding.instances == NULL && allocations == 2U && releases == 2U,
		"controller instances were not released independently");
	return failures == 0 ? 0 : 1;
}
