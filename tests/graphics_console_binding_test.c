/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_console_binding.h>
#include <stdio.h>

static UINTN opens, closes, installs, uninstalls, blts, fail_open;
static struct cdk2_gop_view gop;
static struct cdk2_hii_font_view font;
static UINTN renders;
static UINTN publishes;
static UINTN notifications;
static UINTN draws, fills, scrolls, cursors;
static EFI_STATUS draw_character(void *context, CHAR16 character, UINT32 column,
	UINT32 row, UINT8 attribute, BOOLEAN wide)
{ (void)context; (void)character; (void)column; (void)row; (void)attribute; (void)wide; draws++; return EFI_SUCCESS; }
static EFI_STATUS fill_cells(void *context, UINT32 column, UINT32 row, UINT32 columns,
	UINT32 rows, UINT8 attribute)
{ (void)context; (void)column; (void)row; (void)columns; (void)rows; (void)attribute; fills++; return EFI_SUCCESS; }
static EFI_STATUS scroll_cells(void *context, UINT32 rows, UINT8 attribute)
{ (void)context; (void)rows; (void)attribute; scrolls++; return EFI_SUCCESS; }
static EFI_STATUS cursor(void *context, UINT32 column, UINT32 row, BOOLEAN visible,
	UINT8 attribute)
{ (void)context; (void)column; (void)row; (void)visible; (void)attribute; cursors++; return EFI_SUCCESS; }
static EFI_STATUS publish(void *context, void *handle, const EFI_GUID *guid, void *interface)
{
	(void)context; (void)guid;
	if (handle == NULL || interface == NULL)
		return EFI_INVALID_PARAMETER;
	publishes++;
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
	*interface = opens == 2U ? (void *)&gop : (void *)&font;
	return EFI_SUCCESS;
}

static EFI_STATUS close_protocol(void *context, void *controller, const EFI_GUID *guid)
{ (void)context; (void)controller; (void)guid; closes++; return EFI_SUCCESS; }
static EFI_STATUS install(void *context, void *controller, const EFI_GUID *guid, void *interface)
{ (void)context; (void)controller; (void)guid; (void)interface; installs++; return EFI_SUCCESS; }
static EFI_STATUS uninstall(void *context, void *controller, const EFI_GUID *guid, void *interface)
{ (void)context; (void)controller; (void)guid; (void)interface; uninstalls++; return EFI_SUCCESS; }
static EFI_STATUS locate(void *context, const EFI_GUID *guid, void **interface)
{ (void)context; (void)guid; *interface = &font; return EFI_SUCCESS; }
static EFI_STATUS blt(void *graphics, void *buffer, UINTN operation, UINTN sx, UINTN sy,
	UINTN dx, UINTN dy, UINTN width, UINTN height, UINTN delta)
{ (void)graphics; (void)buffer; (void)operation; (void)sx; (void)sy; (void)dx; (void)dy; (void)width; (void)height; (void)delta; blts++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI render(const struct cdk2_hii_font_view *hii, UINT32 flags,
	const CHAR16 *string, const struct cdk2_font_display_info *display,
	struct cdk2_image_output **image, UINTN x, UINTN y,
	struct cdk2_hii_row_info **rows, UINTN *row_count, UINTN *columns)
{
	(void)hii; (void)display; (void)rows; (void)row_count; (void)columns;
	if (flags != (CDK2_HII_IGNORE_IF_NO_GLYPH | CDK2_HII_IGNORE_LINE_BREAK |
	    CDK2_HII_DIRECT_TO_SCREEN) || string == NULL || image == NULL ||
	    (*image)->image.screen != &gop || (*image)->width != 8U ||
	    (*image)->height != 19U || x != 2U || y != 3U)
		return EFI_INVALID_PARAMETER;
	renders++;
	return EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "graphics binding test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_graphics_console_binding_ops ops = {
		open_protocol, close_protocol, locate, install, uninstall
	};
	static const struct cdk2_graphics_console_ops text_ops = {
		draw_character, fill_cells, scroll_cells, cursor
	};
	struct cdk2_graphics_console_binding binding = { .ops = &ops };
	cdk2_char16_ptr name = NULL;
	int failures = 0;

	gop.blt = blt;
	font.string_to_image = render;
	binding.console.mode_count = 0U;
	failures += expect(cdk2_graphics_console_add_mode(&binding.console, 800U, 600U,
		8U, 19U) == EFI_SUCCESS &&
		cdk2_graphics_binding_prepare_text(&binding, &text_ops, &binding) == EFI_SUCCESS &&
		binding.text.mode->max_mode == 1 && binding.text.mode->mode == 0 && fills == 1U,
		"SimpleTextOut methods and mode were not prepared");
	failures += expect(binding.text.output_string(&binding.text, L"A") == EFI_SUCCESS &&
		draws == 1U && binding.text.mode->cursor_column == 1 && cursors == 2U,
		"SimpleTextOut OutputString did not delegate to the text model");
	failures += expect(cdk2_graphics_binding_publish(&binding, &binding, publish, notify,
		NULL) == EFI_SUCCESS && publishes == 3U && notifications == 1U &&
		binding.driver.version == 0x10U &&
		binding.driver.image_handle == &binding &&
		binding.component_name.get_driver_name(&binding.component_name, "eng", &name) ==
		EFI_SUCCESS && name != NULL,
		"entry glue did not publish DriverBinding and ComponentName");
	fail_open = 2;
	failures += expect(EFI_ERROR(cdk2_graphics_binding_start(&binding, &binding)) &&
		closes == 1U && !binding.device_path_open, "failed Start leaked ownership");
	opens = closes = 0; fail_open = 0;
	failures += expect(cdk2_graphics_binding_start(&binding, &binding) == EFI_SUCCESS &&
		opens == 2U && installs == 1U && binding.text_installed,
		"Start did not acquire and publish protocols");
	failures += expect(cdk2_graphics_gop_blt(&binding, NULL, 0, 0, 0, 0, 0, 8, 19, 0) ==
		EFI_SUCCESS && blts == 1U, "GOP BLT bridge failed");
	{
		struct cdk2_image_output *image = NULL;
		failures += expect(cdk2_graphics_render_string(&binding, L"A", NULL, &image,
			2, 3, 8, 19) == EFI_SUCCESS && renders == 1U && blts == 1U,
			"HII StringToImage was not directed to the GOP");
	}
	failures += expect(cdk2_graphics_binding_stop(&binding) == EFI_SUCCESS &&
		uninstalls == 1U && closes == 2U && !binding.text_installed,
		"Stop did not release protocols symmetrically");
	return failures == 0 ? 0 : 1;
}
