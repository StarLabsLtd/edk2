/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_console_binding.h>
#include <stdio.h>

static UINTN opens, closes, installs, uninstalls, blts, fail_open;
static struct cdk2_gop_view gop;
static struct cdk2_hii_font_view font;

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
static EFI_STATUS blt(void *graphics, void *buffer, UINTN operation, UINTN sx, UINTN sy,
	UINTN dx, UINTN dy, UINTN width, UINTN height, UINTN delta)
{ (void)graphics; (void)buffer; (void)operation; (void)sx; (void)sy; (void)dx; (void)dy; (void)width; (void)height; (void)delta; blts++; return EFI_SUCCESS; }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "graphics binding test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_graphics_console_binding_ops ops = {
		open_protocol, close_protocol, install, uninstall
	};
	struct cdk2_graphics_console_binding binding = { .ops = &ops };
	int failures = 0;

	gop.blt = blt;
	fail_open = 2;
	failures += expect(EFI_ERROR(cdk2_graphics_binding_start(&binding, &binding)) &&
		closes == 1U && !binding.device_path_open, "failed Start leaked ownership");
	opens = closes = 0; fail_open = 0;
	failures += expect(cdk2_graphics_binding_start(&binding, &binding) == EFI_SUCCESS &&
		opens == 3U && installs == 1U && binding.text_installed,
		"Start did not acquire and publish protocols");
	failures += expect(cdk2_graphics_gop_blt(&binding, NULL, 0, 0, 0, 0, 0, 8, 19, 0) ==
		EFI_SUCCESS && blts == 1U, "GOP BLT bridge failed");
	failures += expect(cdk2_graphics_binding_stop(&binding) == EFI_SUCCESS &&
		uninstalls == 1U && closes == 3U && !binding.text_installed,
		"Stop did not release protocols symmetrically");
	return failures == 0 ? 0 : 1;
}
