/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_console_font.h>
#include <cdk2/graphics_console_package.h>
#include <stdio.h>
#include <stdlib.h>

static UINTN allocations, frees, additions, removals;
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); allocations++; return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); frees++; }
static EFI_STATUS CDK2_MS_ABI add(const struct cdk2_hii_database_view *database,
	const void *list, void *driver, void **handle)
{ (void)database; (void)driver; if (list == NULL) return EFI_INVALID_PARAMETER; additions++; *handle = (void *)1; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI remove_package(const struct cdk2_hii_database_view *database,
	void *handle)
{ (void)database; if (handle == NULL) return EFI_INVALID_PARAMETER; removals++; return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_hii_database_view database = { add, remove_package };
	struct cdk2_graphics_font_package package = { 0 };

	if (cdk2_graphics_font_install(&package, &database, allocate, release, NULL) !=
	    EFI_SUCCESS || allocations != 1U || additions != 1U || package.handle == NULL)
		return 1;
	if (cdk2_graphics_font_remove(&package) != EFI_SUCCESS || removals != 1U ||
	    frees != 1U || package.handle != NULL)
		return 1;
	return 0;
}
