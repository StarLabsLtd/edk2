/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer) { (void)context; free(buffer); }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII font test: %s\n", message); return !condition; }
int main(void)
{
	static const struct cdk2_hii_database_ops ops = { .allocate = allocate, .release = release };
	struct cdk2_hii_database database;
	struct cdk2_hii_pixel pixels[8] = { 0 };
	struct cdk2_hii_image_output *output = NULL;
	struct cdk2_hii_row_info *rows = NULL;
	UINTN row_count = 0U, column = 0U;
	struct cdk2_hii_font_info *font_info = NULL;
	void *font_handle = NULL;
	int failures = 0;

	(void)cdk2_hii_database_init(&database, &ops, NULL);
	(void)cdk2_hii_register_glyph(&database, L'A', 2U, 4U, 3U, pixels);
	failures += expect(cdk2_hii_string_to_image(&database, 0U, L"AA\nA", &output,
		0U, 0U, &rows, &row_count, &column, NULL) == EFI_SUCCESS &&
		row_count == 2U && rows[0].line_width == 4U && column == 4U,
		"glyph layout or row metadata is wrong");
	column = 0U;
	failures += expect(cdk2_hii_string_to_image(&database, 0U, L"B", &output,
		0U, 0U, NULL, NULL, &column, NULL) == EFI_NOT_FOUND && column == 0U,
		"missing glyph was not reported at the failing column");
	failures += expect(cdk2_hii_get_font_info(&database, &font_handle, NULL,
		&font_info, L"AA") == EFI_SUCCESS && font_info->size == 4U &&
		font_info->name[0] == L's',
		"font enumeration did not return one matching system font");
	release(NULL, font_info);
	font_info = NULL;
	failures += expect(cdk2_hii_get_font_info(&database, &font_handle, NULL,
		&font_info, NULL) == EFI_NOT_FOUND,
		"font enumeration did not terminate");
	font_handle = NULL;
	failures += expect(cdk2_hii_get_font_info(&database, &font_handle, NULL,
		&font_info, L"AB") == EFI_NOT_FOUND,
		"font lacking a requested glyph was returned");
	return failures == 0 ? 0 : 1;
}
