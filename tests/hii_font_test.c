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
	struct cdk2_hii_image_output clipped = { 2U, 4U, { NULL } };
	struct cdk2_hii_image_output *clipped_output = &clipped;
	struct cdk2_hii_pixel clipped_pixels[8] = { 0 };
	struct cdk2_hii_pixel foreground = { .red = 0xaaU };
	struct cdk2_hii_pixel background = { .blue = 0xbbU };
	struct cdk2_hii_row_info *rows = NULL;
	UINTN row_count = 0U, column = 0U;
	struct cdk2_hii_font_info *font_info = NULL;
	void *font_handle = NULL;
	int failures = 0;

	(void)cdk2_hii_database_init(&database, &ops, NULL);
	(void)cdk2_hii_register_glyph(&database, L'A', 2U, 4U, 3U, pixels);
	pixels[0].red = 0xffU;
	(void)cdk2_hii_register_glyph(&database, L'C', 2U, 4U, 3U, pixels);
	(void)cdk2_hii_register_package_glyph_metrics(&database, NULL, L'D',
		2U, 4U, -1, -3, 3, pixels);
	failures += expect(cdk2_hii_string_to_image(&database, 0U, L"AA\nA", &output,
		0U, 0U, &rows, &row_count, &column, NULL) == EFI_SUCCESS &&
		row_count == 2U && rows[0].line_width == 4U && column == 4U,
		"glyph layout or row metadata is wrong");
	release(NULL, rows);
	rows = NULL;
	release(NULL, output->image.bitmap);
	release(NULL, output);
	output = NULL;
	column = 0U;
	failures += expect(cdk2_hii_string_to_image(&database, 0U, L"DD", &output,
		0U, 0U, &rows, &row_count, &column, NULL) == EFI_SUCCESS &&
		rows[0].line_width == 6U,
		"glyph advance was not used for layout");
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
	clipped.image.bitmap = clipped_pixels;
	column = 0U;
	failures += expect(cdk2_hii_string_to_image_colored(&database, 0x01U, L"CC",
		&clipped_output, 0U, 0U, NULL, NULL, &column, NULL, &foreground,
		&background) == EFI_SUCCESS && clipped_pixels[0].red == 0xaaU &&
		clipped_pixels[1].blue == 0xbbU && column == 2U,
		"font color or horizontal clipping semantics failed");
	output = NULL;
	column = 0U;
	failures += expect(cdk2_hii_string_to_image(&database, 0U, L"A", &output,
		0xffffU, 0U, NULL, NULL, &column, NULL) == EFI_INVALID_PARAMETER &&
		output == NULL, "overflowing auto-sized font surface was admitted");
	{
		struct cdk2_hii_image_output *glyph_image = NULL;
		UINTN glyph_baseline;
		pixels[0].red = 0x11U;
		(void)cdk2_hii_register_package_glyph(&database, (void *)1, L'Z',
			2U, 4U, 3U, pixels);
		pixels[0].red = 0x22U;
		(void)cdk2_hii_register_package_glyph(&database, (void *)2, L'Z',
			2U, 4U, 3U, pixels);
		cdk2_hii_remove_glyphs(&database, (void *)2);
		failures += expect(cdk2_hii_get_glyph(&database, L'Z', &glyph_image,
			&glyph_baseline) == EFI_SUCCESS &&
			glyph_image->image.bitmap[0].red == 0x11U,
			"failed staged glyph replacement destroyed the admitted glyph");
		release(NULL, glyph_image->image.bitmap);
		release(NULL, glyph_image);
	}
	return failures == 0 ? 0 : 1;
}
