/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

#define HII_SIMPLE_FONTS 0x07U
#define HII_KEYBOARD_LAYOUT 0x09U
#define NARROW_HEIGHT 19U
struct simple_font_header { UINT32 length_type; UINT16 narrow_count, wide_count; };
struct narrow_glyph { CHAR16 unicode; UINT8 attributes; UINT8 bitmap[NARROW_HEIGHT]; };

static UINT32 package_length(const struct cdk2_hii_package_header *package)
{ return package->length_and_type & 0x00ffffffU; }
static UINT8 package_type(const struct cdk2_hii_package_header *package)
{ return (UINT8)(package->length_and_type >> 24); }

EFI_STATUS cdk2_hii_ingest_package_list(struct cdk2_hii_database *database,
	void *package_handle)
{
	struct cdk2_hii_list *list = package_handle;
	const struct cdk2_hii_package_list_header *header = list->data;
	const struct cdk2_hii_package_header *package;
	const struct simple_font_header *font;
	const struct narrow_glyph *glyph;
	struct cdk2_hii_pixel pixels[8U * NARROW_HEIGHT];
	EFI_STATUS status;
	UINTN offset = sizeof(*header), index, row, column;

	while (offset < list->size) {
		package = (const void *)((const UINT8 *)list->data + offset);
		if (package_type(package) == HII_SIMPLE_FONTS) {
			font = (const void *)package;
			if (font->wide_count != 0U || sizeof(*font) +
			    (UINTN)font->narrow_count * sizeof(*glyph) > package_length(package))
				return EFI_INVALID_PARAMETER;
			glyph = (const void *)(font + 1);
			for (index = 0; index < font->narrow_count; index++) {
				for (row = 0; row < NARROW_HEIGHT; row++)
					for (column = 0; column < 8U; column++)
						pixels[row * 8U + column] =
							(glyph[index].bitmap[row] & (0x80U >> column)) != 0U ?
							(struct cdk2_hii_pixel) { 0xffU, 0xffU, 0xffU, 0U } :
							(struct cdk2_hii_pixel) { 0U, 0U, 0U, 0U };
				status = cdk2_hii_register_package_glyph(database, list,
					glyph[index].unicode, 8U, NARROW_HEIGHT,
					NARROW_HEIGHT - 1U, pixels);
				if (EFI_ERROR(status)) {
					cdk2_hii_remove_glyphs(database, list);
					return status;
				}
			}
		} else if (package_type(package) == HII_KEYBOARD_LAYOUT) {
			const UINT8 *bytes = (const UINT8 *)package;
			UINT16 count, layout_size;
			UINTN layout_offset = 6U;

			if (package_length(package) < layout_offset)
				goto invalid;
			count = (UINT16)bytes[4] | ((UINT16)bytes[5] << 8);
			for (index = 0; index < count; index++) {
				if (layout_offset + 2U > package_length(package))
					goto invalid;
				layout_size = (UINT16)bytes[layout_offset] |
					((UINT16)bytes[layout_offset + 1U] << 8);
				if (layout_size < 23U || layout_offset + layout_size >
				    package_length(package))
					goto invalid;
				status = cdk2_hii_add_keyboard_layout_record(database, list,
					bytes + layout_offset, layout_size);
				if (EFI_ERROR(status)) {
					cdk2_hii_remove_keyboard_layouts(database, list);
					return status;
				}
				layout_offset += layout_size;
			}
			if (layout_offset != package_length(package))
				goto invalid;
		}
		offset += package_length(package);
	}
	return EFI_SUCCESS;
invalid:
	cdk2_hii_remove_keyboard_layouts(database, list);
	return EFI_INVALID_PARAMETER;
}
