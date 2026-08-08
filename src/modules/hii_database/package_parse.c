/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

#define HII_SIMPLE_FONTS 0x07U
#define HII_STRINGS 0x04U
#define HII_KEYBOARD_LAYOUT 0x09U
#define NARROW_HEIGHT 19U
struct simple_font_header { UINT32 length_type; UINT16 narrow_count, wide_count; };
struct narrow_glyph { CHAR16 unicode; UINT8 attributes; UINT8 bitmap[NARROW_HEIGHT]; };

static UINT32 package_length(const struct cdk2_hii_package_header *package)
{ return package->length_and_type & 0x00ffffffU; }
static UINT8 package_type(const struct cdk2_hii_package_header *package)
{ return (UINT8)(package->length_and_type >> 24); }

static UINT16 read16(const UINT8 *value)
{ return (UINT16)value[0] | ((UINT16)value[1] << 8); }
static UINT32 read32(const UINT8 *value)
{ return (UINT32)read16(value) | ((UINT32)read16(value + 2U) << 16); }

static EFI_STATUS add_raw_string(struct cdk2_hii_database *database, void *handle,
	const CHAR8 *language, UINT16 id, const UINT8 *source, UINTN bytes,
	BOOLEAN ascii)
{
	CHAR16 *text;
	EFI_STATUS status;
	UINTN index, count;

	if (ascii) {
		for (count = 0; count < bytes && source[count] != 0U; count++) { }
		if (count == bytes)
			return EFI_INVALID_PARAMETER;
	} else {
		for (count = 0; count + 1U < bytes && read16(source + count) != 0U;
		     count += 2U) { }
		if (count + 1U >= bytes)
			return EFI_INVALID_PARAMETER;
		count /= 2U;
	}
	status = database->ops->allocate(database->context,
		(count + 1U) * sizeof(*text), (void **)&text);
	if (EFI_ERROR(status))
		return status;
	for (index = 0; index < count; index++)
		text[index] = ascii ? source[index] : read16(source + index * 2U);
	text[count] = 0U;
	status = cdk2_hii_set_string(database, handle, id, language, text, NULL);
	database->ops->release(database->context, text);
	return status;
}

static EFI_STATUS duplicate_raw_string(struct cdk2_hii_database *database,
	void *handle, const CHAR8 *language, UINT16 target, UINT16 source)
{
	CHAR16 *text;
	EFI_STATUS status;
	UINTN size = 0U;

	status = cdk2_hii_get_string(database, language, handle, source, NULL, &size,
		NULL);
	if (status != EFI_BUFFER_TOO_SMALL)
		return EFI_INVALID_PARAMETER;
	status = database->ops->allocate(database->context, size, (void **)&text);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_hii_get_string(database, language, handle, source, text, &size,
		NULL);
	if (!EFI_ERROR(status))
		status = cdk2_hii_set_string(database, handle, target, language, text, NULL);
	database->ops->release(database->context, text);
	return status;
}

static EFI_STATUS ingest_strings(struct cdk2_hii_database *database, void *handle,
	const UINT8 *package, UINT32 length)
{
	const CHAR8 *language;
	UINT32 header_size, offset;
	UINT16 id = 1U, count, index;
	UINT8 type, font;
	BOOLEAN ascii;
	EFI_STATUS status;
	UINTN end, text_start;

	if (length < 47U)
		return EFI_INVALID_PARAMETER;
	header_size = read32(package + 4U);
	offset = read32(package + 8U);
	if (header_size < 47U || header_size > length || offset < header_size ||
	    offset >= length)
		return EFI_INVALID_PARAMETER;
	language = (const CHAR8 *)(package + 46U);
	for (end = 46U; end < header_size && package[end] != 0U; end++) { }
	if (end == header_size || end == 46U || end - 46U > CDK2_HII_MAX_LANGUAGE)
		return EFI_INVALID_PARAMETER;
	while (offset < length) {
		type = package[offset++];
		if (type == 0U)
			return offset == length ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
		font = 0U;
		count = 1U;
		ascii = type == 0x10U || type == 0x11U || type == 0x12U || type == 0x13U;
		if (type == 0x11U || type == 0x15U) {
			if (offset >= length)
				return EFI_INVALID_PARAMETER;
			font = package[offset++];
		} else if (type == 0x12U || type == 0x16U) {
			if (offset + 2U > length)
				return EFI_INVALID_PARAMETER;
			count = read16(package + offset); offset += 2U;
		} else if (type == 0x13U || type == 0x17U) {
			if (offset + 3U > length)
				return EFI_INVALID_PARAMETER;
			font = package[offset++]; count = read16(package + offset); offset += 2U;
		} else if (type == 0x20U) {
			if (offset + 2U > length || read16(package + offset) >= id)
				return EFI_INVALID_PARAMETER;
			status = duplicate_raw_string(database, handle, language, id++,
				read16(package + offset));
			offset += 2U;
			if (EFI_ERROR(status))
				return status;
			continue;
		} else if (type == 0x21U || type == 0x22U) {
			if (offset + (type == 0x21U ? 2U : 1U) > length)
				return EFI_INVALID_PARAMETER;
			count = type == 0x21U ? read16(package + offset) : package[offset];
			offset += type == 0x21U ? 2U : 1U;
			if ((UINT32)id + count > 0xffffU)
				return EFI_INVALID_PARAMETER;
			id = (UINT16)(id + count);
			continue;
		} else if (type >= 0x30U && type <= 0x32U) {
			UINT32 extension;
			UINTN width = type == 0x30U ? 1U : type == 0x31U ? 2U : 4U;
			if (offset + 1U + width > length)
				return EFI_INVALID_PARAMETER;
			extension = width == 1U ? package[offset + 1U] :
				width == 2U ? read16(package + offset + 1U) :
				read32(package + offset + 1U);
			if (extension < 2U + width || offset - 1U + extension > length)
				return EFI_INVALID_PARAMETER;
			offset = offset - 1U + extension;
			continue;
		} else if (type != 0x10U && type != 0x14U) {
			return EFI_INVALID_PARAMETER;
		}
		(void)font;
		for (index = 0; index < count; index++) {
			text_start = offset;
			if (ascii) {
				while (offset < length && package[offset++] != 0U) { }
			} else {
				while (offset + 1U < length && read16(package + offset) != 0U)
					offset += 2U;
				if (offset + 1U < length)
					offset += 2U;
			}
			if (offset > length || (ascii && package[offset - 1U] != 0U) ||
			    (!ascii && (offset < 2U || read16(package + offset - 2U) != 0U)))
				return EFI_INVALID_PARAMETER;
			status = add_raw_string(database, handle, language, id++,
				package + text_start, offset - text_start, ascii);
			if (EFI_ERROR(status))
				return status;
		}
	}
	return EFI_INVALID_PARAMETER;
}

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
		if (package_type(package) == HII_STRINGS) {
			status = ingest_strings(database, list, (const UINT8 *)package,
				package_length(package));
			if (EFI_ERROR(status))
				goto ingest_failed;
		} else if (package_type(package) == HII_SIMPLE_FONTS) {
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
ingest_failed:
	cdk2_hii_remove_strings(database, list);
	cdk2_hii_remove_images(database, list);
	cdk2_hii_remove_glyphs(database, list);
	cdk2_hii_remove_keyboard_layouts(database, list);
	return status;
invalid:
	cdk2_hii_remove_strings(database, list);
	cdk2_hii_remove_images(database, list);
	cdk2_hii_remove_glyphs(database, list);
	cdk2_hii_remove_keyboard_layouts(database, list);
	return EFI_INVALID_PARAMETER;
}
