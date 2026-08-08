/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

#define HII_SIMPLE_FONTS 0x07U
#define HII_FONTS 0x05U
#define HII_STRINGS 0x04U
#define HII_IMAGES 0x06U
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
static INT16 read_s16(const UINT8 *value) { return (INT16)read16(value); }

struct glyph_cell {
	UINT16 width, height;
	INT16 offset_x, offset_y, advance_x;
};

static void read_cell(struct glyph_cell *cell, const UINT8 *data)
{
	cell->width = read16(data);
	cell->height = read16(data + 2U);
	cell->offset_x = read_s16(data + 4U);
	cell->offset_y = read_s16(data + 6U);
	cell->advance_x = read_s16(data + 8U);
}

static EFI_STATUS add_gibt_glyph(struct cdk2_hii_database *database, void *handle,
	UINT16 character, const struct glyph_cell *cell, const UINT8 *bits, UINTN bit_count)
{
	struct cdk2_hii_pixel *pixels;
	EFI_STATUS status;
	UINTN index, count = (UINTN)cell->width * cell->height;

	if (character == 0U || cell->width == 0U || cell->height == 0U ||
	    cell->advance_x < 0 || count > bit_count)
		return EFI_INVALID_PARAMETER;
	status = database->ops->allocate(database->context,
		count * sizeof(*pixels), (void **)&pixels);
	if (EFI_ERROR(status))
		return status;
	for (index = 0U; index < count; index++)
		pixels[index] = (bits[index / 8U] & (0x80U >> (index % 8U))) != 0U ?
			(struct cdk2_hii_pixel) { 0xffU, 0xffU, 0xffU, 0U } :
			(struct cdk2_hii_pixel) { 0U, 0U, 0U, 0U };
	status = cdk2_hii_register_package_glyph_metrics(database, handle, character,
		cell->width, cell->height, cell->offset_x, cell->offset_y,
		cell->advance_x, pixels);
	database->ops->release(database->context, pixels);
	return status;
}

static EFI_STATUS duplicate_gibt_glyph(struct cdk2_hii_database *database,
	void *handle, UINT16 character, UINT16 source)
{
	struct cdk2_hii_glyph *glyph = NULL;
	UINTN index;

	for (index = 0U; index < CDK2_HII_MAX_GLYPHS; index++)
		if (database->glyphs[index].active &&
		    database->glyphs[index].package_handle == handle &&
		    database->glyphs[index].character == source) {
			glyph = &database->glyphs[index];
			break;
		}
	if (glyph == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_hii_register_package_glyph_metrics(database, handle, character,
		glyph->width, glyph->height, glyph->offset_x, glyph->offset_y,
		glyph->advance_x, glyph->bitmap);
}

static EFI_STATUS add_raw_string(struct cdk2_hii_database *database, void *handle,
	const CHAR8 *language, UINT16 id, const UINT8 *source, UINTN bytes,
	BOOLEAN ascii)
{
	CHAR16 *text;
	EFI_STATUS status;
	UINTN index, count;

	if (ascii) {
		for (count = 0; count < bytes && source[count] != 0U; count++)
			;
		if (count == bytes)
			return EFI_INVALID_PARAMETER;
	} else {
		for (count = 0; count + 1U < bytes && read16(source + count) != 0U;
		     count += 2U)
			;
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
	for (end = 46U; end < header_size && package[end] != 0U; end++)
		;
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
				while (offset < length && package[offset++] != 0U)
					;
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

static EFI_STATUS ingest_images(struct cdk2_hii_database *database, void *handle,
	const UINT8 *package, UINT32 length)
{
	struct cdk2_hii_image_input image;
	struct cdk2_hii_pixel *pixels;
	EFI_STATUS status;
	UINT32 offset, encoded_size, info_end;
	UINT32 palette_offset;
	UINT16 id = 1U, width, height, source_id;
	UINT8 type;
	UINTN index, pixel_count, bytes;

	if (length < 12U)
		return EFI_INVALID_PARAMETER;
	offset = read32(package + 4U);
	palette_offset = read32(package + 8U);
	if (offset < 12U || offset >= length)
		return EFI_INVALID_PARAMETER;
	if (palette_offset != 0U && (palette_offset <= offset || palette_offset >= length))
		return EFI_INVALID_PARAMETER;
	info_end = palette_offset == 0U ? length : palette_offset;
	while (offset < info_end) {
		type = package[offset++];
		if (type == 0U)
			return offset == info_end ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
		if (type >= 0x10U && type <= 0x15U) {
			const UINT8 *palette = NULL;
			UINT16 palette_size, palette_count, palette_number;
			UINTN row_bytes, x, y, palette_cursor;
			UINT8 bits = type < 0x12U ? 1U : type < 0x14U ? 4U : 8U;
			UINT8 palette_index, color;

			if (offset + 5U > length || palette_offset == 0U ||
			    palette_offset + 2U > length)
				return EFI_INVALID_PARAMETER;
			palette_index = package[offset++];
			width = read16(package + offset);
			height = read16(package + offset + 2U);
			offset += 4U;
			palette_count = read16(package + palette_offset);
			palette_cursor = palette_offset + 2U;
			for (palette_number = 1U; palette_number <= palette_count;
			     palette_number++) {
				if (palette_cursor + 2U > length)
					return EFI_INVALID_PARAMETER;
				palette_size = read16(package + palette_cursor);
				if (palette_cursor + 2U + palette_size > length ||
				    palette_size % 3U != 0U)
					return EFI_INVALID_PARAMETER;
				if (palette_number == palette_index) {
					palette = package + palette_cursor + 2U;
					break;
				}
				palette_cursor += 2U + palette_size;
			}
			if (palette == NULL || width == 0U || height == 0U)
				return EFI_INVALID_PARAMETER;
			row_bytes = ((UINTN)width * bits + 7U) / 8U;
			if (row_bytes > (length - offset) / height)
				return EFI_INVALID_PARAMETER;
			pixel_count = (UINTN)width * height;
			status = database->ops->allocate(database->context,
				pixel_count * sizeof(*pixels), (void **)&pixels);
			if (EFI_ERROR(status))
				return status;
			for (y = 0; y < height; y++)
				for (x = 0; x < width; x++) {
					if (bits == 1U)
						color = (package[offset + y * row_bytes + x / 8U] >>
							(7U - x % 8U)) & 1U;
					else if (bits == 4U)
						color = (package[offset + y * row_bytes + x / 2U] >>
							((x & 1U) == 0U ? 4U : 0U)) & 0x0fU;
					else
						color = package[offset + y * row_bytes + x];
					if ((UINTN)color * 3U + 3U > palette_size) {
						database->ops->release(database->context, pixels);
						return EFI_INVALID_PARAMETER;
					}
					pixels[y * width + x] = (struct cdk2_hii_pixel) {
						palette[color * 3U], palette[color * 3U + 1U],
						palette[color * 3U + 2U], 0U
					};
				}
			image = (struct cdk2_hii_image_input) {
				.width = width, .height = height, .bitmap = pixels,
				.flags = (type & 1U) != 0U ? 1U : 0U
			};
			status = cdk2_hii_set_image(database, handle, id++, &image);
			database->ops->release(database->context, pixels);
			if (EFI_ERROR(status))
				return status;
			offset += row_bytes * height;
		} else if (type == 0x16U || type == 0x17U) {
			if (offset + 4U > length)
				return EFI_INVALID_PARAMETER;
			width = read16(package + offset);
			height = read16(package + offset + 2U);
			offset += 4U;
			pixel_count = (UINTN)width * height;
			if (width == 0U || height == 0U || pixel_count >
			    (length - offset) / 3U)
				return EFI_INVALID_PARAMETER;
			bytes = pixel_count * sizeof(*pixels);
			status = database->ops->allocate(database->context, bytes,
				(void **)&pixels);
			if (EFI_ERROR(status))
				return status;
			for (index = 0; index < pixel_count; index++)
				pixels[index] = (struct cdk2_hii_pixel) {
					package[offset + index * 3U],
					package[offset + index * 3U + 1U],
					package[offset + index * 3U + 2U], 0U
				};
			image = (struct cdk2_hii_image_input) {
				.width = width, .height = height, .bitmap = pixels,
				.flags = type == 0x17U ? 1U : 0U
			};
			status = cdk2_hii_set_image(database, handle, id++, &image);
			database->ops->release(database->context, pixels);
			if (EFI_ERROR(status))
				return status;
			offset += pixel_count * 3U;
		} else if (type == 0x18U || type == 0x19U) {
			if (offset + 4U > length)
				return EFI_INVALID_PARAMETER;
			encoded_size = read32(package + offset); offset += 4U;
			if (encoded_size == 0U || encoded_size > length - offset)
				return EFI_INVALID_PARAMETER;
			status = cdk2_hii_set_encoded_image(database, handle, id++, type,
				package + offset, encoded_size);
			if (EFI_ERROR(status))
				return status;
			offset += encoded_size;
		} else if (type == 0x20U) {
			struct cdk2_hii_image_entry *source = NULL;

			if (offset + 2U > length)
				return EFI_INVALID_PARAMETER;
			source_id = read16(package + offset); offset += 2U;
			for (index = 0; index < CDK2_HII_MAX_IMAGES; index++)
				if (database->images[index].active &&
				    database->images[index].package_handle == handle &&
				    database->images[index].id == source_id) {
					source = &database->images[index];
					break;
				}
			if (source == NULL)
				return EFI_INVALID_PARAMETER;
			if (source->encoded != NULL)
				status = cdk2_hii_set_encoded_image(database, handle, id++,
					source->encoded_type, source->encoded, source->encoded_size);
			else
				status = cdk2_hii_set_image(database, handle, id++, &source->image);
			if (EFI_ERROR(status))
				return status;
		} else if (type == 0x21U || type == 0x22U) {
			if (offset + (type == 0x21U ? 2U : 1U) > length)
				return EFI_INVALID_PARAMETER;
			source_id = type == 0x21U ? read16(package + offset) : package[offset];
			offset += type == 0x21U ? 2U : 1U;
			if ((UINT32)id + source_id > 0xffffU)
				return EFI_INVALID_PARAMETER;
			id = (UINT16)(id + source_id);
		} else if (type >= 0x30U && type <= 0x32U) {
			UINT32 extension;
			UINTN size_width = type == 0x30U ? 1U : type == 0x31U ? 2U : 4U;
			if (offset + 1U + size_width > length)
				return EFI_INVALID_PARAMETER;
			extension = size_width == 1U ? package[offset + 1U] :
				size_width == 2U ? read16(package + offset + 1U) :
				read32(package + offset + 1U);
			if (extension < 2U + size_width || offset - 1U + extension > length)
				return EFI_INVALID_PARAMETER;
			offset = offset - 1U + extension;
		} else {
			return EFI_UNSUPPORTED;
		}
	}
	return EFI_INVALID_PARAMETER;
}

static EFI_STATUS ingest_fonts(struct cdk2_hii_database *database, void *handle,
	const UINT8 *package, UINT32 length)
{
	struct glyph_cell cell;
	EFI_STATUS status;
	UINT32 glyph_offset, header_size, extension, character = 1U;
	UINTN offset, bitmap_bytes, index, bitmap_bits;
	UINT16 count;
	UINT8 type;

	if (length < 28U)
		return EFI_INVALID_PARAMETER;
	header_size = read32(package + 4U);
	glyph_offset = read32(package + 8U);
	if (header_size < 28U || header_size > length ||
	    (package[header_size - 1U] != 0U || package[header_size - 2U] != 0U) ||
	    glyph_offset < header_size ||
	    glyph_offset >= length)
		return EFI_INVALID_PARAMETER;
	read_cell(&cell, package + 12U);
	offset = glyph_offset;
	while (offset < length) {
		type = package[offset++];
		if (type == 0x00U)
			return offset == length ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
		if (type == 0x23U) {
			if (offset + 10U > length)
				return EFI_INVALID_PARAMETER;
			read_cell(&cell, package + offset);
			offset += 10U;
			continue;
		}
		if (type == 0x21U || type == 0x22U) {
			if (offset + (type == 0x21U ? 2U : 1U) > length)
				return EFI_INVALID_PARAMETER;
			count = type == 0x21U ? read16(package + offset) : package[offset];
			offset += type == 0x21U ? 2U : 1U;
			if (count == 0U || character + count > 0x10000U)
				return EFI_INVALID_PARAMETER;
			character += count;
			continue;
		}
		if (type >= 0x30U && type <= 0x32U) {
			UINTN width = type == 0x30U ? 1U : type == 0x31U ? 2U : 4U;
			if (offset + width + 1U > length)
				return EFI_INVALID_PARAMETER;
			/* BlockType2 precedes Length in every extended block. */
			extension = width == 1U ? package[offset + 1U] :
				width == 2U ? read16(package + offset + 1U) :
				read32(package + offset + 1U);
			if (extension < width + 2U || offset - 1U + extension > length)
				return EFI_INVALID_PARAMETER;
			offset = offset - 1U + extension;
			continue;
		}
		if (type == 0x20U) {
			if (offset + 2U > length)
				return EFI_INVALID_PARAMETER;
			if (character > 0xffffU)
				return EFI_INVALID_PARAMETER;
			status = duplicate_gibt_glyph(database, handle, (UINT16)character,
				read16(package + offset));
			offset += 2U;
			if (EFI_ERROR(status))
				return status;
			character++;
			continue;
		}
		if (type == 0x10U || type == 0x11U || type == 0x14U) {
			if (offset + 10U > length)
				return EFI_INVALID_PARAMETER;
			read_cell(&cell, package + offset);
			offset += 10U;
		}
		if (type == 0x11U || type == 0x13U) {
			if (offset + 2U > length)
				return EFI_INVALID_PARAMETER;
			count = read16(package + offset);
			offset += 2U;
		} else {
			count = 1U;
		}
		bitmap_bits = (UINTN)cell.width * cell.height;
		if (cell.width != 0U && bitmap_bits / cell.width != cell.height)
			return EFI_INVALID_PARAMETER;
		if (type == 0x14U) {
			if (offset >= length)
				return EFI_INVALID_PARAMETER;
			bitmap_bits = package[offset++];
			bitmap_bytes = (bitmap_bits + 7U) / 8U;
		} else if (type == 0x10U || type == 0x11U || type == 0x12U ||
			   type == 0x13U) {
			bitmap_bytes = (bitmap_bits + 7U) / 8U;
		} else {
			return EFI_UNSUPPORTED;
		}
		if (count == 0U || bitmap_bytes == 0U ||
		    bitmap_bytes > (length - offset) / count ||
		    character + count > 0x10000U)
			return EFI_INVALID_PARAMETER;
		for (index = 0U; index < count; index++) {
			status = add_gibt_glyph(database, handle,
				(UINT16)(character + index), &cell,
				package + offset + index * bitmap_bytes, bitmap_bits);
			if (EFI_ERROR(status))
				return status;
		}
		offset += (UINTN)count * bitmap_bytes;
		character += count;
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
		} else if (package_type(package) == HII_IMAGES) {
			status = ingest_images(database, list, (const UINT8 *)package,
				package_length(package));
			if (EFI_ERROR(status))
				goto ingest_failed;
		} else if (package_type(package) == HII_FONTS) {
			status = ingest_fonts(database, list, (const UINT8 *)package,
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
