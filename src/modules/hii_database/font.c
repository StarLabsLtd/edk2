/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

#define HII_IGNORE_IF_NO_GLYPH 0x20U
#define HII_IGNORE_LINE_BREAK 0x40U

static struct cdk2_hii_glyph *find_glyph(struct cdk2_hii_database *database,
	CHAR16 character)
{
	UINTN index;

	for (index = 0; index < CDK2_HII_MAX_GLYPHS; index++)
		if (database->glyphs[index].active &&
		    database->glyphs[index].character == character)
			return &database->glyphs[index];
	return NULL;
}

EFI_STATUS cdk2_hii_register_glyph(struct cdk2_hii_database *database,
	CHAR16 character, UINT16 width, UINT16 height, UINT16 baseline,
	const struct cdk2_hii_pixel *bitmap)
{
	return cdk2_hii_register_package_glyph(database, NULL, character, width,
		height, baseline, bitmap);
}

EFI_STATUS cdk2_hii_register_package_glyph(struct cdk2_hii_database *database,
	void *package_handle, CHAR16 character, UINT16 width, UINT16 height,
	UINT16 baseline, const struct cdk2_hii_pixel *bitmap)
{
	struct cdk2_hii_glyph *glyph = NULL;
	struct cdk2_hii_pixel *copy;
	EFI_STATUS status;
	UINTN index, bytes;

	if (database == NULL || character == 0U || width == 0U || height == 0U ||
	    baseline > height || bitmap == NULL)
		return EFI_INVALID_PARAMETER;
	bytes = (UINTN)width * height * sizeof(*bitmap);
	status = database->ops->allocate(database->context, bytes, (void **)&copy);
	if (EFI_ERROR(status))
		return status;
	__builtin_memcpy(copy, bitmap, bytes);
	glyph = find_glyph(database, character);
	if (glyph == NULL)
		for (index = 0; index < CDK2_HII_MAX_GLYPHS; index++)
			if (!database->glyphs[index].active) {
				glyph = &database->glyphs[index];
				break;
			}
	if (glyph == NULL) {
		database->ops->release(database->context, copy);
		return EFI_OUT_OF_RESOURCES;
	}
	if (glyph->active)
		database->ops->release(database->context, glyph->bitmap);
	*glyph = (struct cdk2_hii_glyph) {
		package_handle, character, width, height, baseline, copy, TRUE
	};
	return EFI_SUCCESS;
}

void cdk2_hii_remove_glyphs(struct cdk2_hii_database *database,
	void *package_handle)
{
	UINTN index;

	if (database == NULL)
		return;
	for (index = 0; index < CDK2_HII_MAX_GLYPHS; index++)
		if (database->glyphs[index].active &&
		    database->glyphs[index].package_handle == package_handle) {
			database->ops->release(database->context,
				database->glyphs[index].bitmap);
			database->glyphs[index] = (struct cdk2_hii_glyph) { 0 };
		}
}

EFI_STATUS cdk2_hii_get_glyph(struct cdk2_hii_database *database,
	CHAR16 character, struct cdk2_hii_image_output **image, UINTN *baseline)
{
	struct cdk2_hii_glyph *glyph;
	struct cdk2_hii_image_output *result;
	EFI_STATUS status;
	UINTN bytes;

	if (database == NULL || image == NULL || baseline == NULL)
		return EFI_INVALID_PARAMETER;
	glyph = find_glyph(database, character);
	if (glyph == NULL)
		return EFI_NOT_FOUND;
	status = database->ops->allocate(database->context, sizeof(*result),
		(void **)&result);
	if (EFI_ERROR(status))
		return status;
	bytes = (UINTN)glyph->width * glyph->height * sizeof(*glyph->bitmap);
	status = database->ops->allocate(database->context, bytes,
		(void **)&result->image.bitmap);
	if (EFI_ERROR(status)) {
		database->ops->release(database->context, result);
		return status;
	}
	__builtin_memcpy(result->image.bitmap, glyph->bitmap, bytes);
	result->width = glyph->width;
	result->height = glyph->height;
	*baseline = glyph->baseline;
	*image = result;
	return EFI_SUCCESS;
}

static BOOLEAN same_text(const CHAR16 *left, const CHAR16 *right)
{
	while (*left != 0U && *left == *right) {
		left++;
		right++;
	}
	return *left == *right;
}

EFI_STATUS cdk2_hii_get_font_info(struct cdk2_hii_database *database,
	void **font_handle, const struct cdk2_hii_font_info *requested,
	struct cdk2_hii_font_info **font_info, const CHAR16 *string)
{
	static const CHAR16 name[] = L"system";
	struct cdk2_hii_font_info *result;
	UINT16 height = 0U;
	UINTN index, size;

	if (database == NULL || font_handle == NULL || font_info == NULL)
		return EFI_INVALID_PARAMETER;
	*font_info = NULL;
	if (*font_handle != NULL)
		return EFI_NOT_FOUND;
	for (index = 0; index < CDK2_HII_MAX_GLYPHS; index++)
		if (database->glyphs[index].active) {
			height = database->glyphs[index].height;
			break;
		}
	if (height == 0U)
		return EFI_NOT_FOUND;
	if (requested != NULL && (requested->style != 0U ||
	    (requested->size != 0U && requested->size != height) ||
	    (requested->name[0] != 0U && !same_text(requested->name, name))))
		return EFI_NOT_FOUND;
	if (string != NULL)
		for (index = 0; string[index] != 0U; index++)
			if (find_glyph(database, string[index]) == NULL)
				return EFI_NOT_FOUND;
	size = sizeof(*result) + (sizeof(name) - sizeof(CHAR16));
	if (database->ops->allocate(database->context, size,
			(void **)&result) != EFI_SUCCESS)
		return EFI_OUT_OF_RESOURCES;
	result->style = 0U;
	result->size = height;
	__builtin_memcpy(result->name, name, sizeof(name));
	*font_info = result;
	*font_handle = database;
	return EFI_SUCCESS;
}

static EFI_STATUS draw_glyph(struct cdk2_hii_database *database,
	struct cdk2_hii_glyph *glyph, struct cdk2_hii_image_output **output,
	UINTN x, UINTN y, cdk2_hii_screen_blt_fn *screen_blt, UINTN flags,
	const struct cdk2_hii_pixel *foreground,
	const struct cdk2_hii_pixel *background)
{
	struct cdk2_hii_image_input image = {
		.width = glyph->width, .height = glyph->height, .bitmap = glyph->bitmap
	};
	struct cdk2_hii_pixel *colored = NULL;
	EFI_STATUS status;
	UINTN index, count = (UINTN)glyph->width * glyph->height;

	if (foreground != NULL && background != NULL) {
		status = database->ops->allocate(database->context,
			count * sizeof(*colored), (void **)&colored);
		if (EFI_ERROR(status))
			return status;
		for (index = 0; index < count; index++)
			colored[index] = (glyph->bitmap[index].red |
				glyph->bitmap[index].green | glyph->bitmap[index].blue) != 0U ?
				*foreground : *background;
		image.bitmap = colored;
	}

	status = cdk2_hii_draw_image(database, &image,
		(flags & 0x10U) != 0U ? 1U : 0U, output, x, y, screen_blt);
	if (colored != NULL)
		database->ops->release(database->context, colored);
	return status;
}

EFI_STATUS cdk2_hii_string_to_image(struct cdk2_hii_database *database,
	UINTN flags, const CHAR16 *string, struct cdk2_hii_image_output **output,
	UINTN x, UINTN y, struct cdk2_hii_row_info **rows, UINTN *row_count,
	UINTN *column, cdk2_hii_screen_blt_fn *screen_blt)
{
	return cdk2_hii_string_to_image_colored(database, flags, string, output, x, y,
		rows, row_count, column, screen_blt, NULL, NULL);
}

EFI_STATUS cdk2_hii_string_to_image_colored(struct cdk2_hii_database *database,
	UINTN flags, const CHAR16 *string, struct cdk2_hii_image_output **output,
	UINTN x, UINTN y, struct cdk2_hii_row_info **rows, UINTN *row_count,
	UINTN *column, cdk2_hii_screen_blt_fn *screen_blt,
	const struct cdk2_hii_pixel *foreground,
	const struct cdk2_hii_pixel *background)
{
	struct cdk2_hii_row_info row_buffer[128];
	struct cdk2_hii_glyph *glyph;
	EFI_STATUS status;
	UINTN index = 0U, start = 0U, line_x = x, line_y = y;
	UINTN count = 0U, height = 0U, baseline = 0U, max_width;
	UINTN measure, measured_width = 0U, measured_line = 0U;
	UINTN measured_height = 0U, measured_line_height = 0U, bytes;

	if (database == NULL || string == NULL || output == NULL || column == NULL)
		return EFI_INVALID_PARAMETER;
	if (*output == NULL) {
		for (measure = 0U; string[measure] != 0U; measure++) {
			if (string[measure] == L'\n' &&
			    (flags & HII_IGNORE_LINE_BREAK) == 0U) {
				if (measured_line > measured_width)
					measured_width = measured_line;
				measured_height += measured_line_height;
				measured_line = measured_line_height = 0U;
				continue;
			}
			glyph = find_glyph(database, string[measure]);
			if (glyph == NULL)
				continue;
			measured_line += glyph->width;
			if (glyph->height > measured_line_height)
				measured_line_height = glyph->height;
		}
		if (measured_line > measured_width)
			measured_width = measured_line;
		measured_height += measured_line_height;
		status = database->ops->allocate(database->context, sizeof(**output),
			(void **)output);
		if (EFI_ERROR(status))
			return status;
		(*output)->width = (UINT16)(x + measured_width);
		(*output)->height = (UINT16)(y + measured_height);
		bytes = (UINTN)(*output)->width * (*output)->height *
			sizeof(struct cdk2_hii_pixel);
		status = database->ops->allocate(database->context, bytes,
			(void **)&(*output)->image.bitmap);
		if (EFI_ERROR(status)) {
			database->ops->release(database->context, *output);
			*output = NULL;
			return status;
		}
		__builtin_memset((*output)->image.bitmap, 0, bytes);
	}
	max_width = (*output)->width;
	while (string[index] != 0U) {
		if (string[index] == L'\n' && (flags & HII_IGNORE_LINE_BREAK) == 0U) {
			if (count == 128U)
				return EFI_OUT_OF_RESOURCES;
			row_buffer[count++] = (struct cdk2_hii_row_info) {
				start, index, line_x - x, height, baseline
			};
			line_y += height; line_x = x; start = ++index;
			height = baseline = 0U;
			continue;
		}
		glyph = find_glyph(database, string[index]);
		if (glyph == NULL) {
			if ((flags & HII_IGNORE_IF_NO_GLYPH) == 0U) {
				*column = index;
				return EFI_NOT_FOUND;
			}
			index++;
			continue;
		}
		if ((flags & 0x02U) != 0U && line_x != x &&
		    line_x + glyph->width > max_width) {
			if (count == 128U)
				return EFI_OUT_OF_RESOURCES;
			row_buffer[count++] = (struct cdk2_hii_row_info) {
				start, index, line_x - x, height, baseline
			};
			line_y += height; line_x = x; start = index;
			height = baseline = 0U;
		}
		if ((flags & 0x01U) != 0U && line_x + glyph->width > max_width) {
			index++;
			continue;
		}
		if ((flags & 0x01U) != 0U &&
		    line_y + glyph->height > (*output)->height) {
			index++;
			continue;
		}
		status = draw_glyph(database, glyph, output, line_x, line_y, screen_blt,
			flags, foreground, background);
		if (EFI_ERROR(status)) {
			*column = index;
			return status;
		}
		line_x += glyph->width;
		if (glyph->height > height)
			height = glyph->height;
		if (glyph->baseline > baseline)
			baseline = glyph->baseline;
		index++;
	}
	if (count == 128U)
		return EFI_OUT_OF_RESOURCES;
	row_buffer[count++] = (struct cdk2_hii_row_info) {
		start, index, line_x - x, height, baseline
	};
	if (rows != NULL && row_count != NULL) {
		status = database->ops->allocate(database->context,
			count * sizeof(**rows), (void **)rows);
		if (EFI_ERROR(status))
			return status;
		__builtin_memcpy(*rows, row_buffer, count * sizeof(**rows));
		*row_count = count;
	}
	*column = index;
	return EFI_SUCCESS;
}
