/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_output.h>

#include <string.h>

#define GOP_DEVICE_ERROR ((1ULL << 63) | 7ULL)

static int multiply(size_t a, size_t b, size_t *result)
{
	if (a != 0 && b > SIZE_MAX / a)
		return 0;
	*result = a * b;
	return 1;
}

static unsigned int mask_shift(uint32_t mask)
{
	unsigned int shift = 0;
	while (mask != 0 && (mask & 1U) == 0) {
		mask >>= 1;
		shift++;
	}
	return shift;
}

static unsigned int mask_width(uint32_t mask)
{
	unsigned int width = 0;
	mask >>= mask_shift(mask);
	while ((mask & 1U) != 0) {
		width++;
		mask >>= 1;
	}
	return mask == 0 ? width : 0;
}

static uint32_t mask_encode(uint8_t value, uint32_t mask)
{
	unsigned int width = mask_width(mask);
	uint64_t maximum = width == 32 ? UINT32_MAX : ((1ULL << width) - 1);
	return width == 0 ? 0
			  : (uint32_t)(((uint64_t)value * maximum / 255)
				       << mask_shift(mask)) &
				    mask;
}

static uint8_t mask_decode(uint32_t value, uint32_t mask)
{
	unsigned int width = mask_width(mask);
	uint64_t maximum = width == 32 ? UINT32_MAX : ((1ULL << width) - 1);
	return width == 0 ? 0
			  : (uint8_t)((((value & mask) >> mask_shift(mask)) *
				       255ULL) /
				      maximum);
}

static uint32_t encode(const struct cdk2_graphics_output *graphics,
		       const struct cdk2_blt_pixel *pixel)
{
	if (graphics->physical.pixel_format ==
	    pixel_blue_green_red_reserved8_bit_per_color)
		return (uint32_t)pixel->blue | (uint32_t)pixel->green << 8 |
		       (uint32_t)pixel->red << 16 |
		       (uint32_t)pixel->reserved << 24;
	if (graphics->physical.pixel_format ==
	    pixel_red_green_blue_reserved8_bit_per_color)
		return (uint32_t)pixel->red | (uint32_t)pixel->green << 8 |
		       (uint32_t)pixel->blue << 16 |
		       (uint32_t)pixel->reserved << 24;
	return mask_encode(pixel->red,
			   graphics->physical.pixel_information.red_mask) |
	       mask_encode(pixel->green,
			   graphics->physical.pixel_information.green_mask) |
	       mask_encode(pixel->blue,
			   graphics->physical.pixel_information.blue_mask) |
	       mask_encode(pixel->reserved,
			   graphics->physical.pixel_information.reserved_mask);
}

static struct cdk2_blt_pixel decode(const struct cdk2_graphics_output *graphics,
				    uint32_t value)
{
	struct cdk2_blt_pixel pixel;
	if (graphics->physical.pixel_format ==
	    pixel_blue_green_red_reserved8_bit_per_color) {
		pixel.blue = value;
		pixel.green = value >> 8;
		pixel.red = value >> 16;
		pixel.reserved = value >> 24;
	} else if (graphics->physical.pixel_format ==
		   pixel_red_green_blue_reserved8_bit_per_color) {
		pixel.red = value;
		pixel.green = value >> 8;
		pixel.blue = value >> 16;
		pixel.reserved = value >> 24;
		return pixel;
	} else {
		pixel.red = mask_decode(
			value, graphics->physical.pixel_information.red_mask);
		pixel.green = mask_decode(
			value, graphics->physical.pixel_information.green_mask);
		pixel.blue = mask_decode(
			value, graphics->physical.pixel_information.blue_mask);
		pixel.reserved = mask_decode(
			value,
			graphics->physical.pixel_information.reserved_mask);
	}
	return pixel;
}

uint64_t cdk2_graphics_init(struct cdk2_graphics_output *graphics,
			    const EFI_PEI_GRAPHICS_INFO_HOB *hob,
			    uint32_t hidpi_scale, uint32_t aspect_width,
			    uint32_t aspect_height)
{
	size_t scan_bytes, required;
	uint64_t candidate;

	if (graphics == NULL || hob == NULL || hob->frame_buffer_base == 0 ||
	    hob->graphics_mode.horizontal_resolution == 0 ||
	    hob->graphics_mode.vertical_resolution == 0 ||
	    hob->graphics_mode.pixels_per_scan_line <
		    hob->graphics_mode.horizontal_resolution ||
	    hob->graphics_mode.pixel_format >= pixel_blt_only ||
	    !multiply(hob->graphics_mode.pixels_per_scan_line, 4,
		      &scan_bytes) ||
	    !multiply(scan_bytes, hob->graphics_mode.vertical_resolution,
		      &required) ||
	    required > hob->frame_buffer_size)
		return EFI_INVALID_PARAMETER;
	if (hob->graphics_mode.pixel_format == pixel_bit_mask) {
		uint32_t merged =
			hob->graphics_mode.pixel_information.red_mask |
			hob->graphics_mode.pixel_information.green_mask |
			hob->graphics_mode.pixel_information.blue_mask |
			hob->graphics_mode.pixel_information.reserved_mask;
		if (merged == 0 ||
		    mask_width(hob->graphics_mode.pixel_information.red_mask) ==
			    0 ||
		    mask_width(
			    hob->graphics_mode.pixel_information.green_mask) ==
			    0 ||
		    mask_width(
			    hob->graphics_mode.pixel_information.blue_mask) ==
			    0 ||
		    ((hob->graphics_mode.pixel_information.red_mask &
		      hob->graphics_mode.pixel_information.green_mask) != 0) ||
		    ((hob->graphics_mode.pixel_information.red_mask &
		      hob->graphics_mode.pixel_information.blue_mask) != 0) ||
		    ((hob->graphics_mode.pixel_information.green_mask &
		      hob->graphics_mode.pixel_information.blue_mask) != 0))
			return EFI_INVALID_PARAMETER;
	}
	memset(graphics, 0, sizeof(*graphics));
	graphics->framebuffer = (uint8_t *)(size_t)hob->frame_buffer_base;
	graphics->framebuffer_size = hob->frame_buffer_size;
	graphics->physical = graphics->logical = hob->graphics_mode;
	graphics->scale = 1;
	graphics->max_mode = 1;
	graphics->viewport_width = hob->graphics_mode.horizontal_resolution;
	graphics->viewport_height = hob->graphics_mode.vertical_resolution;
	if (aspect_width != 0 && aspect_height != 0 &&
	    (uint64_t)graphics->viewport_width * aspect_height >
		    (uint64_t)graphics->viewport_height * aspect_width) {
		candidate = (uint64_t)graphics->viewport_height * aspect_width /
			    aspect_height;
		candidate &= ~1ULL;
		if (candidate != 0 && candidate < graphics->viewport_width) {
			graphics->viewport_x =
				(graphics->viewport_width - candidate) / 2;
			graphics->viewport_width = (uint32_t)candidate;
		}
	}
	if (hidpi_scale > 1 && graphics->viewport_width / hidpi_scale != 0 &&
	    graphics->viewport_height / hidpi_scale != 0) {
		graphics->logical.horizontal_resolution =
			graphics->viewport_width / hidpi_scale;
		graphics->logical.vertical_resolution =
			graphics->viewport_height / hidpi_scale;
		graphics->logical.pixels_per_scan_line =
			graphics->logical.horizontal_resolution;
		graphics->max_mode = 2;
	}
	return EFI_SUCCESS;
}

uint64_t cdk2_graphics_set_mode(struct cdk2_graphics_output *graphics,
				uint32_t mode, uint8_t clear)
{
	struct cdk2_blt_pixel black = {0, 0, 0, 0};
	if (graphics == NULL || mode >= graphics->max_mode)
		return EFI_UNSUPPORTED;
	graphics->current_mode = mode;
	graphics->scale =
		mode == 0 ? 1
			  : graphics->viewport_width /
				    graphics->logical.horizontal_resolution;
	return clear ? cdk2_graphics_blt(
			       graphics, &black, CDK2_BLT_VIDEO_FILL, 0, 0, 0,
			       0,
			       mode == 0 ? graphics->physical
						   .horizontal_resolution
					 : graphics->logical
						   .horizontal_resolution,
			       mode == 0
				       ? graphics->physical.vertical_resolution
				       : graphics->logical.vertical_resolution,
			       0)
		     : EFI_SUCCESS;
}

static int rectangle(size_t x, size_t y, size_t width, size_t height,
		     size_t bound_x, size_t bound_y)
{
	return width != 0 && height != 0 && x <= bound_x && y <= bound_y &&
	       width <= bound_x - x && height <= bound_y - y;
}

uint64_t cdk2_graphics_blt(struct cdk2_graphics_output *graphics,
			   struct cdk2_blt_pixel *buffer,
			   enum cdk2_blt_operation operation, size_t source_x,
			   size_t source_y, size_t destination_x,
			   size_t destination_y, size_t width, size_t height,
			   size_t delta)
{
	uint32_t logical_width, logical_height, scale;
	size_t row, column, stride;

	if (graphics == NULL || operation > CDK2_BLT_VIDEO_TO_VIDEO)
		return EFI_INVALID_PARAMETER;
	logical_width = graphics->current_mode == 0
				? graphics->physical.horizontal_resolution
				: graphics->logical.horizontal_resolution;
	logical_height = graphics->current_mode == 0
				 ? graphics->physical.vertical_resolution
				 : graphics->logical.vertical_resolution;
	scale = graphics->scale;
	if ((operation != CDK2_BLT_VIDEO_TO_VIDEO && buffer == NULL) ||
	    (operation != CDK2_BLT_VIDEO_TO_BUFFER &&
	     !rectangle(destination_x, destination_y, width, height,
			logical_width, logical_height)) ||
	    (operation == CDK2_BLT_VIDEO_TO_VIDEO &&
	     !rectangle(source_x, source_y, width, height, logical_width,
			logical_height)) ||
	    (operation == CDK2_BLT_VIDEO_TO_BUFFER &&
	     !rectangle(source_x, source_y, width, height, logical_width,
			logical_height)))
		return EFI_INVALID_PARAMETER;
	stride = delta == 0 ? width * sizeof(*buffer) : delta;
	if (stride < width * sizeof(*buffer))
		return EFI_INVALID_PARAMETER;
	for (row = 0; row < height; row++) {
		size_t actual_row =
			operation == CDK2_BLT_VIDEO_TO_BUFFER ||
					operation == CDK2_BLT_VIDEO_TO_VIDEO
				? source_y + row
				: destination_y + row;
		if (operation == CDK2_BLT_VIDEO_TO_VIDEO &&
		    destination_y > source_y)
			actual_row = source_y + height - 1 - row;
		for (column = 0; column < width; column++) {
			struct cdk2_blt_pixel pixel;
			size_t sx = source_x + column,
			       dx = destination_x + column;
			size_t sy = actual_row, dy = destination_y + row;
			size_t px, py, yy, xx;
			if (operation == CDK2_BLT_VIDEO_FILL)
				pixel = *buffer;
			else if (operation == CDK2_BLT_BUFFER_TO_VIDEO)
				pixel = *(struct cdk2_blt_pixel
						  *)((uint8_t *)buffer +
						     (source_y + row) * stride +
						     sx * sizeof(pixel));
			else {
				px = graphics->viewport_x + sx * scale;
				py = graphics->viewport_y + sy * scale;
				pixel = decode(
					graphics,
					*(uint32_t
						  *)(graphics->framebuffer +
						     (py * graphics->physical
								      .pixels_per_scan_line +
						      px) * 4));
			}
			if (operation == CDK2_BLT_VIDEO_TO_BUFFER) {
				*(struct cdk2_blt_pixel
					  *)((uint8_t *)buffer +
					     (destination_y + row) * stride +
					     (destination_x + column) *
						     sizeof(pixel)) = pixel;
				continue;
			}
			if (operation == CDK2_BLT_VIDEO_TO_VIDEO &&
			    destination_y > source_y)
				dy = destination_y + height - 1 - row;
			px = graphics->viewport_x + dx * scale;
			py = graphics->viewport_y + dy * scale;
			for (yy = 0; yy < scale; yy++)
				for (xx = 0; xx < scale; xx++)
					*(uint32_t
						  *)(graphics->framebuffer +
						     ((py + yy) *
							      graphics->physical
								      .pixels_per_scan_line +
						      px + xx) *
							     4) =
						encode(graphics, &pixel);
		}
	}
	return EFI_SUCCESS;
}
