/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_output.h>

#include <stdio.h>
#include <string.h>

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "graphics output test: %s\n", message);
	return condition ? 0 : 1;
}

int main(void)
{
	uint32_t framebuffer[12 * 8];
	EFI_PEI_GRAPHICS_INFO_HOB hob;
	struct cdk2_graphics_output graphics;
	struct cdk2_blt_pixel red = {0, 0, 0xff, 0}, readback[4];
	int failures = 0;

	memset(&hob, 0, sizeof(hob));
	memset(framebuffer, 0x55, sizeof(framebuffer));
	hob.frame_buffer_base = (size_t)framebuffer;
	hob.frame_buffer_size = sizeof(framebuffer);
	hob.graphics_mode.horizontal_resolution = 12;
	hob.graphics_mode.vertical_resolution = 8;
	hob.graphics_mode.pixels_per_scan_line = 12;
	hob.graphics_mode.pixel_format =
		pixel_blue_green_red_reserved8_bit_per_color;
	failures += expect(cdk2_graphics_init(&graphics, &hob, 2, 4, 3) ==
				   EFI_SUCCESS,
			   "valid framebuffer HOB accepted");
	failures += expect(
		graphics.viewport_width == 10 && graphics.viewport_x == 1 &&
			graphics.max_mode == 2 &&
			graphics.logical.horizontal_resolution == 5 &&
			graphics.logical.vertical_resolution == 4,
		"aspect cap and HiDPI mode derived");
	failures +=
		expect(cdk2_graphics_set_mode(&graphics, 1, 1) == EFI_SUCCESS &&
			       graphics.scale == 2,
		       "logical mode selected and cleared");
	failures +=
		expect(cdk2_graphics_blt(&graphics, &red, CDK2_BLT_VIDEO_FILL,
					 0, 0, 1, 1, 2, 2, 0) == EFI_SUCCESS &&
			       framebuffer[2 * 12 + 3] == 0x00ff0000,
		       "scaled video fill");
	memset(readback, 0, sizeof(readback));
	failures += expect(cdk2_graphics_blt(&graphics, readback,
					     CDK2_BLT_VIDEO_TO_BUFFER, 1, 1, 0,
					     0, 2, 2, 0) == EFI_SUCCESS &&
				   readback[0].red == 0xff,
			   "video-to-buffer reads logical pixel");
	readback[0] = (struct cdk2_blt_pixel){0xff, 0, 0, 0};
	failures += expect(cdk2_graphics_blt(&graphics, readback,
					     CDK2_BLT_BUFFER_TO_VIDEO, 0, 0, 0,
					     0, 1, 1, 0) == EFI_SUCCESS &&
				   framebuffer[0 * 12 + 1] == 0x000000ff,
			   "buffer-to-video scales pixel");
	failures += expect(cdk2_graphics_blt(&graphics, NULL,
					     CDK2_BLT_VIDEO_TO_VIDEO, 0, 0, 4,
					     3, 1, 1, 0) == EFI_SUCCESS,
			   "video-to-video copy");
	failures += expect(cdk2_graphics_blt(&graphics, &red,
					     CDK2_BLT_VIDEO_FILL, 0, 0, 5, 0, 1,
					     1, 0) == EFI_INVALID_PARAMETER,
			   "destination overflow rejected");
	hob.frame_buffer_size--;
	failures += expect(cdk2_graphics_init(&graphics, &hob, 2, 4, 3) ==
				   EFI_INVALID_PARAMETER,
			   "truncated framebuffer rejected");
	hob.frame_buffer_size = sizeof(framebuffer);
	hob.graphics_mode.pixels_per_scan_line = 12;
	hob.graphics_mode.pixel_format = pixel_bit_mask;
	hob.graphics_mode.pixel_information =
		(EFI_PIXEL_BITMASK) { 0xf800, 0x07e0, 0x001f, 0 };
	failures += expect(
		cdk2_graphics_init(&graphics, &hob, 1, 0, 0) == EFI_SUCCESS &&
			cdk2_graphics_blt(&graphics, &red, CDK2_BLT_VIDEO_FILL,
					  0, 0, 0, 0, 1, 1, 0) == EFI_SUCCESS &&
			(framebuffer[0] & 0xf800) == 0xf800,
		"contiguous bit-mask pixel encoded");
	hob.graphics_mode.pixel_information.green_mask = 0x0f80;
	failures += expect(cdk2_graphics_init(&graphics, &hob, 1, 0, 0) ==
				   EFI_INVALID_PARAMETER,
			   "overlapping bit masks rejected");
	hob.graphics_mode.pixel_format =
		pixel_blue_green_red_reserved8_bit_per_color;
	hob.graphics_mode.pixels_per_scan_line = UINT32_MAX;
	failures += expect(cdk2_graphics_init(&graphics, &hob, 2, 4, 3) ==
				   EFI_INVALID_PARAMETER,
			   "oversized stride rejected");
	return failures == 0 ? 0 : 1;
}
