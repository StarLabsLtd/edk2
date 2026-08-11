/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GRAPHICS_OUTPUT_H_
#define CDK2_GRAPHICS_OUTPUT_H_

#include <guid/graphics_info_hob.h>
#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

struct cdk2_blt_pixel {
	uint8_t blue, green, red, reserved;
};
enum cdk2_blt_operation {
	CDK2_BLT_VIDEO_FILL,
	CDK2_BLT_VIDEO_TO_BUFFER,
	CDK2_BLT_BUFFER_TO_VIDEO,
	CDK2_BLT_VIDEO_TO_VIDEO,
};

struct cdk2_graphics_output {
	uint8_t *framebuffer;
	size_t framebuffer_size;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION physical;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION logical;
	uint32_t current_mode, max_mode, scale;
	uint32_t viewport_x, viewport_y, viewport_width, viewport_height;
};

uint64_t cdk2_graphics_init(struct cdk2_graphics_output *graphics,
			    const EFI_PEI_GRAPHICS_INFO_HOB *hob,
			    uint32_t hidpi_scale, uint32_t aspect_width,
			    uint32_t aspect_height);
uint64_t cdk2_graphics_set_mode(struct cdk2_graphics_output *graphics,
				uint32_t mode, uint8_t clear);
uint64_t cdk2_graphics_blt(struct cdk2_graphics_output *graphics,
			   struct cdk2_blt_pixel *buffer,
			   enum cdk2_blt_operation operation, size_t source_x,
			   size_t source_y, size_t destination_x,
			   size_t destination_y, size_t width, size_t height,
			   size_t delta);

#endif
