/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_GRAPHICS_INFO_HOB_H_
#define CDK2_ABI_GRAPHICS_INFO_HOB_H_

#include <uefi.h>

typedef struct {
	UINT32 red_mask;
	UINT32 green_mask;
	UINT32 blue_mask;
	UINT32 reserved_mask;
} EFI_PIXEL_BITMASK;

typedef enum {
	pixel_red_green_blue_reserved8_bit_per_color,
	pixel_blue_green_red_reserved8_bit_per_color,
	pixel_bit_mask,
	pixel_blt_only,
	pixel_format_max
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef struct {
	UINT32 version;
	UINT32 horizontal_resolution;
	UINT32 vertical_resolution;
	EFI_GRAPHICS_PIXEL_FORMAT pixel_format;
	EFI_PIXEL_BITMASK pixel_information;
	UINT32 pixels_per_scan_line;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct {
	EFI_PHYSICAL_ADDRESS frame_buffer_base;
	UINT32 frame_buffer_size;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION graphics_mode;
} EFI_PEI_GRAPHICS_INFO_HOB;

#endif
