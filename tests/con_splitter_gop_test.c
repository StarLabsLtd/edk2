/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter.h>
#include <stdio.h>

static UINTN sets, blts;
static EFI_STATUS query(void *context, UINT32 mode,
	struct cdk2_split_gop_mode *information)
{
	UINTN device = (UINTN)context;
	static const UINT32 widths[2][2] = { { 800U, 1024U }, { 640U, 800U } };

	*information = (struct cdk2_split_gop_mode) {
		.width = widths[device - 1U][mode], .height = 600U,
		.pixel_format = 1U, .pixels_per_scan_line = widths[device - 1U][mode]
	};
	return EFI_SUCCESS;
}
static EFI_STATUS set(void *context, UINT32 mode)
{
	sets += (UINTN)context + mode;
	return EFI_SUCCESS;
}
static EFI_STATUS blt(void *context, void *buffer, UINTN operation,
	UINTN source_x, UINTN source_y, UINTN destination_x,
	UINTN destination_y, UINTN width, UINTN height, UINTN delta)
{
	(void)buffer; (void)operation; (void)source_x; (void)source_y;
	(void)destination_x; (void)destination_y; (void)width; (void)height;
	(void)delta; blts += (UINTN)context; return EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "con splitter GOP test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct cdk2_split_gop splitter = { 0 };
	struct cdk2_split_gop_device first = { query, set, blt, (void *)1, 2U };
	struct cdk2_split_gop_device second = { query, set, blt, (void *)2, 2U };
	struct cdk2_split_gop_mode mode;
	int failures = 0;

	failures += expect(cdk2_split_gop_add(&splitter, &first) == EFI_SUCCESS &&
		cdk2_split_gop_add(&splitter, &second) == EFI_SUCCESS &&
		splitter.mode_count == 1U &&
		cdk2_split_gop_query_mode(&splitter, 0U, &mode) == EFI_SUCCESS &&
		mode.width == 800U && mode.device_mode[0] == 0 &&
		mode.device_mode[1] == 1, "physical mode intersection is wrong");
	failures += expect(cdk2_split_gop_set_mode(&splitter, 0U) == EFI_SUCCESS &&
		sets == 4U && cdk2_split_gop_blt(&splitter, NULL, 0U, 0U, 0U, 0U,
			0U, 1U, 1U, 0U) == EFI_SUCCESS && blts == 3U,
		"SetMode or Blt was not fanned out");
	failures += expect(cdk2_split_gop_remove(&splitter, (void *)2) == EFI_SUCCESS &&
		splitter.mode_count == 2U, "mode map was not rebuilt on removal");
	return failures == 0 ? 0 : 1;
}
