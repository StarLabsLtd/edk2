/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

typedef char admitted_string_capacity[(CDK2_HII_MAX_STRINGS >= 4096U) ? 1 : -1];

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }

int main(void)
{
	static const struct cdk2_hii_database_ops ops = { .allocate = allocate, .release = release };
	struct cdk2_hii_database database = { 0 };
	FILE *fixture = fopen(HII_PLATFORM_SIMPLE_FONT_FIXTURE, "rb");
	UINT8 *list = NULL;
	void *handle = NULL;
	struct cdk2_hii_image_output *glyph_output;
	UINTN baseline;
	long size;
	int result = 1;

	if (fixture == NULL || fseek(fixture, 0, SEEK_END) != 0 ||
	    (size = ftell(fixture)) <= 0 || fseek(fixture, 0, SEEK_SET) != 0)
		goto out;
	list = malloc((UINTN)size);
	if (list == NULL || fread(list, 1, (UINTN)size, fixture) != (UINTN)size)
		goto out;
	if (cdk2_hii_database_init(&database, &ops, NULL) != EFI_SUCCESS)
		goto out;
	if (cdk2_hii_new_package_list(&database, list, NULL, &handle) != EFI_SUCCESS ||
	    handle == NULL) {
		fprintf(stderr, "HII platform font test: valid default-glyph sentinel rejected\n");
		goto out;
	}
	if (cdk2_hii_get_glyph(&database, 0xffffU, &glyph_output, &baseline) != EFI_SUCCESS ||
	    glyph_output->width != 8U) {
		fprintf(stderr, "HII platform font test: default glyph fallback failed\n");
		goto out;
	}
	release(NULL, glyph_output->image.bitmap); release(NULL, glyph_output);
	{
		struct wide_fixture { struct cdk2_hii_package_list_header list;
			UINT32 font_header; UINT16 narrow_count, wide_count;
			CHAR16 unicode; UINT8 attributes, bitmap[38];
			struct cdk2_hii_package_header end; } __packed wide = { 0 };
		void *wide_handle = NULL;
		wide.list.length = sizeof(wide); wide.font_header = (0x07U << 24) | 49U;
		wide.wide_count = 1U; wide.unicode = 0x2603U; wide.bitmap[0] = 0x80U;
		wide.end.length_and_type = (CDK2_HII_PACKAGE_END << 24) | 4U;
		EFI_STATUS wide_status = cdk2_hii_new_package_list(&database, &wide, NULL, &wide_handle);
		if (wide_status != EFI_SUCCESS ||
		    cdk2_hii_get_glyph(&database, 0x2603U, &glyph_output, &baseline) != EFI_SUCCESS ||
		    glyph_output->width != 16U || glyph_output->height != 19U) {
			fprintf(stderr, "HII platform font test: wide glyph rejected status=%llu\n",
				(unsigned long long)wide_status);
			goto out;
		}
		release(NULL, glyph_output->image.bitmap); release(NULL, glyph_output);
	}
	result = 0;
out:
	if (list != NULL && database.ops != NULL)
		cdk2_hii_database_destroy(&database);
	free(list);
	if (fixture != NULL)
		(void)fclose(fixture);
	return result;
}
