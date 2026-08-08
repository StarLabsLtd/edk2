/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

struct fixture_list { struct cdk2_hii_package_list_header list; struct cdk2_hii_package_header end; };
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer) { (void)context; free(buffer); }
static EFI_STATUS decode(void *context, UINT8 type, const void *encoded,
	UINTN encoded_size, struct cdk2_hii_image_input *image)
{
	(void)context;
	if (type != 0x19U || encoded_size != 2U || ((const UINT8 *)encoded)[0] != 7U)
		return EFI_UNSUPPORTED;
	image->width = image->height = 1U;
	image->bitmap = malloc(sizeof(*image->bitmap));
	if (image->bitmap == NULL)
		return EFI_OUT_OF_RESOURCES;
	image->bitmap[0] = (struct cdk2_hii_pixel) { 1U, 2U, 3U, 0U };
	return EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII image test: %s\n", message); return !condition; }
int main(void)
{
	static const struct cdk2_hii_database_ops ops = {
		.allocate = allocate, .release = release, .decode_image = decode
	};
	struct cdk2_hii_database database;
	struct fixture_list package = {
		.list = { .guid = { .data1 = 1U }, .length = sizeof(package) },
		.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
	};
	struct cdk2_hii_pixel pixels[4] = {
		{ .blue = 1U }, { .blue = 2U }, { .blue = 3U }, { .blue = 4U }
	};
	struct cdk2_hii_image_input image = { 2U, 2U, pixels }, copy;
	struct cdk2_hii_image_output *output = NULL;
	UINT8 png[2] = { 7U, 8U };
	void *handle; UINT16 id = 0U; int failures = 0;
	(void)cdk2_hii_database_init(&database, &ops, NULL);
	(void)cdk2_hii_new_package_list(&database, &package, NULL, &handle);
	failures += expect(cdk2_hii_new_image(&database, handle, &id, &image) == EFI_SUCCESS &&
		cdk2_hii_get_image(&database, handle, id, &copy) == EFI_SUCCESS &&
		copy.width == 2U && copy.bitmap[3].blue == 4U, "image ownership failed");
	release(NULL, copy.bitmap);
	failures += expect(cdk2_hii_set_encoded_image(&database, handle, 2U, 0x19U,
		png, sizeof(png)) == EFI_SUCCESS && cdk2_hii_get_image(&database,
		handle, 2U, &copy) == EFI_SUCCESS && copy.width == 1U &&
		copy.bitmap[0].red == 3U, "compressed image decoder path failed");
	release(NULL, copy.bitmap);
	failures += expect(cdk2_hii_draw_image_id(&database, handle, id, 0U, &output,
		1U, 1U, NULL) == EFI_SUCCESS && output->width == 3U &&
		output->image.bitmap[8].blue == 4U, "bitmap composition failed");
	return failures == 0 ? 0 : 1;
}
