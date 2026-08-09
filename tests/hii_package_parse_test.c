/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }
static void write32(UINT8 *value, UINT32 data)
{
	value[0] = data; value[1] = data >> 8; value[2] = data >> 16;
	value[3] = data >> 24;
}
static void write16(UINT8 *value, UINT16 data)
{ value[0] = data; value[1] = data >> 8; }
static void write_cell(UINT8 *value, UINT16 width, UINT16 height,
	INT16 offset_x, INT16 offset_y, INT16 advance_x)
{
	write16(value, width); write16(value + 2U, height);
	write16(value + 4U, (UINT16)offset_x); write16(value + 6U, (UINT16)offset_y);
	write16(value + 8U, (UINT16)advance_x);
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII package parser test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_hii_database_ops ops = { .allocate = allocate, .release = release };
	struct cdk2_hii_database database;
	UINT8 list[81] = { 0 };
	UINT8 image_list[55] = { 0 };
	UINT8 palette_list[54] = { 0 };
	UINT8 font_list[92] = { 0 };
	UINT8 ifr_list[138] = { 0 };
	struct cdk2_hii_image_input image;
	CHAR16 text[3];
	UINTN size = sizeof(text);
	void *handle = NULL;
	int failures = 0;

	write32(list + 20U, (0x04U << 24) | 57U);
	write32(list + 24U, 49U);
	write32(list + 28U, 49U);
	list[64] = 1U;
	list[66] = 'e'; list[67] = 'n';
	list[69] = 0x14U;
	list[70] = 'H'; list[72] = 'i';
	write32(list + 77U, (CDK2_HII_PACKAGE_END << 24) | 4U);
	write32(list + 16U, sizeof(list));
	(void)cdk2_hii_database_init(&database, &ops, NULL);
	failures += expect(cdk2_hii_new_package_list(&database, list, NULL, &handle) ==
		EFI_SUCCESS && cdk2_hii_get_string(&database, "en", handle, 1U,
		text, &size, NULL) == EFI_SUCCESS && text[0] == L'H' && text[1] == L'i',
		"raw UCS-2 string package was not decoded");
	list[70] = 'J';
	failures += expect(cdk2_hii_update_package_list(&database, handle, list) ==
		EFI_SUCCESS && cdk2_hii_get_string(&database, "en", handle, 1U,
		text, &size, NULL) == EFI_SUCCESS && text[0] == L'J',
		"successful package update did not replace decoded objects");
	list[75] = 1U;
	failures += expect(cdk2_hii_update_package_list(&database, handle, list) ==
		EFI_INVALID_PARAMETER && cdk2_hii_get_string(&database, "en", handle,
		1U, text, &size, NULL) == EFI_SUCCESS && text[0] == L'J',
		"failed package update did not preserve the prior package");
	(void)cdk2_hii_remove_package_list(&database, handle);
	failures += expect(cdk2_hii_new_package_list(&database, list, NULL, &handle) ==
		EFI_INVALID_PARAMETER && handle == NULL,
		"unterminated raw string was admitted");
	write32(image_list + 16U, sizeof(image_list));
	write32(image_list + 20U, (0x06U << 24) | 31U);
	write32(image_list + 24U, 12U);
	image_list[32] = 0x16U;
	image_list[33] = 1U; image_list[35] = 1U;
	image_list[37] = 3U; image_list[38] = 2U; image_list[39] = 1U;
	image_list[40] = 0x19U;
	write32(image_list + 41U, 2U);
	image_list[45] = 0x89U; image_list[46] = 0x50U;
	image_list[47] = 0x20U; image_list[48] = 2U;
	write32(image_list + 51U, (CDK2_HII_PACKAGE_END << 24) | 4U);
	failures += expect(cdk2_hii_new_package_list(&database, image_list, NULL,
		&handle) == EFI_SUCCESS && cdk2_hii_get_image(&database, handle, 1U,
		&image) == EFI_SUCCESS && image.width == 1U && image.bitmap[0].red == 1U &&
		database.images[1].encoded_size == 2U &&
		database.images[2].encoded_size == 2U,
		"raw 24-bit/compressed/duplicate images were not retained");
	release(NULL, image.bitmap);
	write32(palette_list + 16U, sizeof(palette_list));
	write32(palette_list + 20U, (0x06U << 24) | 30U);
	write32(palette_list + 24U, 12U);
	write32(palette_list + 28U, 20U);
	palette_list[32] = 0x11U; palette_list[33] = 1U;
	palette_list[34] = 2U; palette_list[36] = 1U;
	palette_list[38] = 0x40U;
	palette_list[40] = 1U; palette_list[42] = 6U;
	palette_list[49] = 0xffU;
	write32(palette_list + 50U, (CDK2_HII_PACKAGE_END << 24) | 4U);
	failures += expect(cdk2_hii_new_package_list(&database, palette_list, NULL,
		&handle) == EFI_SUCCESS && cdk2_hii_get_image(&database, handle, 1U,
		&image) == EFI_SUCCESS && image.width == 2U && image.flags == 1U &&
		image.bitmap[0].red == 0U && image.bitmap[1].red == 0xffU,
		"paletted transparent image was not decoded faithfully");
	release(NULL, image.bitmap);
	write32(font_list + 16U, sizeof(font_list));
	write32(font_list + 20U, (0x05U << 24) | 68U);
	write32(font_list + 24U, 28U);
	write32(font_list + 28U, 28U);
	write_cell(font_list + 32U, 2U, 2U, -1, 1, 3);
	/* FontStyle is zero and FontFamily is the required empty UCS-2 string. */
	font_list[48] = 0x23U;
	write_cell(font_list + 49U, 2U, 2U, -1, 1, 3);
	font_list[59] = 0x12U; font_list[60] = 0xa0U;
	font_list[61] = 0x13U; write16(font_list + 62U, 2U);
	font_list[64] = 0xc0U; font_list[65] = 0x60U;
	font_list[66] = 0x20U; write16(font_list + 67U, 1U);
	font_list[69] = 0x22U; font_list[70] = 2U;
	font_list[71] = 0x14U;
	write_cell(font_list + 72U, 1U, 1U, 2, -2, 4);
	font_list[82] = 1U; font_list[83] = 0x80U;
	font_list[84] = 0x30U; font_list[85] = 0xeeU; font_list[86] = 3U;
	font_list[87] = 0x00U;
	write32(font_list + 88U, (CDK2_HII_PACKAGE_END << 24) | 4U);
	failures += expect(cdk2_hii_new_package_list(&database, font_list, NULL,
		&handle) == EFI_SUCCESS && database.glyphs[0].character == 1U &&
		database.glyphs[0].width == 2U && database.glyphs[0].offset_x == -1 &&
		database.glyphs[0].advance_x == 3 &&
		database.glyphs[3].character == 4U &&
		database.glyphs[4].character == 7U && database.glyphs[4].width == 1U &&
		database.glyphs[4].offset_y == -2,
		"standard/default/duplicate/skip/variability GIBT blocks were not decoded");
	font_list[82] = 0U;
	failures += expect(cdk2_hii_update_package_list(&database, handle, font_list) ==
		EFI_INVALID_PARAMETER && database.glyphs[0].character == 1U,
		"short variability bitmap was admitted or corrupted the old package");
	font_list[82] = 1U; font_list[86] = 2U;
	failures += expect(cdk2_hii_update_package_list(&database, handle, font_list) ==
		EFI_INVALID_PARAMETER && database.glyphs[4].character == 7U,
		"undersized extended GIBT block was admitted");
	write32(ifr_list + 16U, sizeof(ifr_list));
	write32(ifr_list + 20U, (0x04U << 24) | 68U);
	write32(ifr_list + 24U, 56U); write32(ifr_list + 28U, 56U);
	ifr_list[64] = 1U;
	__builtin_memcpy(ifr_list + 66U, "x-UEFI-ns", 10U);
	ifr_list[76] = 0x14U;
	ifr_list[77] = 'M'; ifr_list[79] = 'o'; ifr_list[81] = 'd'; ifr_list[83] = 'e';
	ifr_list[87] = 0U;
	write32(ifr_list + 88U, (0x02U << 24) | 46U);
	ifr_list[92] = 0x24U; ifr_list[93] = 23U;
	write16(ifr_list + 110U, 1U); write16(ifr_list + 112U, 8U);
	ifr_list[115] = 0x07U; ifr_list[116] = 17U;
	write16(ifr_list + 117U, 1U); write16(ifr_list + 121U, 3U);
	write16(ifr_list + 123U, 1U); write16(ifr_list + 125U, 2U);
	ifr_list[127] = 1U; ifr_list[128] = 0U;
	ifr_list[132] = 0x29U; ifr_list[133] = 2U;
	write32(ifr_list + 134U, (CDK2_HII_PACKAGE_END << 24) | 4U);
	failures += expect(cdk2_hii_new_package_list(&database, ifr_list, NULL,
		&handle) == EFI_SUCCESS && database.keywords[0].active &&
		database.keywords[0].package_handle == handle &&
		database.keywords[0].prompt_id == 1U &&
		database.keywords[0].varstore_id == 1U &&
		database.keywords[0].varstore_info == 2U &&
		database.keywords[0].width == 1U && database.keywords[0].read_only &&
		database.keywords[0].keyword[0] == L'M',
		"x-UEFI prompt was not associated with its IFR question and varstore");
	write16(ifr_list + 123U, 2U);
	failures += expect(cdk2_hii_update_package_list(&database, handle, ifr_list) ==
		EFI_INVALID_PARAMETER && database.keywords[0].varstore_id == 1U,
		"question with a missing varstore was admitted or corrupted old metadata");
	return failures == 0 ? 0 : 1;
}
