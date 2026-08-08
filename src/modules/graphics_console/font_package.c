/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_console_font.h>
#include <cdk2/graphics_console_package.h>

#define HII_SIMPLE_FONTS 0x07U
#define HII_END 0xdfU

struct package_list_header { EFI_GUID guid; UINT32 length; };
struct simple_font_header { UINT32 length_type; UINT16 narrow_count, wide_count; };

static const EFI_GUID font_package_guid = { 0xf5f219d3, 0x7006, 0x4648,
	{ 0xac, 0x8d, 0xd6, 0x1d, 0xfb, 0x7b, 0xc6, 0xad } };

EFI_STATUS cdk2_graphics_font_install(struct cdk2_graphics_font_package *package,
	struct cdk2_hii_database_view *database, cdk2_font_allocate_fn *allocate,
	cdk2_font_free_fn *free, void *context)
{
	struct package_list_header *list;
	struct simple_font_header *font;
	UINT8 *bytes;
	UINTN font_length = sizeof(*font) + mNarrowFontSize;
	UINTN total = sizeof(*list) + font_length + sizeof(UINT32);
	EFI_STATUS status;

	if (package == NULL || database == NULL || database->new_package_list == NULL ||
	    allocate == NULL || free == NULL || total > 0xffffffU)
		return EFI_INVALID_PARAMETER;
	status = allocate(context, total, &package->allocation);
	if (EFI_ERROR(status))
		return status;
	bytes = package->allocation;
	__builtin_memset(bytes, 0, total);
	list = (void *)bytes;
	list->guid = font_package_guid;
	list->length = (UINT32)total;
	font = (void *)(list + 1);
	font->length_type = (UINT32)font_length | (HII_SIMPLE_FONTS << 24);
	font->narrow_count = (UINT16)(mNarrowFontSize / sizeof(EFI_NARROW_GLYPH));
	__builtin_memcpy(font + 1, gUsStdNarrowGlyphData, mNarrowFontSize);
	*(UINT32 *)(bytes + total - sizeof(UINT32)) = sizeof(UINT32) | (HII_END << 24);
	status = database->new_package_list(database, list, NULL, &package->handle);
	if (EFI_ERROR(status)) {
		free(context, package->allocation);
		package->allocation = NULL;
		return status;
	}
	package->database = database;
	package->free = free;
	package->context = context;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_graphics_font_remove(struct cdk2_graphics_font_package *package)
{
	EFI_STATUS status;

	if (package == NULL || package->database == NULL || package->handle == NULL)
		return EFI_NOT_READY;
	status = package->database->remove_package_list(package->database, package->handle);
	if (EFI_ERROR(status))
		return status;
	package->free(package->context, package->allocation);
	package->allocation = NULL;
	package->handle = NULL;
	return EFI_SUCCESS;
}
