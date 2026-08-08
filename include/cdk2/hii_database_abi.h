/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_HII_DATABASE_ABI_H_
#define CDK2_HII_DATABASE_ABI_H_

#include <uefi.h>

struct cdk2_efi_hii_database_protocol;
struct cdk2_efi_hii_string_protocol;
struct cdk2_efi_hii_image_protocol;
struct cdk2_efi_hii_font_protocol;
struct cdk2_efi_hii_config_routing_protocol;
struct cdk2_efi_config_keyword_protocol;

struct cdk2_efi_pixel { UINT8 blue, green, red, reserved; };
struct cdk2_efi_image_input {
	UINT32 flags;
	UINT16 width, height;
	struct cdk2_efi_pixel *bitmap;
};
struct cdk2_efi_image_output {
	UINT16 width, height;
	union { struct cdk2_efi_pixel *bitmap; void *screen; } image;
};
struct cdk2_efi_font_info { UINT32 style; UINT16 size; CHAR16 name[1]; };
struct cdk2_efi_font_display_info {
	struct cdk2_efi_pixel foreground, background;
	UINT32 mask;
	struct cdk2_efi_font_info font;
};
struct cdk2_efi_hii_row_info {
	UINTN start_index, end_index, line_height, line_width, baseline;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_efi_hii_notify_fn(UINT8, const EFI_GUID *,
	const void *, void *, UINTN);

struct cdk2_efi_hii_database_protocol {
	EFI_STATUS (CDK2_MS_ABI *new_package_list)(const void *, const void *, void *, void **);
	EFI_STATUS (CDK2_MS_ABI *remove_package_list)(const void *, void *);
	EFI_STATUS (CDK2_MS_ABI *update_package_list)(const void *, void *, const void *);
	EFI_STATUS (CDK2_MS_ABI *list_package_lists)(const void *, UINT8,
		const EFI_GUID *, UINTN *, void **);
	EFI_STATUS (CDK2_MS_ABI *export_package_lists)(const void *, void *, UINTN *, void *);
	EFI_STATUS (CDK2_MS_ABI *register_package_notify)(const void *, UINT8,
		const EFI_GUID *, cdk2_efi_hii_notify_fn *, UINTN, void **);
	EFI_STATUS (CDK2_MS_ABI *unregister_package_notify)(const void *, void *);
	EFI_STATUS (CDK2_MS_ABI *find_keyboard_layouts)(const void *, UINT16 *, EFI_GUID *);
	EFI_STATUS (CDK2_MS_ABI *get_keyboard_layout)(const void *, const EFI_GUID *,
		UINT16 *, void *);
	EFI_STATUS (CDK2_MS_ABI *set_keyboard_layout)(const void *, const EFI_GUID *);
	EFI_STATUS (CDK2_MS_ABI *get_package_list_handle)(const void *, void *, void **);
};

struct cdk2_efi_hii_string_protocol {
	EFI_STATUS (CDK2_MS_ABI *new_string)(const void *, void *, UINT16 *, const CHAR8 *,
		const CHAR16 *, const CHAR16 *, const struct cdk2_efi_font_info *);
	EFI_STATUS (CDK2_MS_ABI *get_string)(const void *, const CHAR8 *, void *, UINT16,
		CHAR16 *, UINTN *, struct cdk2_efi_font_info **);
	EFI_STATUS (CDK2_MS_ABI *set_string)(const void *, void *, UINT16, const CHAR8 *,
		CHAR16 *, const struct cdk2_efi_font_info *);
	EFI_STATUS (CDK2_MS_ABI *get_languages)(const void *, void *, CHAR8 *, UINTN *);
	EFI_STATUS (CDK2_MS_ABI *get_secondary_languages)(const void *, void *,
		const CHAR8 *, CHAR8 *, UINTN *);
};

struct cdk2_efi_hii_image_protocol {
	EFI_STATUS (CDK2_MS_ABI *new_image)(const void *, void *, UINT16 *,
		const struct cdk2_efi_image_input *);
	EFI_STATUS (CDK2_MS_ABI *get_image)(const void *, void *, UINT16,
		struct cdk2_efi_image_input *);
	EFI_STATUS (CDK2_MS_ABI *set_image)(const void *, void *, UINT16,
		const struct cdk2_efi_image_input *);
	EFI_STATUS (CDK2_MS_ABI *draw_image)(const void *, UINT32,
		const struct cdk2_efi_image_input *, struct cdk2_efi_image_output **,
		UINTN, UINTN);
	EFI_STATUS (CDK2_MS_ABI *draw_image_id)(const void *, UINT32, void *, UINT16,
		struct cdk2_efi_image_output **, UINTN, UINTN);
};

struct cdk2_efi_hii_font_protocol {
	EFI_STATUS (CDK2_MS_ABI *string_to_image)(const void *, UINT32, const CHAR16 *,
		const struct cdk2_efi_font_display_info *, struct cdk2_efi_image_output **,
		UINTN, UINTN, struct cdk2_efi_hii_row_info **, UINTN *, UINTN *);
	EFI_STATUS (CDK2_MS_ABI *string_id_to_image)(const void *, UINT32, void *, UINT16,
		const CHAR8 *, const struct cdk2_efi_font_display_info *,
		struct cdk2_efi_image_output **, UINTN, UINTN,
		struct cdk2_efi_hii_row_info **, UINTN *, UINTN *);
	EFI_STATUS (CDK2_MS_ABI *get_glyph)(const void *, CHAR16,
		const struct cdk2_efi_font_display_info *, struct cdk2_efi_image_output **,
		UINTN *);
	EFI_STATUS (CDK2_MS_ABI *get_font_info)(const void *, void **,
		const struct cdk2_efi_font_display_info *,
		struct cdk2_efi_font_display_info **, const CHAR16 *);
};

struct cdk2_efi_hii_config_routing_protocol {
	EFI_STATUS (CDK2_MS_ABI *extract_config)(const void *, const CHAR16 *,
		const CHAR16 **, CHAR16 **);
	EFI_STATUS (CDK2_MS_ABI *export_config)(const void *, CHAR16 **);
	EFI_STATUS (CDK2_MS_ABI *route_config)(const void *, const CHAR16 *,
		const CHAR16 **);
	EFI_STATUS (CDK2_MS_ABI *block_to_config)(const void *, const CHAR16 *,
		const UINT8 *, UINTN, CHAR16 **, const CHAR16 **);
	EFI_STATUS (CDK2_MS_ABI *config_to_block)(const void *, const CHAR16 *, UINT8 *,
		UINTN *, const CHAR16 **);
	EFI_STATUS (CDK2_MS_ABI *get_alt_config)(const void *, const CHAR16 *,
		const EFI_GUID *, const CHAR16 *, const void *, const UINT16 *, CHAR16 **);
};

struct cdk2_efi_config_keyword_protocol {
	EFI_STATUS (CDK2_MS_ABI *set_data)(const void *, const CHAR16 *, CHAR16 **, UINT32 *);
	EFI_STATUS (CDK2_MS_ABI *get_data)(const void *, const CHAR16 *, const CHAR16 *,
		CHAR16 **, UINT32 *, CHAR16 **);
};

#endif
