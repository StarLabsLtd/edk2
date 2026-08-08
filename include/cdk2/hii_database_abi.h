/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_HII_DATABASE_ABI_H_
#define CDK2_HII_DATABASE_ABI_H_

#include <uefi.h>

typedef CHAR16 * cdk2_hii_char16_ptr;

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
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_new_package_fn(const void *, const void *,
	void *, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_remove_package_fn(const void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_update_package_fn(const void *, void *,
	const void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_list_packages_fn(const void *, UINT8,
	const EFI_GUID *, UINTN *, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_export_packages_fn(const void *, void *,
	UINTN *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_register_notify_fn(const void *, UINT8,
	const EFI_GUID *, cdk2_efi_hii_notify_fn *, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_unregister_notify_fn(const void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_find_layouts_fn(const void *, UINT16 *,
	EFI_GUID *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_layout_fn(const void *,
	const EFI_GUID *, UINT16 *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_set_layout_fn(const void *, const EFI_GUID *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_driver_fn(const void *, void *, void **);

struct cdk2_efi_hii_database_protocol {
	cdk2_hii_new_package_fn *new_package_list;
	cdk2_hii_remove_package_fn *remove_package_list;
	cdk2_hii_update_package_fn *update_package_list;
	cdk2_hii_list_packages_fn *list_package_lists;
	cdk2_hii_export_packages_fn *export_package_lists;
	cdk2_hii_register_notify_fn *register_package_notify;
	cdk2_hii_unregister_notify_fn *unregister_package_notify;
	cdk2_hii_find_layouts_fn *find_keyboard_layouts;
	cdk2_hii_get_layout_fn *get_keyboard_layout;
	cdk2_hii_set_layout_fn *set_keyboard_layout;
	cdk2_hii_get_driver_fn *get_package_list_handle;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_new_string_fn(const void *, void *,
	UINT16 *, const CHAR8 *, const CHAR16 *, const CHAR16 *,
	const struct cdk2_efi_font_info *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_string_fn(const void *, const CHAR8 *,
	void *, UINT16, CHAR16 *, UINTN *, struct cdk2_efi_font_info **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_set_string_fn(const void *, void *, UINT16,
	const CHAR8 *, CHAR16 *, const struct cdk2_efi_font_info *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_languages_fn(const void *, void *,
	CHAR8 *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_secondary_fn(const void *, void *,
	const CHAR8 *, CHAR8 *, UINTN *);

struct cdk2_efi_hii_string_protocol {
	cdk2_hii_new_string_fn *new_string;
	cdk2_hii_get_string_fn *get_string;
	cdk2_hii_set_string_fn *set_string;
	cdk2_hii_get_languages_fn *get_languages;
	cdk2_hii_get_secondary_fn *get_secondary_languages;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_new_image_fn(const void *, void *, UINT16 *,
	const struct cdk2_efi_image_input *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_image_fn(const void *, void *, UINT16,
	struct cdk2_efi_image_input *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_set_image_fn(const void *, void *, UINT16,
	const struct cdk2_efi_image_input *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_draw_image_fn(const void *, UINT32,
	const struct cdk2_efi_image_input *, struct cdk2_efi_image_output **,
	UINTN, UINTN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_draw_image_id_fn(const void *, UINT32,
	void *, UINT16, struct cdk2_efi_image_output **, UINTN, UINTN);

struct cdk2_efi_hii_image_protocol {
	cdk2_hii_new_image_fn *new_image;
	cdk2_hii_get_image_fn *get_image;
	cdk2_hii_set_image_fn *set_image;
	cdk2_hii_draw_image_fn *draw_image;
	cdk2_hii_draw_image_id_fn *draw_image_id;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_string_to_image_fn(const void *, UINT32,
	const CHAR16 *, const struct cdk2_efi_font_display_info *,
	struct cdk2_efi_image_output **, UINTN, UINTN,
	struct cdk2_efi_hii_row_info **, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_string_id_to_image_fn(const void *, UINT32,
	void *, UINT16, const CHAR8 *, const struct cdk2_efi_font_display_info *,
	struct cdk2_efi_image_output **, UINTN, UINTN,
	struct cdk2_efi_hii_row_info **, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_glyph_fn(const void *, CHAR16,
	const struct cdk2_efi_font_display_info *, struct cdk2_efi_image_output **,
	UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_font_info_fn(const void *, void **,
	const struct cdk2_efi_font_display_info *,
	struct cdk2_efi_font_display_info **, const CHAR16 *);

struct cdk2_efi_hii_font_protocol {
	cdk2_hii_string_to_image_fn *string_to_image;
	cdk2_hii_string_id_to_image_fn *string_id_to_image;
	cdk2_hii_get_glyph_fn *get_glyph;
	cdk2_hii_get_font_info_fn *get_font_info;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_extract_config_abi_fn(
	const void *, const CHAR16 *, cdk2_hii_char16_ptr *, cdk2_hii_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_export_config_abi_fn(
	const void *, cdk2_hii_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_route_config_abi_fn(
	const void *, const CHAR16 *, cdk2_hii_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_block_to_config_abi_fn(
	const void *, const CHAR16 *, const UINT8 *, UINTN, cdk2_hii_char16_ptr *,
	cdk2_hii_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_config_to_block_abi_fn(
	const void *, const CHAR16 *, UINT8 *, UINTN *, cdk2_hii_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_get_alt_config_abi_fn(
	const void *, const CHAR16 *, const EFI_GUID *, const CHAR16 *, const void *,
	const UINT16 *, cdk2_hii_char16_ptr *);

struct cdk2_efi_hii_config_routing_protocol {
	cdk2_hii_extract_config_abi_fn *extract_config;
	cdk2_hii_export_config_abi_fn *export_config;
	cdk2_hii_route_config_abi_fn *route_config;
	cdk2_hii_block_to_config_abi_fn *block_to_config;
	cdk2_hii_config_to_block_abi_fn *config_to_block;
	cdk2_hii_get_alt_config_abi_fn *get_alt_config;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_keyword_set_abi_fn(
	const void *, const CHAR16 *, cdk2_hii_char16_ptr *, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_keyword_get_abi_fn(
	const void *, const CHAR16 *, const CHAR16 *, cdk2_hii_char16_ptr *, UINT32 *,
	cdk2_hii_char16_ptr *);

struct cdk2_efi_config_keyword_protocol {
	cdk2_hii_keyword_set_abi_fn *set_data;
	cdk2_hii_keyword_get_abi_fn *get_data;
};

#endif
