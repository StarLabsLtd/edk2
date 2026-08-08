/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_HII_DATABASE_H_
#define CDK2_HII_DATABASE_H_

#include <uefi.h>

#define CDK2_HII_MAX_LISTS 64U
#define CDK2_HII_MAX_NOTIFIES 32U
#define CDK2_HII_MAX_STRINGS 512U
#define CDK2_HII_MAX_LANGUAGE 63U
#define CDK2_HII_MAX_IMAGES 256U
#define CDK2_HII_MAX_GLYPHS 512U
#define CDK2_HII_MAX_KEYBOARD_LAYOUTS 32U
#define CDK2_HII_MAX_CONFIG_ROUTES 64U
#define CDK2_HII_MAX_KEYWORDS 128U
#define CDK2_HII_PACKAGE_END 0xdfU

struct cdk2_hii_package_list_header {
	EFI_GUID guid;
	UINT32 length;
};
struct cdk2_hii_package_header {
	UINT32 length_and_type;
};
typedef EFI_STATUS cdk2_hii_allocate_fn(void *context, UINTN size, void **buffer);
typedef void cdk2_hii_release_fn(void *context, void *buffer);
typedef EFI_STATUS cdk2_hii_notify_fn(void *context, UINT8 package_type,
	const EFI_GUID *package_guid, const void *package_list, void *handle,
	UINTN notify_type);
struct cdk2_hii_database_ops {
	cdk2_hii_allocate_fn *allocate;
	cdk2_hii_release_fn *release;
};
struct cdk2_hii_list {
	void *data, *driver_handle;
	UINT32 size;
	BOOLEAN active;
};
struct cdk2_hii_notify {
	UINT8 package_type;
	EFI_GUID package_guid;
	cdk2_hii_notify_fn *callback;
	void *context;
	UINTN notify_mask;
	BOOLEAN use_guid, active;
};
struct cdk2_hii_database {
	const struct cdk2_hii_database_ops *ops;
	void *context;
	struct cdk2_hii_list lists[CDK2_HII_MAX_LISTS];
	struct cdk2_hii_notify notifies[CDK2_HII_MAX_NOTIFIES];
	struct cdk2_hii_string *strings;
	UINT16 next_string_id;
	struct cdk2_hii_image_entry *images;
	UINT16 next_image_id;
	struct cdk2_hii_glyph *glyphs;
	EFI_GUID keyboard_layouts[CDK2_HII_MAX_KEYBOARD_LAYOUTS];
	UINTN keyboard_layout_count, current_keyboard_layout;
	void (*keyboard_notify)(void *context, const EFI_GUID *layout);
	void *keyboard_notify_context;
	struct cdk2_hii_config_route *config_routes;
	struct cdk2_hii_keyword *keywords;
};
struct cdk2_hii_font_info {
	UINT32 style;
	UINT16 size;
	CHAR16 name[1];
};
struct cdk2_hii_string {
	void *package_handle;
	CHAR8 language[CDK2_HII_MAX_LANGUAGE + 1U];
	CHAR16 *text;
	struct cdk2_hii_font_info *font;
	UINT16 id;
	BOOLEAN active;
};
struct cdk2_hii_pixel { UINT8 blue, green, red, reserved; };
struct cdk2_hii_image_input {
	UINT16 width, height;
	struct cdk2_hii_pixel *bitmap;
};
struct cdk2_hii_image_output {
	UINT16 width, height;
	union { struct cdk2_hii_pixel *bitmap; void *screen; } image;
};
struct cdk2_hii_image_entry {
	void *package_handle;
	struct cdk2_hii_image_input image;
	UINT16 id;
	BOOLEAN active;
};
typedef EFI_STATUS cdk2_hii_screen_blt_fn(void *screen,
	struct cdk2_hii_pixel *bitmap, UINTN x, UINTN y, UINTN width, UINTN height);
struct cdk2_hii_glyph {
	CHAR16 character;
	UINT16 width, height, baseline;
	struct cdk2_hii_pixel *bitmap;
	BOOLEAN active;
};
struct cdk2_hii_row_info {
	UINTN start_index, end_index, line_width, line_height, baseline;
};
typedef EFI_STATUS cdk2_hii_extract_config_fn(void *context,
	const CHAR16 *request, const CHAR16 **progress, CHAR16 **results);
typedef EFI_STATUS cdk2_hii_route_config_fn(void *context,
	const CHAR16 *configuration, const CHAR16 **progress);
struct cdk2_hii_config_route {
	CHAR16 *header;
	cdk2_hii_extract_config_fn *extract;
	cdk2_hii_route_config_fn *route;
	void *context;
	BOOLEAN active;
};
struct cdk2_hii_keyword {
	CHAR16 *name_space, *keyword, *value;
	BOOLEAN read_only, active;
};

EFI_STATUS cdk2_hii_database_init(struct cdk2_hii_database *database,
	const struct cdk2_hii_database_ops *ops, void *context);
EFI_STATUS cdk2_hii_new_package_list(struct cdk2_hii_database *database,
	const void *package_list, void *driver_handle, void **handle);
EFI_STATUS cdk2_hii_remove_package_list(struct cdk2_hii_database *database,
	void *handle);
EFI_STATUS cdk2_hii_update_package_list(struct cdk2_hii_database *database,
	void *handle, const void *package_list);
EFI_STATUS cdk2_hii_export_package_lists(struct cdk2_hii_database *database,
	void *handle, UINTN *size, void *buffer);
EFI_STATUS cdk2_hii_list_package_lists(struct cdk2_hii_database *database,
	UINT8 package_type, const EFI_GUID *package_guid, UINTN *count,
	void **handles);
EFI_STATUS cdk2_hii_register_package_notify(struct cdk2_hii_database *database,
	UINT8 package_type, const EFI_GUID *package_guid, cdk2_hii_notify_fn *callback,
	void *context, UINTN notify_mask, void **notify_handle);
EFI_STATUS cdk2_hii_unregister_package_notify(struct cdk2_hii_database *database,
	void *notify_handle);
EFI_STATUS cdk2_hii_new_string(struct cdk2_hii_database *database,
	void *package_handle, UINT16 *string_id, const CHAR8 *language,
	const CHAR16 *string, const struct cdk2_hii_font_info *font);
EFI_STATUS cdk2_hii_set_string(struct cdk2_hii_database *database,
	void *package_handle, UINT16 string_id, const CHAR8 *language,
	const CHAR16 *string, const struct cdk2_hii_font_info *font);
EFI_STATUS cdk2_hii_get_string(struct cdk2_hii_database *database,
	const CHAR8 *language, void *package_handle, UINT16 string_id,
	CHAR16 *string, UINTN *string_size, struct cdk2_hii_font_info **font);
EFI_STATUS cdk2_hii_get_languages(struct cdk2_hii_database *database,
	void *package_handle, CHAR8 *languages, UINTN *size);
EFI_STATUS cdk2_hii_get_secondary_languages(struct cdk2_hii_database *database,
	void *package_handle, const CHAR8 *primary_language, CHAR8 *languages,
	UINTN *size);
void cdk2_hii_remove_strings(struct cdk2_hii_database *database,
	void *package_handle);
EFI_STATUS cdk2_hii_new_image(struct cdk2_hii_database *database,
	void *package_handle, UINT16 *image_id,
	const struct cdk2_hii_image_input *image);
EFI_STATUS cdk2_hii_get_image(struct cdk2_hii_database *database,
	void *package_handle, UINT16 image_id, struct cdk2_hii_image_input *image);
EFI_STATUS cdk2_hii_set_image(struct cdk2_hii_database *database,
	void *package_handle, UINT16 image_id,
	const struct cdk2_hii_image_input *image);
EFI_STATUS cdk2_hii_draw_image(struct cdk2_hii_database *database,
	const struct cdk2_hii_image_input *image, UINTN flags,
	struct cdk2_hii_image_output **output, UINTN x, UINTN y,
	cdk2_hii_screen_blt_fn *screen_blt);
EFI_STATUS cdk2_hii_draw_image_id(struct cdk2_hii_database *database,
	void *package_handle, UINT16 image_id, UINTN flags,
	struct cdk2_hii_image_output **output, UINTN x, UINTN y,
	cdk2_hii_screen_blt_fn *screen_blt);
void cdk2_hii_remove_images(struct cdk2_hii_database *database,
	void *package_handle);
EFI_STATUS cdk2_hii_register_glyph(struct cdk2_hii_database *database,
	CHAR16 character, UINT16 width, UINT16 height, UINT16 baseline,
	const struct cdk2_hii_pixel *bitmap);
EFI_STATUS cdk2_hii_get_glyph(struct cdk2_hii_database *database,
	CHAR16 character, struct cdk2_hii_image_output **image, UINTN *baseline);
EFI_STATUS cdk2_hii_string_to_image(struct cdk2_hii_database *database,
	UINTN flags, const CHAR16 *string, struct cdk2_hii_image_output **output,
	UINTN x, UINTN y, struct cdk2_hii_row_info **rows, UINTN *row_count,
	UINTN *column, cdk2_hii_screen_blt_fn *screen_blt);
EFI_STATUS cdk2_hii_add_keyboard_layout(struct cdk2_hii_database *database,
	const EFI_GUID *layout);
EFI_STATUS cdk2_hii_find_keyboard_layouts(struct cdk2_hii_database *database,
	UINT16 *count, EFI_GUID *layouts);
EFI_STATUS cdk2_hii_get_keyboard_layout(struct cdk2_hii_database *database,
	EFI_GUID *layout);
EFI_STATUS cdk2_hii_set_keyboard_layout(struct cdk2_hii_database *database,
	const EFI_GUID *layout);
void cdk2_hii_set_keyboard_notify(struct cdk2_hii_database *database,
	void (*notify)(void *context, const EFI_GUID *layout), void *context);
EFI_STATUS cdk2_hii_block_to_config(struct cdk2_hii_database *database,
	const CHAR16 *request, const UINT8 *block, UINTN block_size,
	CHAR16 **configuration, const CHAR16 **progress);
EFI_STATUS cdk2_hii_config_to_block(const CHAR16 *configuration, UINT8 *block,
	UINTN *block_size, const CHAR16 **progress);
EFI_STATUS cdk2_hii_register_config_route(struct cdk2_hii_database *database,
	const CHAR16 *header, cdk2_hii_extract_config_fn *extract,
	cdk2_hii_route_config_fn *route, void *context, void **route_handle);
EFI_STATUS cdk2_hii_unregister_config_route(struct cdk2_hii_database *database,
	void *route_handle);
EFI_STATUS cdk2_hii_extract_config(struct cdk2_hii_database *database,
	const CHAR16 *request, const CHAR16 **progress, CHAR16 **results);
EFI_STATUS cdk2_hii_route_config(struct cdk2_hii_database *database,
	const CHAR16 *configuration, const CHAR16 **progress);
EFI_STATUS cdk2_hii_export_config(struct cdk2_hii_database *database,
	CHAR16 **results);
EFI_STATUS cdk2_hii_get_alt_config(struct cdk2_hii_database *database,
	const CHAR16 *configuration, const CHAR16 *header,
	const CHAR16 *altcfg, CHAR16 **result);
EFI_STATUS cdk2_hii_register_keyword(struct cdk2_hii_database *database,
	const CHAR16 *name_space, const CHAR16 *keyword, const CHAR16 *value,
	BOOLEAN read_only);
EFI_STATUS cdk2_hii_get_keyword_data(struct cdk2_hii_database *database,
	const CHAR16 *name_space, const CHAR16 *keyword, CHAR16 **value);
EFI_STATUS cdk2_hii_set_keyword_data(struct cdk2_hii_database *database,
	const CHAR16 *name_space, const CHAR16 *keyword, const CHAR16 *value);

#endif
