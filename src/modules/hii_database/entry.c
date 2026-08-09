/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>
#include <cdk2/hii_database_abi.h>

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI handle_protocol_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI locate_handle_buffer_fn(UINTN, const EFI_GUID *,
	void *, UINTN *, void ***);
typedef EFI_STATUS CDK2_MS_ABI locate_device_path_fn(const EFI_GUID *, void **,
	void **);
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32, UINTN,
	event_notify_fn *, void *,
	const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI event_fn(void *);
struct boot_services_view {
	UINT8 header[24];
	void *raise_tpl, *restore_tpl, *allocate_pages, *free_pages, *get_memory_map;
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	void *create_event, *set_timer, *wait_for_event;
	event_fn *signal_event;
	event_fn *close_event;
	void *check_event, *install_protocol, *reinstall_protocol, *uninstall_protocol;
	handle_protocol_fn *handle_protocol;
	void *reserved, *register_protocol_notify, *locate_handle;
	locate_device_path_fn *locate_device_path;
	void *install_configuration_table, *load_image, *start_image;
	void *exit, *unload_image, *exit_boot_services, *get_next_monotonic_count;
	void *stall, *set_watchdog_timer, *connect_controller, *disconnect_controller;
	void *open_protocol, *close_protocol, *open_protocol_information;
	void *protocols_per_handle;
	locate_handle_buffer_fn *locate_handle_buffer;
	void *locate_protocol;
	install_multiple_fn *install_multiple;
	void *uninstall_multiple, *calculate_crc32, *copy_mem, *set_mem;
	create_event_ex_fn *create_event_ex;
};
struct system_table_view { UINT8 before_boot_services[96]; struct boot_services_view *boot; };

struct hii_entry_context {
	struct boot_services_view *boot;
	struct cdk2_hii_database database;
	struct cdk2_efi_hii_database_protocol database_protocol;
	struct cdk2_efi_hii_string_protocol string_protocol;
	struct cdk2_efi_hii_image_protocol image_protocol;
	struct cdk2_efi_hii_font_protocol font_protocol;
	struct cdk2_efi_hii_config_routing_protocol config_protocol;
	struct cdk2_efi_config_keyword_protocol keyword_protocol;
	struct {
		cdk2_efi_hii_notify_fn *notify;
		void *source_handle;
		BOOLEAN active;
	} notify_bridges[CDK2_HII_MAX_NOTIFIES];
};
static struct hii_entry_context context;

static const EFI_GUID database_guid = { 0xef9fc172, 0xa1b2, 0x4693,
	{ 0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42 } };
static const EFI_GUID string_guid = { 0x0fd96974, 0x23aa, 0x4cdc,
	{ 0xb9, 0xcb, 0x98, 0xd1, 0x77, 0x50, 0x32, 0x2a } };
static const EFI_GUID image_guid = { 0x31a6406a, 0x6bdf, 0x4e46,
	{ 0xb2, 0xa2, 0xeb, 0xaa, 0x89, 0xc4, 0x09, 0x20 } };
static const EFI_GUID font_guid = { 0xe9ca4775, 0x8657, 0x47fc,
	{ 0x97, 0xe7, 0x7e, 0xd6, 0x5a, 0x08, 0x43, 0x24 } };
static const EFI_GUID config_guid = { 0x587e72d7, 0xcc50, 0x4f79,
	{ 0x82, 0x09, 0xca, 0x29, 0x1f, 0xc1, 0xa1, 0x0f } };
static const EFI_GUID keyword_guid = { 0x0a8badd5, 0x03b8, 0x4d19,
	{ 0xb1, 0x28, 0x7b, 0x8f, 0x0e, 0xda, 0xa5, 0x96 } };
static const EFI_GUID decoder_guid = { 0x9e66f251, 0x727c, 0x418c,
	{ 0xbf, 0xd6, 0xc2, 0xb4, 0x25, 0x28, 0x18, 0xea } };
static const EFI_GUID jpeg_guid = { 0xefefd093, 0x0d9b, 0x46eb,
	{ 0xa8, 0x56, 0x48, 0x35, 0x07, 0x00, 0xc9, 0x08 } };
static const EFI_GUID png_guid = { 0xaf060190, 0x5e3a, 0x4025,
	{ 0xaf, 0xbd, 0xe1, 0xf9, 0x05, 0xbf, 0xaa, 0x4c } };
static const EFI_GUID keyboard_event_guid = { 0x14982a4f, 0xb0ed, 0x45b8,
	{ 0xa8, 0x11, 0x5a, 0x7a, 0x9b, 0xc2, 0x32, 0xdf } };
static const EFI_GUID config_access_guid = { 0x330d4706, 0xf2a0, 0x4e4f,
	{ 0xa3, 0x69, 0xb6, 0x6f, 0xa8, 0xd5, 0x43, 0x85 } };
static const EFI_GUID device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };

typedef EFI_STATUS CDK2_MS_ABI decoder_names_fn(void *, EFI_GUID **, UINT16 *);
typedef EFI_STATUS CDK2_MS_ABI decoder_decode_fn(void *, void *, UINTN,
	struct cdk2_efi_image_output **, BOOLEAN);
struct decoder_protocol {
	decoder_names_fn *get_names;
	void *get_info;
	decoder_decode_fn *decode;
};
typedef EFI_STATUS CDK2_MS_ABI gop_blt_fn(void *, struct cdk2_efi_pixel *, UINTN,
	UINTN, UINTN, UINTN, UINTN, UINTN, UINTN, UINTN);
struct gop_protocol {
	void *query_mode, *set_mode;
	gop_blt_fn *blt;
	void *mode;
};
typedef EFI_STATUS CDK2_MS_ABI config_extract_fn(
	const void *, const CHAR16 *, cdk2_hii_char16_ptr *, cdk2_hii_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI config_route_fn(
	const void *, const CHAR16 *, cdk2_hii_char16_ptr *);
struct config_access_protocol {
	config_extract_fn *extract;
	config_route_fn *route;
	void *callback;
};

static EFI_STATUS allocate(void *opaque, UINTN size, void **buffer)
{ return ((struct hii_entry_context *)opaque)->boot->allocate_pool(4U, size, buffer); }
static void release(void *opaque, void *buffer)
{ (void)((struct hii_entry_context *)opaque)->boot->free_pool(buffer); }
static BOOLEAN same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left, *b = (const UINT8 *)right;
	UINTN index;
	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return FALSE;
	return TRUE;
}
static EFI_STATUS decode_image(void *opaque, UINT8 type, const void *encoded,
	UINTN encoded_size, struct cdk2_hii_image_input *image)
{
	struct hii_entry_context *entry = opaque;
	struct decoder_protocol *decoder;
	struct cdk2_efi_image_output *output = NULL;
	const EFI_GUID *wanted = type == 0x18U ? &jpeg_guid : &png_guid;
	EFI_GUID *names;
	void **handles;
	EFI_STATUS status = EFI_UNSUPPORTED;
	UINTN handle_count, handle_index;
	UINT16 name_count, name_index;

	if (entry->boot->locate_handle_buffer == NULL ||
	    entry->boot->handle_protocol == NULL)
		return EFI_UNSUPPORTED;
	status = entry->boot->locate_handle_buffer(2U, &decoder_guid, NULL,
		&handle_count, &handles);
	if (EFI_ERROR(status))
		return status;
	status = EFI_UNSUPPORTED;
	for (handle_index = 0; handle_index < handle_count; handle_index++) {
		if (EFI_ERROR(entry->boot->handle_protocol(handles[handle_index],
			&decoder_guid, (void **)&decoder)))
			continue;
		names = NULL; name_count = 0U;
		if (EFI_ERROR(decoder->get_names(decoder, &names, &name_count)))
			continue;
		for (name_index = 0; name_index < name_count; name_index++)
			if (same_guid(&names[name_index], wanted)) {
				status = decoder->decode(decoder, (void *)encoded, encoded_size,
					&output, FALSE);
				goto decoded;
			}
	}
decoded:
	(void)entry->boot->free_pool(handles);
	if (EFI_ERROR(status))
		return status;
	if (output == NULL || output->image.bitmap == NULL || output->width == 0U ||
	    output->height == 0U) {
		if (output != NULL)
			(void)entry->boot->free_pool(output);
		return EFI_DEVICE_ERROR;
	}
	image->width = output->width;
	image->height = output->height;
	image->bitmap = (struct cdk2_hii_pixel *)output->image.bitmap;
	image->flags = 0U;
	(void)entry->boot->free_pool(output);
	return EFI_SUCCESS;
}
static EFI_STATUS screen_blt(void *screen, struct cdk2_hii_pixel *bitmap,
	UINTN x, UINTN y, UINTN width, UINTN height)
{
	struct gop_protocol *gop = screen;
	struct cdk2_efi_pixel *source = (struct cdk2_efi_pixel *)bitmap;
	if (gop == NULL || gop->blt == NULL)
		return EFI_INVALID_PARAMETER;
	return gop->blt(gop, source, 2U, 0U, 0U,
		x, y, width, height, 0U);
}

static EFI_STATUS CDK2_MS_ABI new_package(const void *self, const void *list,
	void *driver, void **handle)
{ (void)self; return cdk2_hii_new_package_list(&context.database, list, driver, handle); }
static EFI_STATUS CDK2_MS_ABI remove_package(const void *self, void *handle)
{ (void)self; return cdk2_hii_remove_package_list(&context.database, handle); }
static EFI_STATUS CDK2_MS_ABI update_package(const void *self, void *handle,
	const void *list)
{ (void)self; return cdk2_hii_update_package_list(&context.database, handle, list); }
static EFI_STATUS CDK2_MS_ABI list_packages(const void *self, UINT8 type,
	const EFI_GUID *guid, UINTN *size, void **handles)
{
	UINTN count, capacity;
	EFI_STATUS status;

	(void)self;
	if (size == NULL)
		return EFI_INVALID_PARAMETER;
	capacity = *size / sizeof(*handles);
	count = capacity;
	status = cdk2_hii_list_package_lists(&context.database, type, guid, &count,
		handles);
	*size = count * sizeof(*handles);
	return status;
}
static EFI_STATUS CDK2_MS_ABI export_packages(const void *self, void *handle,
	UINTN *size, void *buffer)
{ (void)self; return cdk2_hii_export_package_lists(&context.database, handle, size, buffer); }

static EFI_STATUS notify_bridge(void *opaque, UINT8 type, const EFI_GUID *guid,
	const void *package, void *handle, UINTN operation)
{
	UINTN index = (UINTN)opaque;
	return context.notify_bridges[index].notify(type, guid, package, handle, operation);
}
static EFI_STATUS CDK2_MS_ABI register_notify(const void *self, UINT8 type,
	const EFI_GUID *guid, cdk2_efi_hii_notify_fn *notify, UINTN mask, void **handle)
{
	EFI_STATUS status;
	UINTN index;

	(void)self;
	if (notify == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < CDK2_HII_MAX_NOTIFIES; index++)
		if (!context.notify_bridges[index].active)
			break;
	if (index == CDK2_HII_MAX_NOTIFIES)
		return EFI_OUT_OF_RESOURCES;
	context.notify_bridges[index].notify = notify;
	status = cdk2_hii_register_package_notify(&context.database, type, guid,
		notify_bridge, (void *)index, mask,
		&context.notify_bridges[index].source_handle);
	if (EFI_ERROR(status)) {
		context.notify_bridges[index].notify = NULL;
		return status;
	}
	context.notify_bridges[index].active = TRUE;
	*handle = context.notify_bridges[index].source_handle;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI unregister_notify(const void *self, void *handle)
{
	EFI_STATUS status;
	UINTN index;
	(void)self;
	status = cdk2_hii_unregister_package_notify(&context.database, handle);
	if (EFI_ERROR(status))
		return status;
	for (index = 0; index < CDK2_HII_MAX_NOTIFIES; index++)
		if (context.notify_bridges[index].active &&
		    context.notify_bridges[index].source_handle == handle) {
			context.notify_bridges[index].active = FALSE;
			context.notify_bridges[index].notify = NULL;
			context.notify_bridges[index].source_handle = NULL;
			break;
		}
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI find_layouts(const void *self, UINT16 *size,
	EFI_GUID *layouts)
{
	UINT16 count, capacity;
	EFI_STATUS status;

	(void)self;
	if (size == NULL)
		return EFI_INVALID_PARAMETER;
	capacity = *size / sizeof(*layouts);
	count = capacity;
	status = cdk2_hii_find_keyboard_layouts(&context.database, &count, layouts);
	*size = count * sizeof(*layouts);
	return status;
}
static EFI_STATUS CDK2_MS_ABI get_layout(const void *self, const EFI_GUID *guid,
	UINT16 *size, void *layout)
{ (void)self; return cdk2_hii_copy_keyboard_layout(&context.database, guid, size, layout); }
static void CDK2_MS_ABI keyboard_event_notify(void *event, void *opaque)
{ (void)event; (void)opaque; }
static EFI_STATUS CDK2_MS_ABI set_layout(const void *self, const EFI_GUID *guid)
{
	void *event;
	EFI_STATUS status;
	(void)self;
	status = cdk2_hii_set_keyboard_layout(&context.database, guid);
	if (EFI_ERROR(status) || context.boot->create_event_ex == NULL ||
	    context.boot->signal_event == NULL || context.boot->close_event == NULL)
		return status;
	status = context.boot->create_event_ex(0x00000200U, 8U,
		keyboard_event_notify, NULL,
		&keyboard_event_guid, &event);
	if (EFI_ERROR(status))
		return status;
	status = context.boot->signal_event(event);
	(void)context.boot->close_event(event);
	return status;
}
static EFI_STATUS CDK2_MS_ABI get_driver(const void *self, void *handle, void **driver)
{ (void)self; return cdk2_hii_get_package_list_handle(&context.database, handle, driver); }

static EFI_STATUS CDK2_MS_ABI new_string(const void *self, void *handle, UINT16 *id,
	const CHAR8 *language, const CHAR16 *language_name, const CHAR16 *string,
	const struct cdk2_efi_font_info *font)
{
	(void)self; (void)language_name;
	return cdk2_hii_new_string(&context.database, handle, id, language, string,
		(const struct cdk2_hii_font_info *)font);
}
static EFI_STATUS CDK2_MS_ABI get_string(const void *self, const CHAR8 *language,
	void *handle, UINT16 id, CHAR16 *string, UINTN *size,
	struct cdk2_efi_font_info **font)
{
	(void)self;
	return cdk2_hii_get_string(&context.database, language, handle, id, string, size,
		(struct cdk2_hii_font_info **)font);
}
static EFI_STATUS CDK2_MS_ABI set_string(const void *self, void *handle, UINT16 id,
	const CHAR8 *language, CHAR16 *string, const struct cdk2_efi_font_info *font)
{
	(void)self;
	return cdk2_hii_set_string(&context.database, handle, id, language, string,
		(const struct cdk2_hii_font_info *)font);
}
static EFI_STATUS CDK2_MS_ABI get_languages(const void *self, void *handle,
	CHAR8 *languages, UINTN *size)
{ (void)self; return cdk2_hii_get_languages(&context.database, handle, languages, size); }
static EFI_STATUS CDK2_MS_ABI get_secondary(const void *self, void *handle,
	const CHAR8 *primary, CHAR8 *languages, UINTN *size)
{
	(void)self;
	return cdk2_hii_get_secondary_languages(&context.database, handle, primary,
		languages, size);
}

static struct cdk2_hii_image_input core_image(const struct cdk2_efi_image_input *image)
{
	return (struct cdk2_hii_image_input) {
		.width = image->width, .height = image->height,
		.bitmap = (struct cdk2_hii_pixel *)image->bitmap, .flags = image->flags
	};
}
static EFI_STATUS CDK2_MS_ABI new_image(const void *self, void *handle, UINT16 *id,
	const struct cdk2_efi_image_input *image)
{
	struct cdk2_hii_image_input input;
	(void)self;
	if (image == NULL)
		return EFI_INVALID_PARAMETER;
	input = core_image(image);
	return cdk2_hii_new_image(&context.database, handle, id, &input);
}
static EFI_STATUS CDK2_MS_ABI get_image(const void *self, void *handle, UINT16 id,
	struct cdk2_efi_image_input *image)
{
	struct cdk2_hii_image_input output;
	EFI_STATUS status;
	(void)self;
	if (image == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_hii_get_image(&context.database, handle, id, &output);
	if (!EFI_ERROR(status)) {
		image->flags = output.flags; image->width = output.width;
		image->height = output.height;
		image->bitmap = (struct cdk2_efi_pixel *)output.bitmap;
	}
	return status;
}
static EFI_STATUS CDK2_MS_ABI set_image(const void *self, void *handle, UINT16 id,
	const struct cdk2_efi_image_input *image)
{
	struct cdk2_hii_image_input input;
	(void)self;
	if (image == NULL)
		return EFI_INVALID_PARAMETER;
	input = core_image(image);
	return cdk2_hii_set_image(&context.database, handle, id, &input);
}
static EFI_STATUS CDK2_MS_ABI draw_image(const void *self, UINT32 flags,
	const struct cdk2_efi_image_input *image,
	struct cdk2_efi_image_output **output, UINTN x, UINTN y)
{
	struct cdk2_hii_image_input input;
	UINTN core_flags;
	(void)self;
	if (image == NULL)
		return EFI_INVALID_PARAMETER;
	input = core_image(image);
	core_flags = (flags & 0x01U) != 0U ? 2U : 0U;
	if ((flags & 0x30U) == 0x10U ||
	    ((flags & 0x30U) == 0U && (image->flags & 1U) != 0U))
		core_flags |= 1U;
	return cdk2_hii_draw_image(&context.database, &input, core_flags,
		(struct cdk2_hii_image_output **)output, x, y,
		(flags & 0x80U) != 0U ? screen_blt : NULL);
}
static EFI_STATUS CDK2_MS_ABI draw_image_id(const void *self, UINT32 flags,
	void *handle, UINT16 id, struct cdk2_efi_image_output **output, UINTN x, UINTN y)
{
	UINTN index, core_flags = (flags & 0x01U) != 0U ? 2U : 0U;
	(void)self;
	if ((flags & 0x30U) == 0x10U)
		core_flags |= 1U;
	else if ((flags & 0x30U) == 0U)
		for (index = 0; index < CDK2_HII_MAX_IMAGES; index++)
			if (context.database.images[index].active &&
			    context.database.images[index].package_handle == handle &&
			    context.database.images[index].id == id &&
			    (context.database.images[index].image.flags & 1U) != 0U) {
				core_flags |= 1U;
				break;
			}
	return cdk2_hii_draw_image_id(&context.database, handle, id, core_flags,
		(struct cdk2_hii_image_output **)output, x, y,
		(flags & 0x80U) != 0U ? screen_blt : NULL);
}

static EFI_STATUS CDK2_MS_ABI string_to_image(const void *self, UINT32 flags,
	const CHAR16 *string, const struct cdk2_efi_font_display_info *display,
	struct cdk2_efi_image_output **output, UINTN x, UINTN y,
	struct cdk2_efi_hii_row_info **rows, UINTN *row_count, UINTN *column)
{
	struct cdk2_hii_row_info *core_rows = NULL;
	EFI_STATUS status;
	UINTN index, count = 0U;

	(void)self;
	status = cdk2_hii_string_to_image_colored(&context.database, flags, string,
		(struct cdk2_hii_image_output **)output, x, y, &core_rows,
		rows == NULL ? NULL : &count, column,
		(flags & 0x80U) != 0U ? screen_blt : NULL,
		display == NULL ? NULL :
		(const struct cdk2_hii_pixel *)&display->foreground,
		display == NULL ? NULL :
		(const struct cdk2_hii_pixel *)&display->background);
	if (EFI_ERROR(status) || rows == NULL)
		return status;
	status = allocate(&context, count * sizeof(**rows), (void **)rows);
	if (EFI_ERROR(status)) {
		release(&context, core_rows);
		return status;
	}
	for (index = 0; index < count; index++)
		(*rows)[index] = (struct cdk2_efi_hii_row_info) {
			core_rows[index].start_index, core_rows[index].end_index,
			core_rows[index].line_height, core_rows[index].line_width,
			core_rows[index].baseline
		};
	release(&context, core_rows);
	if (row_count != NULL)
		*row_count = count;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI string_id_to_image(const void *self, UINT32 flags,
	void *handle, UINT16 id, const CHAR8 *language,
	const struct cdk2_efi_font_display_info *display,
	struct cdk2_efi_image_output **output, UINTN x, UINTN y,
	struct cdk2_efi_hii_row_info **rows, UINTN *row_count, UINTN *column)
{
	CHAR16 *string;
	EFI_STATUS status;
	UINTN size = 0U;

	status = cdk2_hii_get_string(&context.database, language, handle, id, NULL,
		&size, NULL);
	if (status != EFI_BUFFER_TOO_SMALL)
		return status;
	status = allocate(&context, size, (void **)&string);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_hii_get_string(&context.database, language, handle, id, string,
		&size, NULL);
	if (!EFI_ERROR(status))
		status = string_to_image(self, flags, string, display, output, x, y, rows,
			row_count, column);
	release(&context, string);
	return status;
}
static EFI_STATUS CDK2_MS_ABI get_glyph(const void *self, CHAR16 character,
	const struct cdk2_efi_font_display_info *display,
	struct cdk2_efi_image_output **output, UINTN *baseline)
{
	EFI_STATUS status;
	UINTN index, count;
	(void)self;
	status = cdk2_hii_get_glyph(&context.database, character,
		(struct cdk2_hii_image_output **)output, baseline);
	if (EFI_ERROR(status) || display == NULL)
		return status;
	count = (UINTN)(*output)->width * (*output)->height;
	for (index = 0; index < count; index++)
		(*output)->image.bitmap[index] =
			((*output)->image.bitmap[index].red |
			 (*output)->image.bitmap[index].green |
			 (*output)->image.bitmap[index].blue) != 0U ?
			display->foreground : display->background;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_font_info(const void *self, void **handle,
	const struct cdk2_efi_font_display_info *requested,
	struct cdk2_efi_font_display_info **output, const CHAR16 *string)
{
	struct cdk2_hii_font_info *core = NULL;
	struct { UINT32 style; UINT16 size; CHAR16 name[128]; } wanted_storage;
	struct cdk2_hii_font_info *wanted = (void *)&wanted_storage;
	struct cdk2_efi_font_display_info *result;
	EFI_STATUS status;
	UINTN length = 0U, size;

	(void)self;
	while (requested != NULL && requested->font.name[length] != 0U)
		length++;
	if (requested != NULL) {
		if (length >= ARRAY_SIZE(wanted_storage.name))
			return EFI_INVALID_PARAMETER;
		wanted->style = requested->font.style;
		wanted->size = requested->font.size;
		__builtin_memcpy(wanted->name, requested->font.name,
			(length + 1U) * sizeof(CHAR16));
		if ((requested->mask & (0x00000001U | 0x00010000U)) != 0U)
			wanted->name[0] = 0U;
		if ((requested->mask & (0x00000002U | 0x00020000U)) != 0U)
			wanted->size = 0U;
		if ((requested->mask & (0x00000004U | 0x00040000U)) != 0U)
			wanted->style = 0U;
	}
	status = cdk2_hii_get_font_info(&context.database, handle,
		requested == NULL ? NULL : wanted, &core, string);
	if (EFI_ERROR(status))
		return status;
	length = 0U;
	while (core->name[length] != 0U)
		length++;
	size = sizeof(*result) + length * sizeof(CHAR16);
	status = allocate(&context, size, (void **)&result);
	if (EFI_ERROR(status)) {
		release(&context, core);
		return status;
	}
	__builtin_memset(result, 0, size);
	result->mask = requested == NULL ? 0U : requested->mask;
	if (requested != NULL) {
		result->foreground = requested->foreground;
		result->background = requested->background;
	}
	result->font.style = core->style;
	result->font.size = core->size;
	__builtin_memcpy(result->font.name, core->name,
		(length + 1U) * sizeof(CHAR16));
	release(&context, core);
	*output = result;
	return EFI_SUCCESS;
}

static EFI_STATUS resolve_config_access(const CHAR16 *configuration,
	struct config_access_protocol **access, void **path_buffer);
static EFI_STATUS CDK2_MS_ABI extract_config(const void *self, const CHAR16 *request,
	CHAR16 **progress, CHAR16 **results)
{
	struct config_access_protocol *access;
	const CHAR16 *core_progress;
	void *path;
	EFI_STATUS status;
	(void)self;
	status = cdk2_hii_extract_config(&context.database, request, &core_progress,
		results);
	if (status != EFI_NOT_FOUND) {
		*progress = (CHAR16 *)core_progress;
		return status;
	}
	status = resolve_config_access(request, &access, &path);
	if (EFI_ERROR(status)) {
		*progress = (CHAR16 *)request;
		return status;
	}
	status = access->extract(access, request, progress, results);
	release(&context, path);
	return status;
}
static EFI_STATUS CDK2_MS_ABI export_config(const void *self, CHAR16 **results)
{ (void)self; return cdk2_hii_export_config(&context.database, results); }
static EFI_STATUS CDK2_MS_ABI route_config(const void *self, const CHAR16 *configuration,
	CHAR16 **progress)
{
	struct config_access_protocol *access;
	const CHAR16 *core_progress;
	void *path;
	EFI_STATUS status;
	(void)self;
	status = cdk2_hii_route_config(&context.database, configuration, &core_progress);
	if (status != EFI_NOT_FOUND) {
		*progress = (CHAR16 *)core_progress;
		return status;
	}
	status = resolve_config_access(configuration, &access, &path);
	if (EFI_ERROR(status)) {
		*progress = (CHAR16 *)configuration;
		return status;
	}
	status = access->route(access, configuration, progress);
	release(&context, path);
	return status;
}
static EFI_STATUS CDK2_MS_ABI block_to_config(const void *self, const CHAR16 *request,
	const UINT8 *block, UINTN size, CHAR16 **configuration, CHAR16 **progress)
{
	const CHAR16 *core_progress;
	EFI_STATUS status;
	(void)self;
	status = cdk2_hii_block_to_config(&context.database, request, block, size,
		configuration, &core_progress);
	*progress = (CHAR16 *)core_progress;
	return status;
}
static EFI_STATUS CDK2_MS_ABI config_to_block(const void *self,
	const CHAR16 *configuration, UINT8 *block, UINTN *size, CHAR16 **progress)
{
	const CHAR16 *core_progress;
	EFI_STATUS status;
	(void)self;
	status = cdk2_hii_config_to_block(configuration, block, size, &core_progress);
	*progress = (CHAR16 *)core_progress;
	return status;
}

static UINTN text_length(const CHAR16 *text)
{
	UINTN length = 0U;
	while (text[length] != 0U)
		length++;
	return length;
}
static CHAR16 keyword_fold(CHAR16 character)
{
	return character >= L'A' && character <= L'Z' ?
		(CHAR16)(character + (L'a' - L'A')) : character;
}
static BOOLEAN keyword_text_equal(const CHAR16 *left, const CHAR16 *right)
{
	UINTN index = 0U;
	while (left[index] != 0U &&
	       keyword_fold(left[index]) == keyword_fold(right[index]))
		index++;
	return keyword_fold(left[index]) == keyword_fold(right[index]);
}
static BOOLEAN keyword_prefix(const CHAR16 *text, const CHAR16 *prefix)
{
	UINTN index = 0U;
	while (prefix[index] != 0U &&
	       keyword_fold(text[index]) == keyword_fold(prefix[index]))
		index++;
	return prefix[index] == 0U;
}
static BOOLEAN token(const CHAR16 *text, const CHAR16 *name)
{
	UINTN index = 0U;
	while (name[index] != 0U && text[index] == name[index])
		index++;
	return name[index] == 0U;
}

static EFI_STATUS nibble(CHAR16 character, UINT8 *value)
{
	if (character >= L'0' && character <= L'9')
		*value = character - L'0';
	else if (character >= L'A' && character <= L'F')
		*value = character - L'A' + 10U;
	else if (character >= L'a' && character <= L'f')
		*value = character - L'a' + 10U;
	else
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}
static EFI_STATUS resolve_config_access(const CHAR16 *configuration,
	struct config_access_protocol **access, void **path_buffer)
{
	const CHAR16 *path = NULL, *cursor;
	UINT8 *bytes, high, low;
	void *remaining, *handle;
	EFI_STATUS status;
	UINTN digits = 0U, index;

	if (configuration == NULL || access == NULL || path_buffer == NULL ||
	    context.boot->locate_device_path == NULL ||
	    context.boot->handle_protocol == NULL)
		return EFI_INVALID_PARAMETER;
	for (cursor = configuration; *cursor != 0U; cursor++)
		if ((cursor == configuration || cursor[-1] == L'&') &&
		    token(cursor, L"PATH=")) {
			path = cursor + 5U;
			break;
		}
	if (path == NULL)
		return EFI_NOT_FOUND;
	while (path[digits] != 0U && path[digits] != L'&')
		digits++;
	if (digits == 0U || (digits & 1U) != 0U)
		return EFI_INVALID_PARAMETER;
	status = allocate(&context, digits / 2U, (void **)&bytes);
	if (EFI_ERROR(status))
		return status;
	for (index = 0; index < digits; index += 2U) {
		status = nibble(path[index], &high);
		if (!EFI_ERROR(status))
			status = nibble(path[index + 1U], &low);
		if (EFI_ERROR(status)) {
			release(&context, bytes);
			return status;
		}
		bytes[index / 2U] = (UINT8)((high << 4) | low);
	}
	remaining = bytes;
	status = context.boot->locate_device_path(&config_access_guid, &remaining,
		&handle);
	if (!EFI_ERROR(status))
		status = context.boot->handle_protocol(handle, &config_access_guid,
			(void **)access);
	if (EFI_ERROR(status)) {
		release(&context, bytes);
		return status;
	}
	*path_buffer = bytes;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_alt_config(const void *self,
	const CHAR16 *configuration, const EFI_GUID *guid, const CHAR16 *name,
	const void *device_path, const UINT16 *altcfg_id, CHAR16 **result)
{
	CHAR16 header[512], altcfg[5];
	UINTN index = 0U;
	static const CHAR16 hex[] = L"0123456789ABCDEF";

	(void)self; (void)guid; (void)name; (void)device_path;
	if (configuration == NULL || result == NULL)
		return EFI_INVALID_PARAMETER;
	while (configuration[index] != 0U && index + 1U < ARRAY_SIZE(header)) {
		if (configuration[index] == L'&' &&
		    (token(configuration + index, L"&ALTCFG=") ||
		     token(configuration + index, L"&OFFSET=") ||
		     token(configuration + index, L"&WIDTH=") ||
		     token(configuration + index, L"&VALUE=")))
			break;
		header[index] = configuration[index];
		index++;
	}
	if (index == 0U || index + 1U == ARRAY_SIZE(header))
		return EFI_INVALID_PARAMETER;
	header[index] = 0U;
	if (altcfg_id != NULL) {
		altcfg[0] = hex[(*altcfg_id >> 12) & 0x0fU];
		altcfg[1] = hex[(*altcfg_id >> 8) & 0x0fU];
		altcfg[2] = hex[(*altcfg_id >> 4) & 0x0fU];
		altcfg[3] = hex[*altcfg_id & 0x0fU];
		altcfg[4] = 0U;
	}
	return cdk2_hii_get_alt_config(&context.database, configuration, header,
		altcfg_id == NULL ? NULL : altcfg, result);
}
static EFI_STATUS field(const CHAR16 *cursor, const CHAR16 *name, CHAR16 *value,
	UINTN capacity, const CHAR16 **next)
{
	UINTN length = 0U, prefix = text_length(name);

	if (!token(cursor, name))
		return EFI_INVALID_PARAMETER;
	cursor += prefix;
	while (cursor[length] != 0U && cursor[length] != L'&')
		length++;
	if (length == 0U || length + 1U > capacity)
		return EFI_INVALID_PARAMETER;
	__builtin_memcpy(value, cursor, length * sizeof(*value));
	value[length] = 0U;
	*next = cursor + length;
	return EFI_SUCCESS;
}
static BOOLEAN keyword_selector_matches(struct cdk2_hii_keyword *entry,
	const CHAR16 *selector, UINTN selector_length);
static struct cdk2_hii_keyword *lookup_keyword_selector(const CHAR16 *name_space,
	const CHAR16 *keyword, const CHAR16 *selector, UINTN selector_length)
{
	UINTN index;

	for (index = 0U; index < CDK2_HII_MAX_KEYWORDS; index++)
		if (context.database.keywords[index].active &&
		    keyword_text_equal(context.database.keywords[index].name_space,
			name_space) &&
		    keyword_text_equal(context.database.keywords[index].keyword, keyword) &&
		    (selector == NULL || keyword_selector_matches(
			&context.database.keywords[index], selector, selector_length)))
			return &context.database.keywords[index];
	return NULL;
}
static UINT16 keyword_read16(const UINT8 *data)
{ return (UINT16)data[0] | ((UINT16)data[1] << 8); }
static UINT32 keyword_read32(const UINT8 *data)
{
	return (UINT32)keyword_read16(data) |
		((UINT32)keyword_read16(data + 2U) << 16);
}
static CHAR16 keyword_hex(UINT8 value)
{ return value < 10U ? (CHAR16)(L'0' + value) : (CHAR16)(L'A' + value - 10U); }
static const UINT8 *keyword_storage(const struct cdk2_hii_keyword *entry,
	UINT8 *storage_type, UINTN *storage_size)
{
	const struct cdk2_hii_list *list = entry->package_handle;
	const UINT8 *bytes, *package, *opcode;
	UINT32 package_length;
	UINTN package_offset, offset;
	UINT8 length;

	if (list == NULL || !list->active)
		return NULL;
	bytes = list->data;
	package_offset = sizeof(struct cdk2_hii_package_list_header);
	while (package_offset + 4U <= list->size) {
		package = bytes + package_offset;
		package_length = keyword_read32(package) & 0x00ffffffU;
		if (package_length < 4U || package_length > list->size - package_offset)
			return NULL;
		if (package[3] == 0x02U) {
			offset = 4U;
			while (offset + 2U <= package_length) {
				opcode = package + offset;
				length = opcode[1] & 0x7fU;
				if (length < 2U || length > package_length - offset)
					return NULL;
				if (((opcode[0] == 0x24U && length >= 23U &&
				      keyword_read16(opcode + 18U) == entry->varstore_id) ||
				     (opcode[0] == 0x25U && length >= 20U &&
				      keyword_read16(opcode + 2U) == entry->varstore_id) ||
				     (opcode[0] == 0x26U && length >= 27U &&
				      keyword_read16(opcode + 2U) == entry->varstore_id))) {
					*storage_type = opcode[0];
					*storage_size = length;
					return opcode;
				}
				offset += length;
			}
		}
		package_offset += package_length;
	}
	return NULL;
}
static EFI_STATUS keyword_device_path(void *driver, const UINT8 **path,
	UINTN *size)
{
	const UINT8 *bytes;
	UINTN offset = 0U;
	UINT16 node_size;
	EFI_STATUS status;

	status = context.boot->handle_protocol(driver, &device_path_guid,
		(void **)&bytes);
	if (EFI_ERROR(status))
		return status;
	while (offset < 4096U) {
		node_size = keyword_read16(bytes + offset + 2U);
		if (node_size < 4U || node_size > 4096U - offset)
			return EFI_INVALID_PARAMETER;
		offset += node_size;
		if (bytes[offset - node_size] == 0x7fU &&
		    bytes[offset - node_size + 1U] == 0xffU) {
			*path = bytes;
			*size = offset;
			return EFI_SUCCESS;
		}
	}
	return EFI_INVALID_PARAMETER;
}
static EFI_STATUS keyword_config_request(struct cdk2_hii_keyword *entry,
	const CHAR16 *value, CHAR16 **configuration, CHAR16 **path_text)
{
	const struct cdk2_hii_list *list = entry->package_handle;
	const UINT8 *storage, *guid, *path;
	const CHAR8 *ascii_name = NULL;
	CHAR16 *output, *cursor, *name_value = NULL;
	CHAR8 language[CDK2_HII_MAX_LANGUAGE + 1U];
	UINTN storage_size, path_size, name_length = 0U, needed, index;
	UINT8 storage_type;
	EFI_STATUS status;

	if (list == NULL || list->driver_handle == NULL ||
	    context.boot->handle_protocol == NULL)
		return EFI_NOT_FOUND;
	storage = keyword_storage(entry, &storage_type, &storage_size);
	if (storage == NULL)
		return EFI_NOT_FOUND;
	guid = storage + (storage_type == 0x24U ? 2U : 4U);
	if (storage_type == 0x24U)
		ascii_name = (const CHAR8 *)(storage + 22U);
	else if (storage_type == 0x26U)
		ascii_name = (const CHAR8 *)(storage + 26U);
	if (ascii_name != NULL) {
		while (22U + name_length < storage_size && ascii_name[name_length] != 0)
			name_length++;
		if ((storage_type == 0x24U ? 22U : 26U) + name_length >= storage_size)
			return EFI_INVALID_PARAMETER;
	} else {
		for (index = 0U; entry->name_space[index] != 0U; index++)
			language[index] = (CHAR8)entry->name_space[index];
		language[index] = 0;
		needed = 0U;
		status = cdk2_hii_get_string(&context.database, language,
			entry->package_handle, entry->varstore_info, NULL, &needed, NULL);
		if (status != EFI_BUFFER_TOO_SMALL)
			return EFI_NOT_FOUND;
		status = allocate(&context, needed, (void **)&name_value);
		if (EFI_ERROR(status))
			return status;
		status = cdk2_hii_get_string(&context.database, language,
			entry->package_handle, entry->varstore_info, name_value, &needed, NULL);
		if (EFI_ERROR(status)) {
			release(&context, name_value);
			return status;
		}
		name_length = text_length(name_value);
	}
	status = keyword_device_path(list->driver_handle, &path, &path_size);
	if (EFI_ERROR(status)) {
		if (name_value != NULL)
			release(&context, name_value);
		return status;
	}
	needed = 5U + 32U + 6U + name_length * 4U + 6U + path_size * 2U +
		(storage_type == 0x25U ? 6U + name_length * 4U : 15U + 16U) +
		(value == NULL ? 0U : 7U + text_length(value)) + 1U;
	status = allocate(&context, needed * sizeof(CHAR16), (void **)&output);
	if (EFI_ERROR(status))
		goto cleanup_name;
	cursor = output;
#define PUT_TEXT(text) do { const CHAR16 *p_ = (text); while (*p_ != 0U) *cursor++ = *p_++; } while (0)
	PUT_TEXT(L"GUID=");
	for (index = 0U; index < 16U; index++) {
		*cursor++ = keyword_hex(guid[index] >> 4); *cursor++ = keyword_hex(guid[index] & 15U);
	}
	PUT_TEXT(L"&NAME=");
	for (index = 0U; index < name_length; index++) {
		UINT16 character = name_value == NULL ? (UINT8)ascii_name[index] : name_value[index];
		*cursor++ = keyword_hex((UINT8)(character >> 12));
		*cursor++ = keyword_hex((UINT8)((character >> 8) & 15U));
		*cursor++ = keyword_hex((UINT8)((character >> 4) & 15U));
		*cursor++ = keyword_hex((UINT8)(character & 15U));
	}
	PUT_TEXT(L"&PATH=");
	if (path_text != NULL)
		*path_text = cursor;
	for (index = 0U; index < path_size; index++) {
		*cursor++ = keyword_hex(path[index] >> 4); *cursor++ = keyword_hex(path[index] & 15U);
	}
	if (storage_type == 0x25U) {
		PUT_TEXT(L"&NAME=");
		for (index = 0U; index < name_length; index++) {
			UINT16 character = name_value[index];
			*cursor++ = keyword_hex((UINT8)(character >> 12));
			*cursor++ = keyword_hex((UINT8)((character >> 8) & 15U));
			*cursor++ = keyword_hex((UINT8)((character >> 4) & 15U));
			*cursor++ = keyword_hex((UINT8)(character & 15U));
		}
	} else {
		static const CHAR16 hex[] = L"0123456789ABCDEF";
		PUT_TEXT(L"&OFFSET=");
		for (index = 0U; index < 4U; index++)
			*cursor++ = hex[(entry->varstore_info >> ((3U - index) * 4U)) & 15U];
		PUT_TEXT(L"&WIDTH=");
		for (index = 0U; index < 4U; index++)
			*cursor++ = hex[(entry->width >> ((3U - index) * 4U)) & 15U];
	}
	if (value != NULL) {
		PUT_TEXT(L"&VALUE=");
		PUT_TEXT(value);
	}
	*cursor = 0U;
#undef PUT_TEXT
	*configuration = output;
	status = EFI_SUCCESS;
cleanup_name:
	if (name_value != NULL)
		release(&context, name_value);
	return status;
}
static EFI_STATUS keyword_config_header(struct cdk2_hii_keyword *entry,
	CHAR16 **header)
{
	CHAR16 *request, *cursor, *last_name = NULL;
	EFI_STATUS status;

	status = keyword_config_request(entry, NULL, &request, NULL);
	if (EFI_ERROR(status))
		return status;
	for (cursor = request; *cursor != 0U; cursor++) {
		if (token(cursor, L"&OFFSET=")) {
			*cursor = 0U;
			*header = request;
			return EFI_SUCCESS;
		}
		if (token(cursor, L"&NAME="))
			last_name = cursor;
	}
	if (last_name == NULL || last_name == request + 37U) {
		release(&context, request);
		return EFI_DEVICE_ERROR;
	}
	*last_name = 0U;
	*header = request;
	return EFI_SUCCESS;
}
static BOOLEAN keyword_selector_matches(struct cdk2_hii_keyword *entry,
	const CHAR16 *selector, UINTN selector_length)
{
	CHAR16 *header;
	BOOLEAN matches;
	EFI_STATUS status = keyword_config_header(entry, &header);

	if (EFI_ERROR(status))
		return FALSE;
	matches = text_length(header) == selector_length;
	if (matches)
		while (selector_length-- != 0U)
			if (keyword_fold(header[selector_length]) !=
			    keyword_fold(selector[selector_length])) {
				matches = FALSE;
				break;
			}
	release(&context, header);
	return matches;
}
static EFI_STATUS keyword_extract_value(struct cdk2_hii_keyword *entry,
	CHAR16 **value)
{
	const struct cdk2_hii_list *list = entry->package_handle;
	struct config_access_protocol *access;
	CHAR16 *request, *result = NULL, *copy;
	CHAR16 *progress;
	const CHAR16 *found, *end;
	EFI_STATUS status;
	UINTN length;

	status = context.boot->handle_protocol(list->driver_handle,
		&config_access_guid, (void **)&access);
	if (EFI_ERROR(status))
		return status;
	status = keyword_config_request(entry, NULL, &request, NULL);
	if (EFI_ERROR(status))
		return status;
	status = access->extract(access, request, &progress, &result);
	release(&context, request);
	if (EFI_ERROR(status))
		return status;
	if (result == NULL)
		return EFI_DEVICE_ERROR;
	found = result;
	while (*found != 0U && !token(found, L"&VALUE="))
		found++;
	if (*found == 0U) {
		release(&context, result);
		return EFI_DEVICE_ERROR;
	}
	found += 7U;
	for (end = found; *end != 0U && *end != L'&'; end++)
		;
	length = (UINTN)(end - found);
	status = allocate(&context, (length + 1U) * sizeof(CHAR16), (void **)&copy);
	if (!EFI_ERROR(status)) {
		__builtin_memcpy(copy, found, length * sizeof(CHAR16));
		copy[length] = 0U;
		*value = copy;
	}
	release(&context, result);
	return status;
}
static EFI_STATUS keyword_route_value(struct cdk2_hii_keyword *entry,
	const CHAR16 *value)
{
	const struct cdk2_hii_list *list = entry->package_handle;
	struct config_access_protocol *access;
	CHAR16 *configuration;
	CHAR16 *progress;
	EFI_STATUS status;

	status = context.boot->handle_protocol(list->driver_handle,
		&config_access_guid, (void **)&access);
	if (EFI_ERROR(status))
		return status;
	status = keyword_config_request(entry, value, &configuration, NULL);
	if (EFI_ERROR(status))
		return status;
	status = access->route(access, configuration, &progress);
	release(&context, configuration);
	return status;
}
static EFI_STATUS keyword_refresh(struct cdk2_hii_keyword *entry)
{
	CHAR16 *value;
	EFI_STATUS status;

	if (entry->package_handle == NULL)
		return EFI_SUCCESS;
	status = keyword_extract_value(entry, &value);
	if (EFI_ERROR(status))
		return status;
	release(&context, entry->value);
	entry->value = value;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI keyword_set(const void *self, const CHAR16 *request,
	CHAR16 **progress, UINT32 *progress_error)
{
	struct staged_keyword {
		struct cdk2_hii_keyword *entry;
		CHAR16 name_space[128], keyword[128], value[256];
		const CHAR16 *start;
	};
	struct staged_keyword *staged;
	const CHAR16 *cursor, *next, *keyword_start, *selector;
	UINTN count = 0U, index, selector_length;
	EFI_STATUS status;

	(void)self;
	if (request == NULL || progress == NULL || progress_error == NULL)
		return EFI_INVALID_PARAMETER;
	status = allocate(&context, sizeof(*staged) * CDK2_HII_MAX_KEYWORDS,
		(void **)&staged);
	if (EFI_ERROR(status))
		return status;
	cursor = request;
	while (*cursor != 0U) {
		if (count == CDK2_HII_MAX_KEYWORDS) {
			status = EFI_OUT_OF_RESOURCES;
			goto failed;
		}
		*progress = (CHAR16 *)cursor;
		staged[count].start = cursor;
		status = field(cursor, L"NAMESPACE=", staged[count].name_space,
			ARRAY_SIZE(staged[count].name_space), &next);
		if (EFI_ERROR(status) || *next != L'&')
			goto malformed;
		selector = NULL;
		selector_length = 0U;
		keyword_start = next + 1U;
		if (!token(keyword_start, L"KEYWORD=")) {
			selector = keyword_start;
			for (; *keyword_start != 0U &&
			     !token(keyword_start, L"&KEYWORD="); keyword_start++)
				;
			if (*keyword_start == 0U)
				goto malformed;
			selector_length = (UINTN)(keyword_start - selector);
			keyword_start++;
		}
		status = field(keyword_start, L"KEYWORD=", staged[count].keyword,
			ARRAY_SIZE(staged[count].keyword), &next);
		if (EFI_ERROR(status) || *next != L'&' || !token(next + 1U, L"VALUE="))
			goto malformed;
		status = field(next + 1U, L"VALUE=", staged[count].value,
			ARRAY_SIZE(staged[count].value), &next);
		if (EFI_ERROR(status))
			goto malformed;
		staged[count].entry = lookup_keyword_selector(staged[count].name_space,
			staged[count].keyword, selector, selector_length);
		if (staged[count].entry == NULL) {
			*progress_error = 0x00000004U;
			status = EFI_NOT_FOUND;
			goto failed;
		}
		if (staged[count].entry->read_only) {
			*progress_error = 0x00000010U;
			status = EFIERR(15);
			goto failed;
		}
		count++;
		cursor = *next == L'&' ? next + 1U : next;
	}
	for (index = 0U; index < count; index++) {
		status = staged[index].entry->package_handle == NULL ?
			cdk2_hii_set_keyword_data(&context.database,
				staged[index].name_space, staged[index].keyword,
				staged[index].value) :
			keyword_route_value(staged[index].entry, staged[index].value);
		if (EFI_ERROR(status)) {
			*progress = (CHAR16 *)staged[index].start;
			*progress_error = 0x80000000U;
			goto failed;
		}
	}
	*progress = (CHAR16 *)cursor;
	*progress_error = 0U;
	release(&context, staged);
	return EFI_SUCCESS;
malformed:
	*progress_error = 0x00000002U;
	status = EFI_INVALID_PARAMETER;
failed:
	release(&context, staged);
	return status;
}

static EFI_STATUS append_keyword(CHAR16 *output, UINTN *offset,
	const struct cdk2_hii_keyword *entry)
{
	static const CHAR16 namespace_token[] = L"NAMESPACE=";
	static const CHAR16 keyword_token[] = L"&KEYWORD=";
	static const CHAR16 value_token[] = L"&VALUE=";
	static const CHAR16 read_only_token[] = L"&READONLY";
	const CHAR16 *pieces[] = { namespace_token, entry->name_space };
	CHAR16 *header = NULL;
	EFI_STATUS status;
	UINTN index, length;

	for (index = 0; index < ARRAY_SIZE(pieces); index++) {
		length = text_length(pieces[index]);
		if (output != NULL)
			__builtin_memcpy(output + *offset, pieces[index],
				length * sizeof(CHAR16));
		*offset += length;
	}
	if (entry->package_handle != NULL) {
		status = keyword_config_header((struct cdk2_hii_keyword *)entry, &header);
		if (EFI_ERROR(status))
			return status;
		if (output != NULL)
			output[(*offset)] = L'&';
		(*offset)++;
		length = text_length(header);
		if (output != NULL)
			__builtin_memcpy(output + *offset, header,
				length * sizeof(CHAR16));
		*offset += length;
		release(&context, header);
	}
	{
		const CHAR16 *tail[] = { keyword_token, entry->keyword,
			value_token, entry->value };
		for (index = 0U; index < ARRAY_SIZE(tail); index++) {
			length = text_length(tail[index]);
			if (output != NULL)
				__builtin_memcpy(output + *offset, tail[index],
					length * sizeof(CHAR16));
			*offset += length;
		}
	}
	if (entry->read_only) {
		length = text_length(read_only_token);
		if (output != NULL)
			__builtin_memcpy(output + *offset, read_only_token,
				length * sizeof(CHAR16));
		*offset += length;
	}
	return EFI_SUCCESS;
}
static EFI_STATUS keyword_filter(const struct cdk2_hii_keyword *entry,
	const CHAR16 *filter, const CHAR16 **next)
{
	UINTN length = 0U;
	BOOLEAN numeric = entry->opcode == 0x05U || entry->opcode == 0x07U ||
		entry->opcode == 0x06U;
	BOOLEAN matches = TRUE;

	while (filter[length] != 0U && filter[length] != L'&')
		length++;
	if (length == 8U && token(filter, L"ReadOnly"))
		matches = entry->read_only;
	else if (length == 9U && token(filter, L"ReadWrite"))
		matches = !entry->read_only;
	else if (length == 6U && token(filter, L"Buffer"))
		matches = !numeric;
	else if (length == 7U && token(filter, L"Numeric"))
		matches = numeric;
	else if (length == 9U && token(filter, L"Numeric:")) {
		UINT8 wanted = filter[8] == L'1' ? 0U : filter[8] == L'2' ? 1U :
			filter[8] == L'4' ? 2U : filter[8] == L'8' ? 3U : 0xffU;
		matches = numeric && wanted != 0xffU &&
			(entry->opcode == 0x06U ? wanted == 0U :
			 entry->numeric_size == wanted);
	} else {
		return EFI_INVALID_PARAMETER;
	}
	*next = filter + length;
	return matches ? EFI_SUCCESS : EFI_NOT_FOUND;
}
static EFI_STATUS CDK2_MS_ABI keyword_get(const void *self,
	const CHAR16 *requested_namespace, const CHAR16 *request, CHAR16 **progress,
	UINT32 *progress_error, CHAR16 **results)
{
	CHAR16 keyword[128];
	const CHAR16 *cursor, *next, *keyword_start, *selector;
	struct cdk2_hii_keyword *entry;
	struct cdk2_hii_keyword *entries[CDK2_HII_MAX_KEYWORDS];
	CHAR16 *output;
	UINTN index, offset = 0U, matches = 0U, selector_length;
	EFI_STATUS status;

	(void)self;
	if (progress == NULL || progress_error == NULL || results == NULL)
		return EFI_INVALID_PARAMETER;
	if (request == NULL) {
		for (index = 0; index < CDK2_HII_MAX_KEYWORDS; index++)
			if (context.database.keywords[index].active &&
			    ((requested_namespace == NULL && keyword_prefix(
				context.database.keywords[index].name_space, L"x-UEFI-")) ||
			     (requested_namespace != NULL && keyword_text_equal(
				requested_namespace,
				context.database.keywords[index].name_space)))) {
				status = keyword_refresh(&context.database.keywords[index]);
				if (EFI_ERROR(status)) {
					*progress_error = 0x80000000U;
					return status;
				}
				if (matches++ != 0U)
					offset++;
				entries[matches - 1U] = &context.database.keywords[index];
				status = append_keyword(NULL, &offset,
					&context.database.keywords[index]);
				if (EFI_ERROR(status)) {
					*progress_error = 0x80000000U;
					return status;
				}
			}
		*progress = NULL;
	} else {
		cursor = request;
		while (*cursor != 0U) {
			*progress = (CHAR16 *)cursor;
			selector = NULL;
			selector_length = 0U;
			keyword_start = cursor;
			if (!token(keyword_start, L"KEYWORD=")) {
				for (; *keyword_start != 0U &&
				     !token(keyword_start, L"&KEYWORD="); keyword_start++)
					;
				if (*keyword_start == 0U) {
					*progress_error = 0x00000002U;
					return EFI_INVALID_PARAMETER;
				}
				selector = cursor;
				selector_length = (UINTN)(keyword_start - cursor);
				keyword_start++;
			}
			status = field(keyword_start, L"KEYWORD=", keyword,
				ARRAY_SIZE(keyword), &next);
			if (EFI_ERROR(status)) {
				*progress_error = 0x00000002U;
				return EFI_INVALID_PARAMETER;
			}
			entry = requested_namespace == NULL ? NULL :
				lookup_keyword_selector(requested_namespace, keyword,
					selector, selector_length);
			if (entry == NULL) {
				*progress_error = requested_namespace == NULL ?
					0x00000001U : 0x00000004U;
				return EFI_NOT_FOUND;
			}
			status = keyword_refresh(entry);
			if (EFI_ERROR(status)) {
				*progress_error = 0x80000000U;
				return status;
			}
			while (*next == L'&' && !token(next + 1U, L"KEYWORD=") &&
			       !token(next + 1U, L"GUID=")) {
				const CHAR16 *after;
				status = keyword_filter(entry, next + 1U, &after);
				if (status == EFI_INVALID_PARAMETER) {
					*progress = (CHAR16 *)next;
					*progress_error = 0x00000002U;
					return status;
				}
				if (status == EFI_NOT_FOUND) {
					*progress = (CHAR16 *)next;
					*progress_error = 0x00000008U;
					return EFI_INVALID_PARAMETER;
				}
				next = after;
			}
			if (matches++ != 0U)
				offset++;
			entries[matches - 1U] = entry;
			status = append_keyword(NULL, &offset, entry);
			if (EFI_ERROR(status)) {
				*progress_error = 0x80000000U;
				return status;
			}
			cursor = *next == L'&' ? next + 1U : next;
		}
		*progress = (CHAR16 *)cursor;
	}
	if (matches == 0U) {
		*progress_error = 0x00000001U;
		return EFI_NOT_FOUND;
	}
	status = allocate(&context, (offset + 1U) * sizeof(CHAR16), (void **)&output);
	if (EFI_ERROR(status))
		return status;
	offset = 0U;
	for (index = 0; index < matches; index++) {
		if (index != 0U)
			output[offset++] = L'&';
		status = append_keyword(output, &offset, entries[index]);
		if (EFI_ERROR(status)) {
			release(&context, output);
			*progress_error = 0x80000000U;
			return status;
		}
	}
	output[offset] = 0U;
	*results = output;
	*progress_error = 0U;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_hii_database_entry(void *image, void *system_table)
{
	static const struct cdk2_hii_database_ops ops = {
		.allocate = allocate, .release = release, .decode_image = decode_image
	};
	struct system_table_view *system = system_table;
	void *handle = NULL;
	EFI_STATUS status;
	(void)image;

	if (system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	context.boot = system->boot;
	status = cdk2_hii_database_init(&context.database, &ops, &context);
	if (EFI_ERROR(status))
		return status;
	context.database_protocol = (struct cdk2_efi_hii_database_protocol) {
		.new_package_list = new_package, .remove_package_list = remove_package,
		.update_package_list = update_package, .list_package_lists = list_packages,
		.export_package_lists = export_packages,
		.register_package_notify = register_notify,
		.unregister_package_notify = unregister_notify,
		.find_keyboard_layouts = find_layouts, .get_keyboard_layout = get_layout,
		.set_keyboard_layout = set_layout, .get_package_list_handle = get_driver
	};
	context.string_protocol = (struct cdk2_efi_hii_string_protocol) {
		.new_string = new_string, .get_string = get_string, .set_string = set_string,
		.get_languages = get_languages, .get_secondary_languages = get_secondary
	};
	context.image_protocol = (struct cdk2_efi_hii_image_protocol) {
		.new_image = new_image, .get_image = get_image, .set_image = set_image,
		.draw_image = draw_image, .draw_image_id = draw_image_id
	};
	context.font_protocol = (struct cdk2_efi_hii_font_protocol) {
		.string_to_image = string_to_image,
		.string_id_to_image = string_id_to_image,
		.get_glyph = get_glyph, .get_font_info = get_font_info
	};
	context.config_protocol = (struct cdk2_efi_hii_config_routing_protocol) {
		.extract_config = extract_config, .export_config = export_config,
		.route_config = route_config, .block_to_config = block_to_config,
		.config_to_block = config_to_block, .get_alt_config = get_alt_config
	};
	context.keyword_protocol = (struct cdk2_efi_config_keyword_protocol) {
		.set_data = keyword_set, .get_data = keyword_get
	};
	return context.boot->install_multiple(&handle,
		&database_guid, &context.database_protocol,
		&string_guid, &context.string_protocol,
		&image_guid, &context.image_protocol,
		&font_guid, &context.font_protocol,
		&config_guid, &context.config_protocol,
		&keyword_guid, &context.keyword_protocol, NULL);
}
