/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_console_binding.h>
#include <cdk2/graphics_console_package.h>

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN, event_notify_fn *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI register_notify_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);

struct boot_services_view {
	UINT8 header[24];
	void *raise_tpl;
	void *restore_tpl;
	void *allocate_pages;
	void *free_pages;
	void *get_memory_map;
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	create_event_fn *create_event;
	void *set_timer;
	void *wait_for_event;
	void *signal_event;
	close_event_fn *close_event;
	void *check_event;
	void *install_protocol;
	void *reinstall_protocol;
	void *uninstall_protocol;
	void *handle_protocol;
	void *reserved;
	register_notify_fn *register_protocol_notify;
	void *locate_handle;
	void *locate_device_path;
	void *install_configuration_table;
	void *load_image;
	void *start_image;
	void *exit;
	void *unload_image;
	void *exit_boot_services;
	void *get_next_monotonic_count;
	void *stall;
	void *set_watchdog_timer;
	void *connect_controller;
	void *disconnect_controller;
	open_protocol_fn *open_protocol;
	close_protocol_fn *close_protocol;
	void *open_protocol_information;
	void *protocols_per_handle;
	void *locate_handle_buffer;
	locate_protocol_fn *locate_protocol;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct system_table_view { UINT8 before_boot_services[96]; struct boot_services_view *boot; };

struct graphics_entry_context {
	struct boot_services_view *boot;
	void *image;
	void *notify_event;
	void *notify_registration;
	struct cdk2_graphics_console_binding binding;
	struct cdk2_graphics_font_package package;
	BOOLEAN cursor_drawn;
};

static struct graphics_entry_context entry_context;
static const EFI_GUID hii_database_guid = { 0xef9fc172, 0xa1b2, 0x4693,
	{ 0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42 } };
static const EFI_GUID gop_guid = { 0x9042a9de, 0x23dc, 0x4a38,
	{ 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } };
static const struct cdk2_graphics_pixel palette[16] = {
	{ 0x00, 0x00, 0x00, 0 }, { 0x98, 0x00, 0x00, 0 },
	{ 0x00, 0x98, 0x00, 0 }, { 0x98, 0x98, 0x00, 0 },
	{ 0x00, 0x00, 0x98, 0 }, { 0x98, 0x00, 0x98, 0 },
	{ 0x00, 0x98, 0x98, 0 }, { 0x98, 0x98, 0x98, 0 },
	{ 0x30, 0x30, 0x30, 0 }, { 0xff, 0x00, 0x00, 0 },
	{ 0x00, 0xff, 0x00, 0 }, { 0xff, 0xff, 0x00, 0 },
	{ 0x00, 0x00, 0xff, 0 }, { 0xff, 0x00, 0xff, 0 },
	{ 0x00, 0xff, 0xff, 0 }, { 0xff, 0xff, 0xff, 0 },
};

static int guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const void *)left;
	const UINT8 *b = (const void *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return 0;
	return 1;
}

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ return ((struct graphics_entry_context *)context)->boot->allocate_pool(4U, size, buffer); }
static void release(void *context, void *buffer)
{ (void)((struct graphics_entry_context *)context)->boot->free_pool(buffer); }

static EFI_STATUS draw(void *context, CHAR16 character, UINT32 column, UINT32 row,
	UINT8 attribute, BOOLEAN wide)
{
	struct graphics_entry_context *entry = context;
	const struct cdk2_graphics_text_mode *mode =
		&entry->binding.console.modes[entry->binding.console.mode];
	struct cdk2_image_output *image = NULL;
	struct cdk2_font_display_info display = { 0 };
	CHAR16 string[2] = { character, 0 };

	display.foreground = palette[attribute & 0x0fU];
	display.background = palette[(attribute >> 4) & 0x07U];
	display.mask = 0x00000003U;
	return cdk2_graphics_render_string(&entry->binding, string, &display, &image,
		mode->horizontal_delta + column * mode->glyph_width,
		mode->vertical_delta + row * mode->glyph_height,
		mode->glyph_width * (wide ? 2U : 1U), mode->glyph_height);
}

static EFI_STATUS fill(void *context, UINT32 column, UINT32 row, UINT32 columns,
	UINT32 rows, UINT8 attribute)
{
	struct graphics_entry_context *entry = context;
	const struct cdk2_graphics_text_mode *mode =
		&entry->binding.console.modes[entry->binding.console.mode];
	struct cdk2_graphics_pixel color = palette[(attribute >> 4) & 0x07U];

	return cdk2_graphics_gop_blt(&entry->binding, &color, 0U, 0, 0,
		mode->horizontal_delta + column * mode->glyph_width,
		mode->vertical_delta + row * mode->glyph_height,
		columns * mode->glyph_width, rows * mode->glyph_height, 0);
}

static EFI_STATUS scroll(void *context, UINT32 rows, UINT8 attribute)
{
	struct graphics_entry_context *entry = context;
	const struct cdk2_graphics_text_mode *mode =
		&entry->binding.console.modes[entry->binding.console.mode];
	EFI_STATUS status = cdk2_graphics_gop_blt(&entry->binding, NULL, 3U,
		mode->horizontal_delta, mode->vertical_delta + rows * mode->glyph_height,
		mode->horizontal_delta, mode->vertical_delta,
		mode->columns * mode->glyph_width, (mode->rows - rows) * mode->glyph_height, 0);

	if (EFI_ERROR(status))
		return status;
	return fill(context, 0, mode->rows - rows, mode->columns, rows, attribute);
}

static EFI_STATUS cursor(void *context, UINT32 column, UINT32 row, BOOLEAN visible,
	UINT8 attribute)
{
	struct graphics_entry_context *entry = context;
	const struct cdk2_graphics_text_mode *mode =
		&entry->binding.console.modes[entry->binding.console.mode];
	struct cdk2_graphics_pixel pixels[19][8];
	UINTN x, y;
	EFI_STATUS status;

	if (entry->cursor_drawn == visible)
		return EFI_SUCCESS;
	x = mode->horizontal_delta + column * mode->glyph_width;
	y = mode->vertical_delta + row * mode->glyph_height;
	status = cdk2_graphics_gop_blt(&entry->binding, pixels, 1U, x, y, 0, 0, 8U,
		19U, sizeof(pixels[0]));
	if (EFI_ERROR(status))
		return status;
	for (y = 15U; y < 17U; y++)
		for (x = 0; x < 8U; x++) {
			pixels[y][x].blue ^= palette[attribute & 0x0fU].blue;
			pixels[y][x].green ^= palette[attribute & 0x0fU].green;
			pixels[y][x].red ^= palette[attribute & 0x0fU].red;
		}
	status = cdk2_graphics_gop_blt(&entry->binding, pixels, 2U, 0, 0,
		mode->horizontal_delta + column * mode->glyph_width,
		mode->vertical_delta + row * mode->glyph_height, 8U, 19U, sizeof(pixels[0]));
	if (!EFI_ERROR(status))
		entry->cursor_drawn = visible;
	return status;
}

static const struct cdk2_graphics_console_ops text_ops = { draw, fill, scroll, cursor };

static EFI_STATUS open(void *context, void *controller, const EFI_GUID *protocol,
	UINT32 attributes, void **interface)
{
	struct graphics_entry_context *entry = context;
	EFI_STATUS status = entry->boot->open_protocol(controller, protocol, interface, entry->image,
		controller, attributes);

	if (!EFI_ERROR(status) && guid_equal(protocol, &gop_guid)) {
		struct cdk2_gop_view *gop = *interface;

		if (gop == NULL || gop->mode == NULL || gop->mode->info == NULL)
			status = EFI_DEVICE_ERROR;
		if (EFI_ERROR(status)) {
			(void)entry->boot->close_protocol(controller, protocol, entry->image,
				controller);
			return status;
		}
		entry->binding.gop = gop;
		entry->binding.console.mode_count = 0U;
		status = cdk2_graphics_console_add_mode(&entry->binding.console,
			gop->mode->info->horizontal_resolution,
			gop->mode->info->vertical_resolution, 8U, 19U);
		if (!EFI_ERROR(status))
			status = cdk2_graphics_binding_prepare_text(&entry->binding, &text_ops, entry);
	}
	return status;
}
static EFI_STATUS close(void *context, void *controller, const EFI_GUID *protocol)
{
	struct graphics_entry_context *entry = context;
	return entry->boot->close_protocol(controller, protocol, entry->image, controller);
}
static EFI_STATUS locate(void *context, const EFI_GUID *protocol, void **interface)
{ return ((struct graphics_entry_context *)context)->boot->locate_protocol(protocol, NULL, interface); }
static EFI_STATUS install(void *context, void *controller, const EFI_GUID *protocol,
	void *interface)
{ return ((struct graphics_entry_context *)context)->boot->install_multiple(&controller, protocol, interface, NULL); }
static EFI_STATUS uninstall(void *context, void *controller, const EFI_GUID *protocol,
	void *interface)
{ return ((struct graphics_entry_context *)context)->boot->uninstall_multiple(controller, protocol, interface, NULL); }
static EFI_STATUS publish(void *context, void *handle, const EFI_GUID *protocol, void *interface)
{ return install(context, handle, protocol, interface); }

static void CDK2_MS_ABI database_available(void *event, void *context)
{
	struct graphics_entry_context *entry = context;
	struct cdk2_hii_database_view *database;

	(void)event;
	if (entry->package.handle != NULL || EFI_ERROR(locate(entry, &hii_database_guid,
	    (void **)&database)))
		return;
	(void)cdk2_graphics_font_install(&entry->package, database, allocate, release, entry);
}

static EFI_STATUS notify(void *context, const EFI_GUID *protocol)
{
	struct graphics_entry_context *entry = context;
	EFI_STATUS status = entry->boot->create_event(0x200U, 8U, database_available, entry,
		&entry->notify_event);

	if (EFI_ERROR(status))
		return status;
	status = entry->boot->register_protocol_notify(protocol, entry->notify_event,
		&entry->notify_registration);
	if (EFI_ERROR(status)) {
		entry->boot->close_event(entry->notify_event);
		entry->notify_event = NULL;
		return status;
	}
	database_available(entry->notify_event, entry);
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_graphics_console_entry(void *image, struct system_table_view *system)
{
	static const struct cdk2_graphics_console_binding_ops ops = {
		open, close, locate, install, uninstall
	};
	if (image == NULL || system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	__builtin_memset(&entry_context, 0, sizeof(entry_context));
	entry_context.boot = system->boot;
	entry_context.image = image;
	entry_context.binding.ops = &ops;
	entry_context.binding.context = &entry_context;
	return cdk2_graphics_binding_publish(&entry_context.binding, image, publish, notify,
		&entry_context);
}
