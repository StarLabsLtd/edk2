/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_console_binding.h>

#define EFI_NOT_STARTED EFIERR(19)
#define EFI_ALREADY_STARTED EFIERR(20)

static const EFI_GUID device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID gop_guid = { 0x9042a9de, 0x23dc, 0x4a38,
	{ 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } };
static const EFI_GUID font_guid = { 0xe9ca4775, 0x8657, 0x47fc,
	{ 0x97, 0xe7, 0x7e, 0xd6, 0x5a, 0x08, 0x43, 0x24 } };
static const EFI_GUID text_guid = { 0x387477c2, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const EFI_GUID hii_database_guid = { 0xef9fc172, 0xa1b2, 0x4693,
	{ 0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42 } };
static CHAR16 driver_name[] = L"CDK2 Graphics Console Driver";

static struct cdk2_graphics_console_binding *from_text(
	struct cdk2_simple_text_output_view *text)
{
	return (struct cdk2_graphics_console_binding *)((UINT8 *)text -
		offsetof(struct cdk2_graphics_console_binding, text));
}

static void sync_text_mode(struct cdk2_graphics_console_binding *binding)
{
	binding->text_mode.max_mode = (INT32)binding->console.mode_count;
	binding->text_mode.mode = (INT32)binding->console.mode;
	binding->text_mode.attribute = (INT32)binding->console.attribute;
	binding->text_mode.cursor_column = (INT32)binding->console.column;
	binding->text_mode.cursor_row = (INT32)binding->console.row;
	binding->text_mode.cursor_visible = binding->console.cursor_visible;
}

static EFI_STATUS CDK2_MS_ABI text_reset(struct cdk2_simple_text_output_view *text,
	BOOLEAN extended)
{
	struct cdk2_graphics_console_binding *binding = from_text(text);
	EFI_STATUS status;

	(void)extended;
	status = cdk2_graphics_console_set_mode(&binding->console, 0U);
	if (!EFI_ERROR(status))
		sync_text_mode(binding);
	return status;
}

static EFI_STATUS CDK2_MS_ABI text_output(struct cdk2_simple_text_output_view *text,
	CHAR16 *string)
{
	struct cdk2_graphics_console_binding *binding = from_text(text);
	EFI_STATUS status = cdk2_graphics_console_output(&binding->console, string);

	sync_text_mode(binding);
	return status;
}

static EFI_STATUS CDK2_MS_ABI text_test(struct cdk2_simple_text_output_view *text,
	CHAR16 *string)
{
	struct cdk2_graphics_console_binding *binding = from_text(text);
	struct cdk2_image_output *image;
	UINTN baseline;
	EFI_STATUS status;
	CHAR16 *character;

	status = cdk2_graphics_console_test_string(string);
	if (EFI_ERROR(status) || binding->font == NULL ||
	    binding->font->get_glyph == NULL)
		return EFI_ERROR(status) ? status : EFI_UNSUPPORTED;
	for (character = string; *character != 0U; character++) {
		if (*character < 0x20U || *character == 0xfff0U || *character == 0xfff1U)
			continue;
		image = NULL;
		status = binding->font->get_glyph(binding->font, *character, NULL,
			&image, &baseline);
		if (EFI_ERROR(status))
			return EFI_UNSUPPORTED;
		if (image != NULL) {
			if (image->image.bitmap != NULL && binding->ops->release != NULL)
				binding->ops->release(binding->context, image->image.bitmap);
			if (binding->ops->release != NULL)
				binding->ops->release(binding->context, image);
		}
	}
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI text_query(struct cdk2_simple_text_output_view *text,
	UINTN mode, UINTN *columns, UINTN *rows)
{
	struct cdk2_graphics_console *console = &from_text(text)->console;

	if (columns == NULL || rows == NULL)
		return EFI_INVALID_PARAMETER;
	if (mode >= console->mode_count)
		return EFI_UNSUPPORTED;
	*columns = console->modes[mode].columns;
	*rows = console->modes[mode].rows;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI text_set_mode(struct cdk2_simple_text_output_view *text,
	UINTN mode)
{
	struct cdk2_graphics_console_binding *binding = from_text(text);
	EFI_STATUS status;

	if (mode >= binding->console.mode_count)
		return EFI_UNSUPPORTED;
	if (binding->gop != NULL && binding->gop->set_mode != NULL &&
	    binding->gop->mode->mode != binding->console.modes[mode].gop_mode) {
		status = binding->gop->set_mode(binding->gop,
			binding->console.modes[mode].gop_mode);
		if (EFI_ERROR(status))
			return status;
	}
	status = cdk2_graphics_console_set_mode(&binding->console, (UINT32)mode);

	if (!EFI_ERROR(status))
		sync_text_mode(binding);
	return status;
}

static EFI_STATUS CDK2_MS_ABI text_set_attribute(struct cdk2_simple_text_output_view *text,
	UINTN attribute)
{
	struct cdk2_graphics_console_binding *binding = from_text(text);
	EFI_STATUS status = cdk2_graphics_console_set_attribute(&binding->console, attribute);

	if (!EFI_ERROR(status))
		sync_text_mode(binding);
	return status;
}

static EFI_STATUS CDK2_MS_ABI text_clear(struct cdk2_simple_text_output_view *text)
{
	return text_set_mode(text, from_text(text)->console.mode);
}

static EFI_STATUS CDK2_MS_ABI text_set_cursor(struct cdk2_simple_text_output_view *text,
	UINTN column, UINTN row)
{
	struct cdk2_graphics_console_binding *binding = from_text(text);
	EFI_STATUS status = cdk2_graphics_console_set_cursor(&binding->console, column, row);

	if (!EFI_ERROR(status))
		sync_text_mode(binding);
	return status;
}

static EFI_STATUS CDK2_MS_ABI text_enable_cursor(struct cdk2_simple_text_output_view *text,
	BOOLEAN visible)
{
	struct cdk2_graphics_console_binding *binding = from_text(text);
	EFI_STATUS status = cdk2_graphics_console_enable_cursor(&binding->console, visible);

	if (!EFI_ERROR(status))
		sync_text_mode(binding);
	return status;
}

EFI_STATUS cdk2_graphics_binding_prepare_text(struct cdk2_graphics_console_binding *binding,
	const struct cdk2_graphics_console_ops *ops, void *context)
{
	EFI_STATUS status;

	if (binding == NULL)
		return EFI_INVALID_PARAMETER;
	binding->text_ops = ops;
	status = cdk2_graphics_console_init(&binding->console, ops, context);
	if (EFI_ERROR(status))
		return status;
	binding->text = (struct cdk2_simple_text_output_view) {
		.reset = text_reset,
		.output_string = text_output,
		.test_string = text_test,
		.query_mode = text_query,
		.set_mode = text_set_mode,
		.set_attribute = text_set_attribute,
		.clear_screen = text_clear,
		.set_cursor_position = text_set_cursor,
		.enable_cursor = text_enable_cursor,
		.mode = &binding->text_mode,
	};
	sync_text_mode(binding);
	return EFI_SUCCESS;
}

static struct cdk2_graphics_console_binding *from_driver(
	struct cdk2_driver_binding_view *driver)
{
	return (struct cdk2_graphics_console_binding *)((UINT8 *)driver -
		offsetof(struct cdk2_graphics_console_binding, driver));
}

static EFI_STATUS CDK2_MS_ABI driver_supported(struct cdk2_driver_binding_view *driver,
	void *controller, void *remaining)
{
	(void)remaining;
	return cdk2_graphics_binding_supported(from_driver(driver), controller);
}

static EFI_STATUS CDK2_MS_ABI driver_start(struct cdk2_driver_binding_view *driver,
	void *controller, void *remaining)
{
	struct cdk2_graphics_console_binding *root = from_driver(driver);
	struct cdk2_graphics_console_binding *instance;
	EFI_STATUS status;

	(void)remaining;
	if (root->ops->allocate == NULL || root->ops->release == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = root->ops->allocate(root->context, sizeof(*instance), (void **)&instance);
	if (EFI_ERROR(status))
		return status;
	*instance = (struct cdk2_graphics_console_binding) {
		.ops = root->ops,
		.context = root->context,
		.text_ops = root->text_ops,
		.owner = root,
	};
	status = cdk2_graphics_binding_start(instance, controller);
	if (EFI_ERROR(status)) {
		root->ops->release(root->context, instance);
		return status;
	}
	instance->next = root->instances;
	root->instances = instance;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI driver_stop(struct cdk2_driver_binding_view *driver,
	void *controller, UINTN children, void **child_buffer)
{
	struct cdk2_graphics_console_binding *root = from_driver(driver);
	struct cdk2_graphics_console_binding **link = &root->instances;
	struct cdk2_graphics_console_binding *binding;
	EFI_STATUS status;

	(void)child_buffer;
	if (children != 0U)
		return EFI_INVALID_PARAMETER;
	while (*link != NULL && (*link)->controller != controller)
		link = &(*link)->next;
	if (*link == NULL)
		return EFI_INVALID_PARAMETER;
	binding = *link;
	status = cdk2_graphics_binding_stop(binding);
	if (EFI_ERROR(status))
		return status;
	*link = binding->next;
	root->ops->release(root->context, binding);
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_driver_name(struct cdk2_component_name_view *component,
	CHAR8 * language, cdk2_char16_ptr * name)
{
	(void)component;
	if (language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (language[0] != 'e' || language[1] != 'n' || language[2] != 'g' ||
	    language[3] != '\0')
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_controller_name(struct cdk2_component_name_view *component,
	void *controller, void *child, CHAR8 * language, cdk2_char16_ptr * name)
{
	(void)component;
	(void)controller;
	(void)child;
	(void)language;
	(void)name;
	return EFI_UNSUPPORTED;
}

static EFI_STATUS CDK2_MS_ABI get_driver_name2(struct cdk2_component_name_view *component,
	CHAR8 * language, cdk2_char16_ptr * name)
{
	(void)component;
	if (language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (language[0] != 'e' || language[1] != 'n' || language[2] != '\0')
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS rollback(struct cdk2_graphics_console_binding *binding)
{
	EFI_STATUS status;

	if (binding->text_installed) {
		status = binding->ops->uninstall(binding->context, binding->controller, &text_guid,
			&binding->text);
		if (EFI_ERROR(status))
			return status;
		binding->text_installed = FALSE;
	}
	binding->font = NULL;
	if (binding->gop_open) {
		binding->ops->close(binding->context, binding->controller, &gop_guid);
		binding->gop_open = FALSE;
	}
	if (binding->device_path_open) {
		binding->ops->close(binding->context, binding->controller, &device_path_guid);
		binding->device_path_open = FALSE;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_graphics_binding_supported(struct cdk2_graphics_console_binding *binding,
	void *controller)
{
	void *interface;
	EFI_STATUS status;

	if (binding == NULL || binding->ops == NULL || binding->ops->open == NULL ||
	    binding->ops->close == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->ops->open(binding->context, controller, &gop_guid,
		CDK2_OPEN_BY_DRIVER, &interface);
	if (!EFI_ERROR(status))
		binding->ops->close(binding->context, controller, &gop_guid);
	return status;
}

static EFI_STATUS select_mode_zero(struct cdk2_graphics_console_binding *binding)
{
	struct cdk2_gop_mode_info *info;
	UINTN size;
	UINT32 mode;
	EFI_STATUS status;

	if (binding->gop->mode->info->horizontal_resolution >= 640U &&
	    binding->gop->mode->info->vertical_resolution >= 475U)
		return EFI_SUCCESS;
	if (binding->gop->query_mode == NULL || binding->gop->set_mode == NULL ||
	    binding->ops->release == NULL)
		return EFI_UNSUPPORTED;
	for (mode = 0; mode < binding->gop->mode->max_mode; mode++) {
		info = NULL;
		status = binding->gop->query_mode(binding->gop, mode, &size, &info);
		if (!EFI_ERROR(status) && info != NULL &&
		    info->horizontal_resolution >= 640U &&
		    info->vertical_resolution >= 475U) {
			binding->ops->release(binding->context, info);
			return binding->gop->set_mode(binding->gop, mode);
		}
		if (info != NULL)
			binding->ops->release(binding->context, info);
	}
	return EFI_UNSUPPORTED;
}

EFI_STATUS cdk2_graphics_binding_start(struct cdk2_graphics_console_binding *binding,
	void *controller)
{
	void *interface;
	EFI_STATUS status;

	if (binding == NULL || binding->ops == NULL || binding->ops->open == NULL ||
	    binding->ops->close == NULL || binding->ops->install == NULL ||
	    binding->ops->uninstall == NULL || binding->ops->locate == NULL ||
	    binding->text_ops == NULL)
		return EFI_INVALID_PARAMETER;
	binding->controller = controller;
	status = binding->ops->open(binding->context, controller, &device_path_guid,
		CDK2_OPEN_BY_DRIVER, &interface);
	if (EFI_ERROR(status))
		return status;
	binding->device_path_open = TRUE;
	status = binding->ops->open(binding->context, controller, &gop_guid,
		CDK2_OPEN_BY_DRIVER, (void **)&binding->gop);
	if (EFI_ERROR(status))
		goto fail;
	binding->gop_open = TRUE;
	status = select_mode_zero(binding);
	if (EFI_ERROR(status))
		goto fail;
	binding->console.mode_count = 0U;
	status = cdk2_graphics_console_add_mode_geometry(&binding->console,
		binding->gop->mode->info->horizontal_resolution,
		binding->gop->mode->info->vertical_resolution, 80U, 25U, 8U, 19U,
		binding->gop->mode->mode);
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_graphics_console_add_mode_geometry(&binding->console,
		binding->gop->mode->info->horizontal_resolution,
		binding->gop->mode->info->vertical_resolution,
		binding->gop->mode->info->horizontal_resolution / 8U,
		binding->gop->mode->info->vertical_resolution / 19U, 8U, 19U,
		binding->gop->mode->mode);
	if (status == EFI_ALREADY_STARTED)
		status = EFI_SUCCESS;
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_graphics_binding_prepare_text(binding, binding->text_ops, binding);
	if (EFI_ERROR(status))
		goto fail;
	status = binding->ops->locate(binding->context, &font_guid, (void **)&binding->font);
	if (EFI_ERROR(status))
		goto fail;
	status = binding->ops->install(binding->context, controller, &text_guid, &binding->text);
	if (EFI_ERROR(status))
		goto fail;
	binding->text_installed = TRUE;
	return EFI_SUCCESS;
fail:
	(void)rollback(binding);
	return status;
}

EFI_STATUS cdk2_graphics_binding_stop(struct cdk2_graphics_console_binding *binding)
{
	if (binding == NULL || !binding->text_installed)
		return EFI_NOT_STARTED;
	{
		EFI_STATUS status = rollback(binding);

		if (EFI_ERROR(status))
			return status;
	}
	binding->controller = NULL;
	binding->gop = NULL;
	binding->font = NULL;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_graphics_gop_blt(struct cdk2_graphics_console_binding *binding,
	void *buffer, UINTN operation, UINTN source_x, UINTN source_y,
	UINTN destination_x, UINTN destination_y, UINTN width, UINTN height, UINTN delta)
{
	if (binding == NULL || binding->gop == NULL || binding->gop->blt == NULL)
		return EFI_NOT_READY;
	return binding->gop->blt(binding->gop, buffer, operation, source_x, source_y,
		destination_x, destination_y, width, height, delta);
}

EFI_STATUS cdk2_graphics_render_string(struct cdk2_graphics_console_binding *binding,
	const CHAR16 *string, const struct cdk2_font_display_info *display,
	struct cdk2_image_output **image, UINTN x, UINTN y, UINTN width, UINTN height)
{
	struct cdk2_image_output direct;
	EFI_STATUS status;
	UINT32 flags;

	if (binding == NULL || binding->font == NULL ||
	    binding->font->string_to_image == NULL || binding->gop == NULL ||
	    binding->gop->mode == NULL || binding->gop->mode->info == NULL ||
	    string == NULL || image == NULL || width == 0U || height == 0U ||
	    binding->gop->mode->info->horizontal_resolution > 0xffffU ||
	    binding->gop->mode->info->vertical_resolution > 0xffffU)
		return EFI_INVALID_PARAMETER;
	direct.width = (UINT16)binding->gop->mode->info->horizontal_resolution;
	direct.height = (UINT16)binding->gop->mode->info->vertical_resolution;
	direct.image.screen = binding->gop;
	*image = &direct;
	flags = CDK2_HII_IGNORE_IF_NO_GLYPH | CDK2_HII_IGNORE_LINE_BREAK |
		CDK2_HII_DIRECT_TO_SCREEN;
	status = binding->font->string_to_image(binding->font, flags, string, display,
		image, x, y, NULL, NULL, NULL);
	*image = NULL;
	return status;
}

EFI_STATUS cdk2_graphics_binding_publish(struct cdk2_graphics_console_binding *binding,
	void *image, cdk2_binding_publish_fn publish, cdk2_binding_publish_fn unpublish,
	cdk2_binding_notify_fn notify, void *context)
{
	EFI_STATUS status;

	if (binding == NULL || image == NULL || publish == NULL || unpublish == NULL ||
	    notify == NULL)
		return EFI_INVALID_PARAMETER;
	status = notify(context, &hii_database_guid);
	if (EFI_ERROR(status))
		return status;
	binding->driver = (struct cdk2_driver_binding_view) {
		.supported = driver_supported,
		.start = driver_start,
		.stop = driver_stop,
		.version = 0x10U,
		.image_handle = image,
		.driver_binding_handle = image,
	};
	binding->component_name = (struct cdk2_component_name_view) {
		.get_driver_name = get_driver_name,
		.get_controller_name = get_controller_name,
		.supported_languages = "eng",
	};
	binding->component_name2 = (struct cdk2_component_name_view) {
		.get_driver_name = get_driver_name2,
		.get_controller_name = get_controller_name,
		.supported_languages = "en",
	};
	status = publish(context, image, &driver_binding_guid, &binding->driver);
	if (EFI_ERROR(status))
		return status;
	status = publish(context, image, &component_name_guid, &binding->component_name);
	if (EFI_ERROR(status)) {
		(void)unpublish(context, image, &driver_binding_guid, &binding->driver);
		return status;
	}
	status = publish(context, image, &component_name2_guid, &binding->component_name2);
	if (EFI_ERROR(status)) {
		(void)unpublish(context, image, &component_name_guid,
			&binding->component_name);
		(void)unpublish(context, image, &driver_binding_guid, &binding->driver);
	}
	return status;
}
