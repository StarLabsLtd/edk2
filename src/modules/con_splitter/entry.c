/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_splitter_entry.h>
#include <cdk2/con_splitter_binding.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINTN, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *,
	void *);
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN, event_notify_fn *,
	void *, void **);
typedef EFI_STATUS CDK2_MS_ABI event_fn(void *);
struct boot_services_view {
	UINT8 header[24];
	void *raise_tpl, *restore_tpl, *allocate_pages, *free_pages, *get_memory_map;
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	create_event_fn *create_event;
	void *set_timer, *wait_for_event;
	event_fn *signal_event;
	event_fn *close_event;
	event_fn *check_event;
	void *slots_before_open[19];
	open_protocol_fn *open_protocol;
	close_protocol_fn *close_protocol;
	void *slots_after_close[4];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct cdk2_split_system_table {
	UINT8 header[24];
	CHAR16 *firmware_vendor;
	UINT32 firmware_revision, padding;
	void *console_in_handle;
	struct cdk2_split_text_in_protocol *con_in;
	void *console_out_handle;
	struct cdk2_split_text_out_protocol *con_out;
	void *standard_error_handle;
	struct cdk2_split_text_out_protocol *standard_error;
	void *runtime;
	struct boot_services_view *boot;
};
enum binding_kind { BIND_INPUT, BIND_POINTER, BIND_ABSOLUTE, BIND_OUTPUT, BIND_ERROR };
struct binding_context {
	struct splitter_entry *owner;
	enum binding_kind kind;
};
struct wait_context {
	struct splitter_entry *owner;
	enum binding_kind kind;
	void *event;
};
struct input_ex_attachment {
	void *controller;
	struct cdk2_split_text_in_ex_protocol *protocol;
	BOOLEAN active;
};
struct gop_attachment {
	void *controller;
	struct cdk2_split_gop_protocol *protocol;
	struct splitter_entry *owner;
	BOOLEAN active;
};
struct splitter_entry {
	struct cdk2_split_text_in input_model;
	struct cdk2_split_pointer pointer_model;
	struct cdk2_split_absolute absolute_model;
	struct cdk2_split_gop gop_model;
	struct cdk2_split_text_out output_model, error_model;
	struct cdk2_split_text_in_protocol input;
	struct cdk2_split_text_in_ex_protocol input_ex;
	struct cdk2_split_text_out_protocol output, error;
	struct cdk2_split_pointer_protocol pointer;
	struct cdk2_split_absolute_protocol absolute;
	struct cdk2_split_gop_protocol gop;
	struct cdk2_split_pointer_mode pointer_mode;
	struct cdk2_split_absolute_mode absolute_mode;
	struct cdk2_split_gop_protocol_mode gop_mode;
	struct cdk2_split_text_out_mode output_mode, error_mode;
	struct boot_services_view *boot;
	void *input_handle, *input_ex_handle, *output_handle, *error_handle;
	void *pointer_handle, *absolute_handle;
	void *gop_handle;
	void *image;
	struct cdk2_split_binding bindings[5];
	struct binding_context binding_contexts[5];
	struct cdk2_split_publication publications[5];
	struct wait_context waits[4];
	struct input_ex_attachment input_ex_devices[CDK2_CON_SPLITTER_MAX_INPUTS];
	void *input_ex_notify_handles[CDK2_CON_SPLITTER_MAX_KEY_NOTIFIES]
		[CDK2_CON_SPLITTER_MAX_INPUTS];
	struct gop_attachment gop_devices[CDK2_CON_SPLITTER_MAX_GOPS];
};
static struct splitter_entry entry;
static const EFI_GUID text_in_guid = { 0x387477c1, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID text_out_guid = { 0x387477c2, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID text_in_ex_guid = { 0xdd9e7534, 0x7762, 0x4698,
	{ 0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa } };
static const EFI_GUID pointer_guid = { 0x31878c87, 0x0b75, 0x11d5,
	{ 0x9a, 0x4f, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID absolute_guid = { 0x8d59d32b, 0xc655, 0x4ae9,
	{ 0x9b, 0x15, 0xf2, 0x59, 0x04, 0x99, 0x2a, 0x43 } };
static const EFI_GUID gop_guid = { 0x9042a9de, 0x23dc, 0x4a38,
	{ 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } };
static const EFI_GUID driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };

EFI_STATUS cdk2_split_wait_poll(void *virtual_event, void **physical_events,
	UINTN count, cdk2_split_event_fn *check_event,
	cdk2_split_event_fn *signal_event)
{
	UINTN index;

	if (virtual_event == NULL || physical_events == NULL || check_event == NULL ||
	    signal_event == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < count; index++)
		if (physical_events[index] != NULL &&
		    check_event(physical_events[index]) == EFI_SUCCESS)
			return signal_event(virtual_event);
	return EFI_NOT_READY;
}

static void CDK2_MS_ABI wait_notify(void *event, void *context)
{
	struct wait_context *wait = context;
	UINTN index, count = 0U;
	void *physical[CDK2_CON_SPLITTER_MAX_INPUTS] = { 0 };

	if (wait == NULL || wait->owner == NULL || event != wait->event)
		return;
	switch (wait->kind) {
	case BIND_INPUT:
		count = wait->owner->input_model.device_count;
		break;
	case BIND_POINTER:
		count = wait->owner->pointer_model.device_count;
		break;
	case BIND_ABSOLUTE:
		count = wait->owner->absolute_model.device_count;
		break;
	default:
		return;
	}
	for (index = 0; index < count; index++) {
		if (wait->kind == BIND_INPUT)
			physical[index] = wait->owner->input_model.devices[index].wait_event;
		else if (wait->kind == BIND_POINTER)
			physical[index] = wait->owner->pointer_model.devices[index].wait_event;
		else
			physical[index] = wait->owner->absolute_model.devices[index].wait_event;
	}
	(void)cdk2_split_wait_poll(event, physical, count,
		wait->owner->boot->check_event, wait->owner->boot->signal_event);
}

static EFI_STATUS prepare_wait_events(struct splitter_entry *owner)
{
	static const enum binding_kind kinds[4] = {
		BIND_INPUT, BIND_INPUT, BIND_POINTER, BIND_ABSOLUTE
	};
	EFI_STATUS status;
	UINTN index;

	if (owner->boot->create_event == NULL || owner->boot->signal_event == NULL ||
	    owner->boot->close_event == NULL || owner->boot->check_event == NULL)
		return EFI_UNSUPPORTED;
	for (index = 0; index < 4U; index++) {
		owner->waits[index] = (struct wait_context) { owner, kinds[index], NULL };
		status = owner->boot->create_event(0x100U, 16U, wait_notify,
			&owner->waits[index], &owner->waits[index].event);
		if (EFI_ERROR(status)) {
			while (index != 0U)
				(void)owner->boot->close_event(owner->waits[--index].event);
			return status;
		}
	}
	return EFI_SUCCESS;
}

static void close_wait_events(struct splitter_entry *owner)
{
	UINTN index;

	for (index = 0; index < 4U; index++)
		if (owner->waits[index].event != NULL)
			(void)owner->boot->close_event(owner->waits[index].event);
}

static struct cdk2_split_text_out *output_model(
	struct cdk2_split_text_out_protocol *protocol)
{
	return protocol == &entry.output ? &entry.output_model : &entry.error_model;
}

static struct cdk2_split_text_out_mode *output_mode(
	struct cdk2_split_text_out_protocol *protocol)
{
	return protocol == &entry.output ? &entry.output_mode : &entry.error_mode;
}

static void sync_mode(struct cdk2_split_text_out_protocol *protocol)
{
	struct cdk2_split_text_out *model = output_model(protocol);
	struct cdk2_split_text_out_mode *mode = output_mode(protocol);

	mode->max_mode = (INT32)model->mode_count;
	mode->mode = (INT32)model->mode;
	mode->attribute = (INT32)model->attribute;
	mode->cursor_column = (INT32)model->column;
	mode->cursor_row = (INT32)model->row;
	mode->cursor_visible = model->cursor_visible;
}

static EFI_STATUS CDK2_MS_ABI text_reset(struct cdk2_split_text_out_protocol *protocol,
	BOOLEAN extended)
{
	EFI_STATUS status;
	(void)extended;
	status = cdk2_split_text_out_set_attribute(output_model(protocol), 7U);
	if (!EFI_ERROR(status))
		status = cdk2_split_text_out_clear(output_model(protocol));
	sync_mode(protocol);
	return status;
}
static EFI_STATUS CDK2_MS_ABI text_output(struct cdk2_split_text_out_protocol *protocol,
	CHAR16 *string)
{ EFI_STATUS status = cdk2_split_text_out_output(output_model(protocol), string); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_test(struct cdk2_split_text_out_protocol *protocol,
	CHAR16 *string)
{ return cdk2_split_text_out_test(output_model(protocol), string); }
static EFI_STATUS CDK2_MS_ABI text_query(struct cdk2_split_text_out_protocol *protocol,
	UINTN mode, UINTN *columns,
	UINTN *rows)
{ return cdk2_split_text_out_query_mode(output_model(protocol), mode, columns, rows); }
static EFI_STATUS CDK2_MS_ABI text_set_mode(struct cdk2_split_text_out_protocol *protocol,
	UINTN mode)
{ EFI_STATUS status = cdk2_split_text_out_set_mode(output_model(protocol), mode); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_attribute(struct cdk2_split_text_out_protocol *protocol,
	UINTN attribute)
{ EFI_STATUS status = cdk2_split_text_out_set_attribute(output_model(protocol), attribute); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_clear(struct cdk2_split_text_out_protocol *protocol)
{ EFI_STATUS status = cdk2_split_text_out_clear(output_model(protocol)); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_cursor(struct cdk2_split_text_out_protocol *protocol,
	UINTN column, UINTN row)
{ EFI_STATUS status = cdk2_split_text_out_set_cursor(output_model(protocol), column, row); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_visible(struct cdk2_split_text_out_protocol *protocol,
	BOOLEAN visible)
{ EFI_STATUS status = cdk2_split_text_out_enable_cursor(output_model(protocol), visible); sync_mode(protocol); return status; }

static EFI_STATUS CDK2_MS_ABI input_reset(struct cdk2_split_text_in_protocol *protocol,
	BOOLEAN extended)
{ (void)protocol; return cdk2_split_text_in_reset(&entry.input_model, extended); }
static EFI_STATUS CDK2_MS_ABI input_read(struct cdk2_split_text_in_protocol *protocol,
	struct cdk2_split_input_key *key)
{
	(void)protocol;
	return cdk2_split_text_in_read(&entry.input_model, (struct cdk2_split_key *)key);
}

static EFI_STATUS CDK2_MS_ABI input_ex_reset(
	struct cdk2_split_text_in_ex_protocol *protocol, BOOLEAN extended)
{
	(void)protocol;
	return cdk2_split_text_in_reset(&entry.input_model, extended);
}

static EFI_STATUS CDK2_MS_ABI input_ex_read(
	struct cdk2_split_text_in_ex_protocol *protocol,
	struct cdk2_split_key_data *key)
{
	EFI_STATUS status = EFI_NOT_READY;
	UINTN index;

	(void)protocol;
	for (index = 0; index < CDK2_CON_SPLITTER_MAX_INPUTS; index++) {
		if (!entry.input_ex_devices[index].active)
			continue;
		status = entry.input_ex_devices[index].protocol->read(
			entry.input_ex_devices[index].protocol, key);
		if (!EFI_ERROR(status))
			return cdk2_split_text_in_deliver(&entry.input_model, key);
	}
	return cdk2_split_text_in_read_ex(&entry.input_model, key);
}

static EFI_STATUS CDK2_MS_ABI input_ex_set_state(
	struct cdk2_split_text_in_ex_protocol *protocol,
	UINT8 *toggle)
{
	EFI_STATUS result = EFI_SUCCESS, status;
	UINTN index;

	(void)protocol;
	for (index = 0; index < CDK2_CON_SPLITTER_MAX_INPUTS; index++) {
		if (!entry.input_ex_devices[index].active)
			continue;
		status = entry.input_ex_devices[index].protocol->set_state(
			entry.input_ex_devices[index].protocol, toggle);
		if (EFI_ERROR(status))
			result = status;
	}
	if (!EFI_ERROR(result))
		result = cdk2_split_text_in_set_state(&entry.input_model, toggle);
	return result;
}

static EFI_STATUS CDK2_MS_ABI input_ex_register(
	struct cdk2_split_text_in_ex_protocol *protocol,
	struct cdk2_split_key_data *key,
	cdk2_split_key_notify_fn *callback,
	void **handle)
{
	EFI_STATUS status;
	UINTN device, notify_index;
	BOOLEAN existing = FALSE;

	(void)protocol;
	for (notify_index = 0; notify_index < entry.input_model.notify_count;
	     notify_index++)
		if (entry.input_model.notifies[notify_index].active &&
		    entry.input_model.notifies[notify_index].callback == callback &&
		    entry.input_model.notifies[notify_index].match.key.scan_code ==
			key->key.scan_code &&
		    entry.input_model.notifies[notify_index].match.key.unicode ==
			key->key.unicode &&
		    entry.input_model.notifies[notify_index].match.state.shift_state ==
			key->state.shift_state &&
		    entry.input_model.notifies[notify_index].match.state.toggle_state ==
			key->state.toggle_state)
			existing = TRUE;
	status = cdk2_split_text_in_register_notify(&entry.input_model, key, callback,
		handle);
	if (EFI_ERROR(status))
		return status;
	notify_index = (UINTN)((struct cdk2_split_key_notify *)*handle -
		entry.input_model.notifies);
	for (device = 0; device < CDK2_CON_SPLITTER_MAX_INPUTS; device++) {
		if (!entry.input_ex_devices[device].active ||
		    entry.input_ex_notify_handles[notify_index][device] != NULL)
			continue;
		status = entry.input_ex_devices[device].protocol->register_notify(
			entry.input_ex_devices[device].protocol, key, callback,
			&entry.input_ex_notify_handles[notify_index][device]);
		if (EFI_ERROR(status)) {
			while (device != 0U) {
				device--;
				if (entry.input_ex_notify_handles[notify_index][device] != NULL) {
					(void)entry.input_ex_devices[device].protocol->unregister_notify(
						entry.input_ex_devices[device].protocol,
						entry.input_ex_notify_handles[notify_index][device]);
					entry.input_ex_notify_handles[notify_index][device] = NULL;
				}
			}
			if (!existing)
				(void)cdk2_split_text_in_unregister_notify(&entry.input_model,
					*handle);
			return status;
		}
	}
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI input_ex_unregister(
	struct cdk2_split_text_in_ex_protocol *protocol, void *handle)
{
	struct cdk2_split_key_notify *notification = handle;
	UINTN device, notify_index;
	EFI_STATUS status;

	(void)protocol;
	if (notification < entry.input_model.notifies ||
	    notification >= entry.input_model.notifies +
		CDK2_CON_SPLITTER_MAX_KEY_NOTIFIES || !notification->active)
		return EFI_INVALID_PARAMETER;
	notify_index = (UINTN)(notification - entry.input_model.notifies);
	for (device = 0; device < CDK2_CON_SPLITTER_MAX_INPUTS; device++) {
		if (!entry.input_ex_devices[device].active ||
		    entry.input_ex_notify_handles[notify_index][device] == NULL)
			continue;
		status = entry.input_ex_devices[device].protocol->unregister_notify(
			entry.input_ex_devices[device].protocol,
			entry.input_ex_notify_handles[notify_index][device]);
		if (EFI_ERROR(status))
			return status;
		entry.input_ex_notify_handles[notify_index][device] = NULL;
	}
	return cdk2_split_text_in_unregister_notify(&entry.input_model, handle);
}

static EFI_STATUS CDK2_MS_ABI pointer_reset(
	struct cdk2_split_pointer_protocol *protocol, BOOLEAN extended)
{
	(void)protocol;
	(void)extended;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI pointer_get_state(
	struct cdk2_split_pointer_protocol *protocol,
	struct cdk2_split_pointer_state *state)
{
	(void)protocol;
	return cdk2_split_pointer_get_state(&entry.pointer_model, state);
}

static EFI_STATUS CDK2_MS_ABI absolute_reset(
	struct cdk2_split_absolute_protocol *protocol, BOOLEAN extended)
{
	(void)protocol;
	(void)extended;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI absolute_get_state(
	struct cdk2_split_absolute_protocol *protocol,
	struct cdk2_split_absolute_state *state)
{
	(void)protocol;
	return cdk2_split_absolute_get_state(&entry.absolute_model, state);
}

static EFI_STATUS CDK2_MS_ABI gop_query(
	struct cdk2_split_gop_protocol *protocol, UINT32 mode,
	UINTN *size,
	struct cdk2_split_gop_mode_info **information)
{
	struct cdk2_split_gop_mode split_mode;
	EFI_STATUS status;

	(void)protocol;
	if (size == NULL || information == NULL || entry.boot->allocate_pool == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_split_gop_query_mode(&entry.gop_model, mode, &split_mode);
	if (EFI_ERROR(status))
		return status;
	status = entry.boot->allocate_pool(4U, sizeof(**information),
		(void **)information);
	if (EFI_ERROR(status))
		return status;
	**information = (struct cdk2_split_gop_mode_info) {
		.horizontal_resolution = split_mode.width,
		.vertical_resolution = split_mode.height,
		.pixel_format = split_mode.pixel_format,
		.pixels_per_scan_line = split_mode.pixels_per_scan_line
	};
	*size = sizeof(**information);
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI gop_set(struct cdk2_split_gop_protocol *protocol,
	UINT32 mode)
{
	EFI_STATUS status;

	(void)protocol;
	status = cdk2_split_gop_set_mode(&entry.gop_model, mode);
	if (!EFI_ERROR(status))
		entry.gop_mode.mode = mode;
	return status;
}

static EFI_STATUS CDK2_MS_ABI gop_blt(struct cdk2_split_gop_protocol *protocol,
	void *buffer, UINTN operation, UINTN source_x, UINTN source_y,
	UINTN destination_x, UINTN destination_y, UINTN width, UINTN height,
	UINTN delta)
{
	(void)protocol;
	return cdk2_split_gop_blt(&entry.gop_model, buffer, operation, source_x,
		source_y, destination_x, destination_y, width, height, delta);
}

static EFI_STATUS physical_output(void *context, const CHAR16 *string)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->output(text, (CHAR16 *)string);
}
static EFI_STATUS physical_test(void *context, const CHAR16 *string)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->test(text, (CHAR16 *)string);
}
static EFI_STATUS physical_query(void *context, UINTN mode, UINTN *columns,
	UINTN *rows)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->query(text, mode, columns, rows);
}
static EFI_STATUS physical_value_mode(void *context, UINTN value)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->set_mode(text, value);
}
static EFI_STATUS physical_value_attribute(void *context, UINTN value)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->set_attribute(text, value);
}
static EFI_STATUS physical_clear(void *context)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->clear(text);
}
static EFI_STATUS physical_cursor(void *context, UINTN column, UINTN row)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->set_cursor(text, column, row);
}
static EFI_STATUS physical_visible(void *context, BOOLEAN visible)
{
	struct cdk2_split_text_out_protocol *text = context;
	return text->enable_cursor(text, visible);
}
static const struct cdk2_split_text_out_ops physical_output_ops = {
	physical_output, physical_test, physical_query, physical_value_mode,
	physical_value_attribute, physical_clear, physical_cursor, physical_visible
};
static EFI_STATUS physical_gop_query(void *context, UINT32 mode,
	struct cdk2_split_gop_mode *information)
{
	struct gop_attachment *attachment = context;
	struct cdk2_split_gop_mode_info *physical = NULL;
	UINTN size;
	EFI_STATUS status;

	status = attachment->protocol->query_mode(attachment->protocol, mode, &size,
		&physical);
	if (EFI_ERROR(status))
		return status;
	if (physical == NULL || size < sizeof(*physical)) {
		if (physical != NULL)
			(void)attachment->owner->boot->free_pool(physical);
		return EFI_DEVICE_ERROR;
	}
	*information = (struct cdk2_split_gop_mode) {
		.width = physical->horizontal_resolution,
		.height = physical->vertical_resolution,
		.pixel_format = physical->pixel_format,
		.pixels_per_scan_line = physical->pixels_per_scan_line
	};
	return attachment->owner->boot->free_pool(physical);
}
static EFI_STATUS physical_gop_set(void *context, UINT32 mode)
{
	struct gop_attachment *attachment = context;
	return attachment->protocol->set_mode(attachment->protocol, mode);
}
static EFI_STATUS physical_gop_blt(void *context, void *buffer, UINTN operation,
	UINTN source_x, UINTN source_y, UINTN destination_x,
	UINTN destination_y, UINTN width, UINTN height, UINTN delta)
{
	struct gop_attachment *attachment = context;
	return attachment->protocol->blt(attachment->protocol, buffer, operation,
		source_x, source_y, destination_x, destination_y, width, height, delta);
}
static EFI_STATUS physical_input_read(void *context, struct cdk2_split_key *key)
{
	struct cdk2_split_text_in_protocol *input = context;
	return input->read(input, (struct cdk2_split_input_key *)key);
}
static EFI_STATUS physical_input_reset(void *context, BOOLEAN extended)
{
	struct cdk2_split_text_in_protocol *input = context;
	return input->reset(input, extended);
}
static EFI_STATUS physical_pointer_reset(void *context, BOOLEAN extended)
{
	struct cdk2_split_pointer_protocol *pointer = context;
	return pointer->reset(pointer, extended);
}
static EFI_STATUS physical_pointer_state(void *context,
	struct cdk2_split_pointer_state *state)
{
	struct cdk2_split_pointer_protocol *pointer = context;
	return pointer->get_state(pointer, state);
}
static EFI_STATUS physical_absolute_reset(void *context, BOOLEAN extended)
{
	struct cdk2_split_absolute_protocol *absolute = context;
	return absolute->reset(absolute, extended);
}
static EFI_STATUS physical_absolute_state(void *context,
	struct cdk2_split_absolute_state *state)
{
	struct cdk2_split_absolute_protocol *absolute = context;
	return absolute->get_state(absolute, state);
}

static EFI_STATUS binding_open(void *context, void *controller,
	const EFI_GUID *protocol, UINT32 attributes, void **interface)
{
	struct binding_context *binding = context;
	return binding->owner->boot->open_protocol(controller, protocol, interface,
		binding->owner->image, controller, attributes);
}
static EFI_STATUS binding_close(void *context, void *controller,
	const EFI_GUID *protocol)
{
	struct binding_context *binding = context;
	return binding->owner->boot->close_protocol(controller, protocol,
		binding->owner->image, controller);
}
static EFI_STATUS binding_admit(void *context, void *controller, void *interface)
{
	struct binding_context *binding = context;
	struct splitter_entry *owner = binding->owner;
	EFI_STATUS status;
	UINTN index, notify;

	switch (binding->kind) {
	case BIND_INPUT: {
		struct cdk2_split_text_in_protocol *input = interface;
		struct input_ex_attachment *attachment = NULL;
		void *physical_ex = NULL;

		status = cdk2_split_text_in_add_event(&owner->input_model,
			physical_input_read, physical_input_reset, interface,
			input->wait_for_key);
		if (EFI_ERROR(status))
			return status;
		status = owner->boot->open_protocol(controller, &text_in_ex_guid,
			&physical_ex, owner->image, controller,
			CDK2_CON_SPLITTER_OPEN_BY_DRIVER);
		if (status == EFI_NOT_FOUND || status == EFI_UNSUPPORTED)
			return EFI_SUCCESS;
		if (EFI_ERROR(status))
			goto rollback_simple_input;
		for (index = 0; index < CDK2_CON_SPLITTER_MAX_INPUTS; index++)
			if (!owner->input_ex_devices[index].active) {
				attachment = &owner->input_ex_devices[index];
				break;
			}
		if (attachment == NULL) {
			status = EFI_OUT_OF_RESOURCES;
			goto rollback_ex_open;
		}
		*attachment = (struct input_ex_attachment) {
			controller, physical_ex, TRUE
		};
		for (notify = 0; notify < owner->input_model.notify_count; notify++) {
			if (!owner->input_model.notifies[notify].active)
				continue;
			status = attachment->protocol->register_notify(attachment->protocol,
				&owner->input_model.notifies[notify].match,
				owner->input_model.notifies[notify].callback,
				&owner->input_ex_notify_handles[notify][index]);
			if (EFI_ERROR(status))
				goto rollback_ex_notifies;
		}
		return EFI_SUCCESS;

rollback_ex_notifies:
		while (notify != 0U) {
			notify--;
			if (owner->input_ex_notify_handles[notify][index] != NULL) {
				(void)attachment->protocol->unregister_notify(
					attachment->protocol,
					owner->input_ex_notify_handles[notify][index]);
				owner->input_ex_notify_handles[notify][index] = NULL;
			}
		}
		*attachment = (struct input_ex_attachment) { 0 };
rollback_ex_open:
		(void)owner->boot->close_protocol(controller, &text_in_ex_guid,
			owner->image, controller);
rollback_simple_input:
		(void)cdk2_split_text_in_remove(&owner->input_model, interface);
		return status;
	}
	case BIND_POINTER: {
		struct cdk2_split_pointer_protocol *pointer = interface;
		struct cdk2_split_pointer_device device = {
			physical_pointer_reset, physical_pointer_state, interface,
			pointer->wait_for_input, pointer->mode->resolution_x,
			pointer->mode->resolution_y, pointer->mode->resolution_z
		};
		return cdk2_split_pointer_add(&owner->pointer_model, &device);
	}
	case BIND_ABSOLUTE: {
		struct cdk2_split_absolute_protocol *absolute = interface;
		struct cdk2_split_absolute_device device = {
			physical_absolute_reset, physical_absolute_state, interface,
			absolute->wait_for_input, absolute->mode->min_x,
			absolute->mode->min_y, absolute->mode->min_z,
			absolute->mode->max_x, absolute->mode->max_y,
			absolute->mode->max_z
		};
		return cdk2_split_absolute_add(&owner->absolute_model, &device);
	}
	case BIND_OUTPUT:
		status = cdk2_split_text_out_add(&owner->output_model,
			&physical_output_ops, interface,
			(UINTN)((struct cdk2_split_text_out_protocol *)interface)->mode->max_mode);
		if (EFI_ERROR(status))
			return status;
		{
			struct gop_attachment *attachment = NULL;
			struct cdk2_split_gop_device device;
			void *physical_gop = NULL;

			status = owner->boot->open_protocol(controller, &gop_guid,
				&physical_gop, owner->image, controller,
				CDK2_CON_SPLITTER_OPEN_BY_DRIVER);
			if (status == EFI_NOT_FOUND || status == EFI_UNSUPPORTED)
				return EFI_SUCCESS;
			if (EFI_ERROR(status))
				goto rollback_text_output;
			for (index = 0; index < CDK2_CON_SPLITTER_MAX_GOPS; index++)
				if (!owner->gop_devices[index].active) {
					attachment = &owner->gop_devices[index];
					break;
				}
			if (attachment == NULL) {
				status = EFI_OUT_OF_RESOURCES;
				goto rollback_gop_open;
			}
			*attachment = (struct gop_attachment) {
				controller, physical_gop, owner, TRUE
			};
			device = (struct cdk2_split_gop_device) {
				physical_gop_query, physical_gop_set, physical_gop_blt,
				attachment, attachment->protocol->mode->max_mode
			};
			status = cdk2_split_gop_add(&owner->gop_model, &device);
			if (EFI_ERROR(status)) {
				*attachment = (struct gop_attachment) { 0 };
				goto rollback_gop_open;
			}
			owner->gop_mode.max_mode = (UINT32)owner->gop_model.mode_count;
			return EFI_SUCCESS;

rollback_gop_open:
			(void)owner->boot->close_protocol(controller, &gop_guid,
				owner->image, controller);
rollback_text_output:
			(void)cdk2_split_text_out_remove(&owner->output_model, interface);
			return status;
		}
	case BIND_ERROR:
		return cdk2_split_text_out_add(&owner->error_model,
			&physical_output_ops, interface,
			(UINTN)((struct cdk2_split_text_out_protocol *)interface)->mode->max_mode);
	}
	return EFI_UNSUPPORTED;
}
static EFI_STATUS binding_remove(void *context, void *controller, void *interface)
{
	struct binding_context *binding = context;
	struct splitter_entry *owner = binding->owner;
	EFI_STATUS status;
	UINTN index, notify;

	switch (binding->kind) {
	case BIND_INPUT:
		for (index = 0; index < CDK2_CON_SPLITTER_MAX_INPUTS; index++) {
			struct input_ex_attachment *attachment =
				&owner->input_ex_devices[index];
			if (!attachment->active || attachment->controller != controller)
				continue;
			for (notify = 0; notify < owner->input_model.notify_count; notify++) {
				if (owner->input_ex_notify_handles[notify][index] != NULL) {
					status = attachment->protocol->unregister_notify(
						attachment->protocol,
						owner->input_ex_notify_handles[notify][index]);
					if (EFI_ERROR(status))
						return status;
					owner->input_ex_notify_handles[notify][index] = NULL;
				}
			}
			status = owner->boot->close_protocol(controller, &text_in_ex_guid,
				owner->image, controller);
			if (EFI_ERROR(status)) {
				for (notify = 0; notify < owner->input_model.notify_count;
				     notify++)
					if (owner->input_model.notifies[notify].active)
						(void)attachment->protocol->register_notify(
							attachment->protocol,
							&owner->input_model.notifies[notify].match,
							owner->input_model.notifies[notify].callback,
							&owner->input_ex_notify_handles[notify][index]);
				return status;
			}
			*attachment = (struct input_ex_attachment) { 0 };
			break;
		}
		return cdk2_split_text_in_remove(&owner->input_model, interface);
	case BIND_POINTER:
		return cdk2_split_pointer_remove(&owner->pointer_model, interface);
	case BIND_ABSOLUTE:
		return cdk2_split_absolute_remove(&owner->absolute_model, interface);
	case BIND_OUTPUT:
		for (index = 0; index < CDK2_CON_SPLITTER_MAX_GOPS; index++) {
			struct gop_attachment *attachment = &owner->gop_devices[index];
			struct cdk2_split_gop_device device;
			if (!attachment->active || attachment->controller != controller)
				continue;
			status = cdk2_split_gop_remove(&owner->gop_model, attachment);
			if (EFI_ERROR(status))
				return status;
			status = owner->boot->close_protocol(controller, &gop_guid,
				owner->image, controller);
			if (EFI_ERROR(status)) {
				device = (struct cdk2_split_gop_device) {
					physical_gop_query, physical_gop_set,
					physical_gop_blt, attachment,
					attachment->protocol->mode->max_mode
				};
				(void)cdk2_split_gop_add(&owner->gop_model, &device);
				return status;
			}
			*attachment = (struct gop_attachment) { 0 };
			owner->gop_mode.max_mode = (UINT32)owner->gop_model.mode_count;
			break;
		}
		return cdk2_split_text_out_remove(&owner->output_model, interface);
	case BIND_ERROR:
		return cdk2_split_text_out_remove(&owner->error_model, interface);
	}
	return EFI_UNSUPPORTED;
}
static const struct cdk2_split_binding_ops binding_ops = {
	binding_open, binding_close, binding_admit, binding_remove
};

static EFI_STATUS publish_binding(void *context, void **handle, void *driver,
	void *component, void *component2)
{
	struct splitter_entry *owner = context;
	return owner->boot->install_multiple(handle, &driver_binding_guid, driver,
		&component_name_guid, component, &component_name2_guid, component2,
		NULL);
}
static EFI_STATUS unpublish_binding(void *context, void *handle, void *driver,
	void *component, void *component2)
{
	struct splitter_entry *owner = context;
	return owner->boot->uninstall_multiple(handle, &driver_binding_guid, driver,
		&component_name_guid, component, &component_name2_guid, component2,
		NULL);
}

static void prepare_output(struct cdk2_split_text_out_protocol *protocol,
	struct cdk2_split_text_out_mode *mode)
{
	*protocol = (struct cdk2_split_text_out_protocol) {
		text_reset, text_output, text_test, text_query, text_set_mode, text_attribute,
		text_clear, text_cursor, text_visible, mode
	};
}

EFI_STATUS CDK2_MS_ABI cdk2_con_splitter_entry(void *image,
	struct cdk2_split_system_table *system)
{
	EFI_STATUS status;

	if (image == NULL || system == NULL || system->boot == NULL ||
	    system->boot->install_multiple == NULL ||
	    system->boot->uninstall_multiple == NULL ||
	    system->boot->open_protocol == NULL ||
	    system->boot->close_protocol == NULL)
		return EFI_INVALID_PARAMETER;
	__builtin_memset(&entry, 0, sizeof(entry));
	entry.boot = system->boot;
	entry.image = image;
	(void)cdk2_split_text_out_init(&entry.output_model, 80U, 25U);
	(void)cdk2_split_text_out_init(&entry.error_model, 80U, 25U);
	entry.input = (struct cdk2_split_text_in_protocol) { input_reset, input_read, NULL };
	entry.input_ex = (struct cdk2_split_text_in_ex_protocol) {
		input_ex_reset, input_ex_read, NULL, input_ex_set_state,
		input_ex_register, input_ex_unregister
	};
	entry.pointer = (struct cdk2_split_pointer_protocol) {
		pointer_reset, pointer_get_state, NULL, &entry.pointer_mode
	};
	entry.absolute = (struct cdk2_split_absolute_protocol) {
		absolute_reset, absolute_get_state, NULL, &entry.absolute_mode
	};
	entry.gop = (struct cdk2_split_gop_protocol) {
		gop_query, gop_set, gop_blt, &entry.gop_mode
	};
	status = prepare_wait_events(&entry);
	if (EFI_ERROR(status))
		return status;
	entry.input.wait_for_key = entry.waits[0].event;
	entry.input_ex.wait_for_key_ex = entry.waits[1].event;
	entry.pointer.wait_for_input = entry.waits[2].event;
	entry.absolute.wait_for_input = entry.waits[3].event;
	for (UINTN index = 0; index < 5U; index++) {
		const EFI_GUID *protocol = index == BIND_INPUT ? &text_in_guid :
			index == BIND_POINTER ? &pointer_guid :
			index == BIND_ABSOLUTE ? &absolute_guid : &text_out_guid;
		entry.binding_contexts[index] = (struct binding_context) {
			&entry, (enum binding_kind)index
		};
		entry.bindings[index] = (struct cdk2_split_binding) {
			&binding_ops, &entry.binding_contexts[index], protocol, { { 0 } }
		};
		cdk2_split_publication_prepare(&entry.publications[index],
			&entry.bindings[index], image);
	}
	prepare_output(&entry.output, &entry.output_mode);
	prepare_output(&entry.error, &entry.error_mode);
	sync_mode(&entry.output);
	sync_mode(&entry.error);
	status = entry.boot->install_multiple(&entry.input_handle, &text_in_guid,
		&entry.input, NULL);
	if (EFI_ERROR(status))
		goto cleanup_events;
	status = entry.boot->install_multiple(&entry.output_handle, &text_out_guid,
		&entry.output, NULL);
	if (EFI_ERROR(status))
		goto rollback_input;
	status = entry.boot->install_multiple(&entry.input_ex_handle, &text_in_ex_guid,
		&entry.input_ex, NULL);
	if (EFI_ERROR(status))
		goto rollback_output;
	status = entry.boot->install_multiple(&entry.error_handle, &text_out_guid,
		&entry.error, NULL);
	if (EFI_ERROR(status))
		goto rollback_input_ex;
	status = entry.boot->install_multiple(&entry.pointer_handle, &pointer_guid,
		&entry.pointer, NULL);
	if (EFI_ERROR(status))
		goto rollback_error;
	status = entry.boot->install_multiple(&entry.absolute_handle, &absolute_guid,
		&entry.absolute, NULL);
	if (EFI_ERROR(status))
		goto rollback_pointer;
	status = entry.boot->install_multiple(&entry.gop_handle, &gop_guid,
		&entry.gop, NULL);
	if (EFI_ERROR(status))
		goto rollback_absolute;
	status = cdk2_split_publications_install(entry.publications, 5U,
		publish_binding, unpublish_binding, &entry);
	if (EFI_ERROR(status))
		goto rollback_gop;
	system->console_in_handle = entry.input_handle;
	system->con_in = &entry.input;
	system->console_out_handle = entry.output_handle;
	system->con_out = &entry.output;
	system->standard_error_handle = entry.error_handle;
	system->standard_error = &entry.error;
	return EFI_SUCCESS;

rollback_gop:
	(void)entry.boot->uninstall_multiple(entry.gop_handle, &gop_guid,
		&entry.gop, NULL);

rollback_absolute:
	(void)entry.boot->uninstall_multiple(entry.absolute_handle, &absolute_guid,
		&entry.absolute, NULL);

rollback_pointer:
	(void)entry.boot->uninstall_multiple(entry.pointer_handle, &pointer_guid,
		&entry.pointer, NULL);
rollback_error:
	(void)entry.boot->uninstall_multiple(entry.error_handle, &text_out_guid,
		&entry.error, NULL);
rollback_input_ex:
	(void)entry.boot->uninstall_multiple(entry.input_ex_handle, &text_in_ex_guid,
		&entry.input_ex, NULL);

rollback_output:
	(void)entry.boot->uninstall_multiple(entry.output_handle, &text_out_guid,
		&entry.output, NULL);
rollback_input:
	(void)entry.boot->uninstall_multiple(entry.input_handle, &text_in_guid,
		&entry.input, NULL);
cleanup_events:
	close_wait_events(&entry);
	return status;
}
