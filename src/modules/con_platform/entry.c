/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_platform_entry.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI get_variable_fn(CHAR16 *, const EFI_GUID *, UINT32 *,
	UINTN *, void *);
typedef EFI_STATUS CDK2_MS_ABI set_variable_fn(CHAR16 *, const EFI_GUID *, UINT32,
	UINTN, const void *);
typedef EFI_STATUS CDK2_MS_ABI locate_device_path_fn(const EFI_GUID *, void **, void **);
typedef EFI_STATUS CDK2_MS_ABI handle_protocol_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI locate_handle_buffer_fn(UINT32, const EFI_GUID *, void *,
	UINTN *, void ***);

struct runtime_services_view {
	UINT8 header[24];
	void *get_time, *set_time, *get_wakeup_time, *set_wakeup_time;
	void *set_virtual_address_map, *convert_pointer;
	get_variable_fn *get_variable;
	set_variable_fn *set_variable;
};

struct cdk2_con_boot_services {
	UINT8 header[24];
	void *raise_tpl, *restore_tpl, *allocate_pages, *free_pages, *get_memory_map;
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	void *create_event, *set_timer, *wait_for_event, *signal_event, *close_event,
		*check_event;
	void *install_protocol;
	void *reinstall_protocol;
	void *uninstall_protocol;
	handle_protocol_fn *handle_protocol;
	void *reserved;
	void *register_protocol_notify;
	void *locate_handle;
	locate_device_path_fn *locate_device_path;
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
	locate_handle_buffer_fn *locate_handle_buffer;
	void *locate_protocol;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};

struct con_entry_context {
	struct cdk2_con_boot_services *boot;
	struct runtime_services_view *runtime;
	void *image, *input_handle, *output_handle;
	struct cdk2_con_driver_binding input, output;
	struct cdk2_con_binding input_model, output_model;
	struct cdk2_con_component_name name, name2;
};

static struct con_entry_context entry;
static CHAR16 driver_name[] = {
	'C', 'D', 'K', '2', ' ', 'C', 'o', 'n', 's', 'o', 'l', 'e', 0
};
static const EFI_GUID driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const EFI_GUID global_variable_guid = { 0x8be4df61, 0x93ca, 0x11d2,
	{ 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c } };
static const EFI_GUID device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID gop_guid = { 0x9042a9de, 0x23dc, 0x4a38,
	{ 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } };

static UINTN path_size(const void *path)
{
	const struct cdk2_dp_node *node = path;
	UINTN total = 0U;

	if (path == NULL)
		return 0U;
	while (total < 65536U) {
		UINT16 length = node->length;

		if (length < sizeof(*node) || total + length > 65536U)
			return 0U;
		total += length;
		if (node->type == CDK2_DP_END && node->subtype == CDK2_DP_END_ENTIRE)
			return total;
		node = (const void *)((const UINT8 *)node + length);
	}
	return 0U;
}

static BOOLEAN bytes_equal(const void *left, const void *right, UINTN size)
{
	const UINT8 *a = left, *b = right;
	UINTN index;

	for (index = 0; index < size; index++)
		if (a[index] != b[index])
			return FALSE;
	return TRUE;
}

static struct cdk2_con_binding *model_from_driver(struct cdk2_con_driver_binding *driver)
{
	return driver == &entry.input ? &entry.input_model : &entry.output_model;
}

static EFI_STATUS CDK2_MS_ABI driver_supported(struct cdk2_con_driver_binding *driver,
	void *controller, void *remaining)
{
	(void)remaining;
	return cdk2_con_binding_supported(model_from_driver(driver), controller);
}

static EFI_STATUS CDK2_MS_ABI driver_start(struct cdk2_con_driver_binding *driver,
	void *controller, void *remaining)
{
	(void)remaining;
	return cdk2_con_binding_start(model_from_driver(driver), controller);
}

static EFI_STATUS CDK2_MS_ABI driver_stop(struct cdk2_con_driver_binding *driver,
	void *controller, UINTN children, void **child_buffer)
{
	struct cdk2_con_binding *model = model_from_driver(driver);

	(void)child_buffer;
	if (children != 0U || model->controller != controller)
		return EFI_INVALID_PARAMETER;
	return cdk2_con_binding_stop(model);
}

static EFI_STATUS open(void *context, void *controller, const EFI_GUID *protocol,
	UINT32 attributes, void **interface)
{
	struct con_entry_context *state = context;

	EFI_STATUS status = state->boot->open_protocol(controller, protocol, interface, state->image,
		controller, attributes);

	if (!EFI_ERROR(status) && attributes == CDK2_CON_OPEN_GET && interface != NULL) {
		UINTN size = path_size(*interface);

		if (size == 0U)
			return EFI_DEVICE_ERROR;
		state->input_model.path_size = size;
		state->output_model.path_size = size;
	}
	return status;
}

static EFI_STATUS close(void *context, void *controller, const EFI_GUID *protocol)
{
	struct con_entry_context *state = context;

	return state->boot->close_protocol(controller, protocol, state->image, controller);
}

static EFI_STATUS install_marker(void *context, void *controller, const EFI_GUID *protocol)
{
	struct con_entry_context *state = context;

	return state->boot->install_multiple(&controller, protocol, NULL, NULL);
}

static EFI_STATUS uninstall_marker(void *context, void *controller,
	const EFI_GUID *protocol)
{
	struct con_entry_context *state = context;

	return state->boot->uninstall_multiple(controller, protocol, NULL, NULL);
}

static EFI_STATUS variable_read(void *context, const CHAR16 *name, void **data, UINTN *size)
{
	struct con_entry_context *state = context;
	EFI_STATUS status;

	*data = NULL;
	*size = 0U;
	status = state->runtime->get_variable((CHAR16 *)name, &global_variable_guid,
		NULL, size, NULL);
	if (status != EFI_BUFFER_TOO_SMALL)
		return status;
	status = state->boot->allocate_pool(4U, *size, data);
	if (EFI_ERROR(status))
		return status;
	status = state->runtime->get_variable((CHAR16 *)name, &global_variable_guid,
		NULL, size, *data);
	if (EFI_ERROR(status)) {
		(void)state->boot->free_pool(*data);
		*data = NULL;
	}
	return status;
}

static EFI_STATUS variable_write(void *context, const CHAR16 *name, const void *data,
	UINTN size)
{
	struct con_entry_context *state = context;
	return state->runtime->set_variable((CHAR16 *)name, &global_variable_guid,
		6U, size, data);
}

static void release_pool(void *context, void *data)
{
	struct con_entry_context *state = context;
	(void)state->boot->free_pool(data);
}

static EFI_STATUS edit_path(void *context, const void *current, UINTN current_size,
	const void *path, UINTN size, enum cdk2_con_variable_operation operation,
	void **result, UINTN *result_size)
{
	struct con_entry_context *state = context;
	const UINT8 *source = current;
	UINT8 *copy, *destination;
	UINTN remaining = current_size, instance_size, kept = 0U;
	BOOLEAN found = FALSE;

	*result = NULL;
	*result_size = 0U;
	while (remaining != 0U) {
		const struct cdk2_dp_node *node = (const void *)source;
		instance_size = 0U;
		for (;;) {
			UINT16 length;
			if (remaining - instance_size < sizeof(*node))
				return EFI_INVALID_PARAMETER;
			length = node->length;
			if (length < sizeof(*node) || length > remaining - instance_size)
				return EFI_INVALID_PARAMETER;
			instance_size += length;
			if (node->type == CDK2_DP_END)
				break;
			node = (const void *)((const UINT8 *)node + length);
		}
		if (instance_size == size &&
		    (bytes_equal(source, path, size - sizeof(*node)) ||
		     cdk2_con_gop_siblings(source, instance_size, path, size)))
			found = TRUE;
		source += instance_size;
		remaining -= instance_size;
	}
	if (operation == CDK2_CON_CHECK)
		return found ? EFI_SUCCESS : EFI_NOT_FOUND;
	if (operation == CDK2_CON_APPEND && found)
		return CDK2_CON_ALREADY_STARTED;
	if (current_size > MAX_UINTN - size)
		return EFI_OUT_OF_RESOURCES;
	if (EFI_ERROR(state->boot->allocate_pool(4U, current_size + size, result)))
		return EFI_OUT_OF_RESOURCES;
	copy = *result;
	destination = copy;
	if (operation == CDK2_CON_DELETE) {
		source = current;
		remaining = current_size;
		while (remaining != 0U) {
			const struct cdk2_dp_node *node = (const void *)source;
			instance_size = 0U;
			for (;;) {
				instance_size += node->length;
				if (node->type == CDK2_DP_END)
					break;
				node = (const void *)((const UINT8 *)node + node->length);
			}
			if (!(instance_size == size &&
			    bytes_equal(source, path, size - sizeof(*node)))) {
				__builtin_memcpy(destination, source, instance_size);
				destination += instance_size;
				kept += instance_size;
			}
			source += instance_size;
			remaining -= instance_size;
		}
		if (kept != 0U)
			destination[-3] = CDK2_DP_END_ENTIRE;
		*result_size = kept;
		return EFI_SUCCESS;
	}
	if (current_size != 0U) {
		__builtin_memcpy(copy, current, current_size);
		copy[current_size - 3U] = CDK2_DP_END_INSTANCE;
	}
	__builtin_memcpy(copy + current_size, path, size);
	*result_size = current_size + size;
	return EFI_SUCCESS;
}

static EFI_STATUS update_variable(void *context, const CHAR16 *name,
	const void *path, UINTN size, enum cdk2_con_variable_operation operation)
{
	static const struct cdk2_con_variable_ops ops = {
		variable_read, variable_write, edit_path, release_pool
	};
	return cdk2_con_update_variable(&ops, context, name, path, size, operation);
}

static BOOLEAN update_gop_candidates(void *context, const void *path, UINTN size)
{
	struct con_entry_context *state = context;
	void *remaining = (void *)path, *gop_handle;
	void **handles = NULL;
	UINTN count = 0U, index;
	EFI_STATUS status;
	static const CHAR16 con_out_dev[] = {
		'C', 'o', 'n', 'O', 'u', 't', 'D', 'e', 'v', 0
	};
	static const CHAR16 err_out_dev[] = {
		'E', 'r', 'r', 'O', 'u', 't', 'D', 'e', 'v', 0
	};

	if (state->boot->locate_device_path == NULL || state->boot->handle_protocol == NULL ||
	    state->boot->locate_handle_buffer == NULL ||
	    EFI_ERROR(state->boot->locate_device_path(&gop_guid, &remaining, &gop_handle)))
		return FALSE;
	status = state->boot->locate_handle_buffer(2U, &gop_guid, NULL, &count, &handles);
	if (EFI_ERROR(status))
		return TRUE;
	for (index = 0; index < count; index++) {
		void *candidate;
		UINTN candidate_size;

		status = state->boot->handle_protocol(handles[index], &device_path_guid,
			&candidate);
		candidate_size = EFI_ERROR(status) ? 0U : path_size(candidate);
		if (candidate_size != 0U &&
		    (cdk2_con_gop_siblings(path, size, candidate, candidate_size) ||
		     (candidate_size == size && bytes_equal(path, candidate, size)))) {
			(void)update_variable(context, con_out_dev, candidate, candidate_size,
				CDK2_CON_APPEND);
			(void)update_variable(context, err_out_dev, candidate, candidate_size,
				CDK2_CON_APPEND);
		}
	}
	(void)state->boot->free_pool(handles);
	return TRUE;
}

static EFI_STATUS CDK2_MS_ABI get_name(struct cdk2_con_component_name *component,
	CHAR8 * language, cdk2_con_name_ptr * name)
{
	(void)component;
	if (language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	*name = driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_controller_name(struct cdk2_con_component_name *component,
	void *controller, void *child, CHAR8 * language, cdk2_con_name_ptr * name)
{
	(void)component; (void)controller; (void)child; (void)language; (void)name;
	return EFI_UNSUPPORTED;
}

static EFI_STATUS publish(void **handle, const EFI_GUID *guid, void *interface)
{
	return entry.boot->install_multiple(handle, guid, interface, NULL);
}

static void unpublish(void *handle, const EFI_GUID *guid, void *interface)
{
	(void)entry.boot->uninstall_multiple(handle, guid, interface, NULL);
}

static EFI_STATUS publish_binding(void **handle, struct cdk2_con_driver_binding *binding)
{
	EFI_STATUS status;

	status = publish(handle, &driver_binding_guid, binding);
	if (EFI_ERROR(status))
		return status;
	status = publish(handle, &component_name_guid, &entry.name);
	if (EFI_ERROR(status)) {
		unpublish(*handle, &driver_binding_guid, binding);
		return status;
	}
	status = publish(handle, &component_name2_guid, &entry.name2);
	if (EFI_ERROR(status)) {
		unpublish(*handle, &component_name_guid, &entry.name);
		unpublish(*handle, &driver_binding_guid, binding);
	}
	return status;
}

EFI_STATUS CDK2_MS_ABI cdk2_con_platform_entry(void *image,
	struct cdk2_con_system_table *system)
{
	EFI_STATUS status;

	if (image == NULL || system == NULL || system->boot == NULL ||
	    system->runtime == NULL ||
	    system->boot->install_multiple == NULL ||
	    system->boot->uninstall_multiple == NULL)
		return EFI_INVALID_PARAMETER;
	__builtin_memset(&entry, 0, sizeof(entry));
	entry.boot = system->boot;
	entry.runtime = system->runtime;
	entry.image = image;
	entry.input_handle = image;
	entry.input = (struct cdk2_con_driver_binding) {
		driver_supported, driver_start, driver_stop, 0x0aU, image, image
	};
	entry.output = entry.input;
	entry.name = (struct cdk2_con_component_name) {
		get_name, get_controller_name, "eng"
	};
	entry.name2 = (struct cdk2_con_component_name) {
		get_name, get_controller_name, "en"
	};
	{
		static const struct cdk2_con_binding_ops ops = {
			open, close, install_marker, uninstall_marker, update_variable,
			update_gop_candidates
		};

		entry.input_model = (struct cdk2_con_binding) {
			.ops = &ops, .context = &entry, .direction = CDK2_CON_INPUT
		};
		entry.output_model = (struct cdk2_con_binding) {
			.ops = &ops, .context = &entry, .direction = CDK2_CON_OUTPUT
		};
	}
	status = publish_binding(&entry.input_handle, &entry.input);
	if (EFI_ERROR(status))
		return status;
	status = publish_binding(&entry.output_handle, &entry.output);
	if (EFI_ERROR(status)) {
		unpublish(entry.input_handle, &component_name2_guid, &entry.name2);
		unpublish(entry.input_handle, &component_name_guid, &entry.name);
		unpublish(entry.input_handle, &driver_binding_guid, &entry.input);
	}
	return status;
}
