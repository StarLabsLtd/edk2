/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_bus_binding.h>

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI signal_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI locate_device_path_fn(const EFI_GUID *,
	struct cdk2_device_path **, void **);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI handle_protocol_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI image_unload_fn(void *);

struct cdk2_boot_services {
	UINT8 header[24];
	void *raise_tpl;
	void *restore_tpl;
	void *allocate_pages;
	void *free_pages;
	void *get_memory_map;
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	void *create_event;
	void *set_timer;
	void *wait_for_event;
	signal_event_fn *signal_event;
	void *close_event;
	void *check_event;
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
	void *locate_handle_buffer;
	void *locate_protocol;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};

struct cdk2_system_table {
	UINT8 before_boot_services[96];
	struct cdk2_boot_services *boot;
};

struct cdk2_loaded_image {
	UINT32 revision;
	void *parent, *system, *device, *path, *reserved;
	UINT32 options_size;
	void *options, *base;
	UINT64 size;
	UINT32 code_type, data_type;
	image_unload_fn *unload;
};

typedef char allocate_offset_check[offsetof(struct cdk2_boot_services,
	allocate_pool) == 64 ? 1 : -1];
typedef char signal_offset_check[offsetof(struct cdk2_boot_services,
	signal_event) == 104 ? 1 : -1];
typedef char handle_offset_check[offsetof(struct cdk2_boot_services,
	handle_protocol) == 152 ? 1 : -1];
typedef char locate_path_offset_check[offsetof(struct cdk2_boot_services,
	locate_device_path) == 184 ? 1 : -1];
typedef char open_offset_check[offsetof(struct cdk2_boot_services,
	open_protocol) == 280 ? 1 : -1];
typedef char install_offset_check[offsetof(struct cdk2_boot_services,
	install_multiple) == 328 ? 1 : -1];
typedef char loaded_unload_offset_check[offsetof(struct cdk2_loaded_image,
	unload) == 88 ? 1 : -1];

struct scsi_controller_entry {
	struct scsi_controller_entry *next;
	struct cdk2_scsi_binding binding;
};

struct scsi_entry_context {
	struct cdk2_boot_services *boot;
	void *image;
	void *driver_handle;
	struct cdk2_loaded_image *loaded;
	image_unload_fn *original_unload;
	struct scsi_controller_entry *controllers;
	struct cdk2_scsi_driver_binding driver;
	struct cdk2_scsi_component_name component_name;
	struct cdk2_scsi_component_name component_name2;
	BOOLEAN published;
};

static struct scsi_entry_context entry_context;
static const EFI_GUID loaded_image_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };

static EFI_STATUS open(void *context, void *controller, const EFI_GUID *protocol,
	void **interface, void *agent, void *child, UINT32 attributes)
{
	return ((struct scsi_entry_context *)context)->boot->open_protocol(controller,
		protocol, interface, agent, child, attributes);
}

static EFI_STATUS close(void *context, void *controller, const EFI_GUID *protocol,
	void *agent, void *child)
{
	return ((struct scsi_entry_context *)context)->boot->close_protocol(controller,
		protocol, agent, child);
}

static EFI_STATUS install(void *context, void **handle, const EFI_GUID *first,
	void *first_interface, const EFI_GUID *second, void *second_interface)
{
	return ((struct scsi_entry_context *)context)->boot->install_multiple(handle,
		first, first_interface, second, second_interface, NULL);
}

static EFI_STATUS uninstall(void *context, void *handle, const EFI_GUID *first,
	void *first_interface, const EFI_GUID *second, void *second_interface)
{
	return ((struct scsi_entry_context *)context)->boot->uninstall_multiple(handle,
		first, first_interface, second, second_interface, NULL);
}

static EFI_STATUS locate_path(void *context, const EFI_GUID *protocol,
	struct cdk2_device_path **path, void **handle)
{
	return ((struct scsi_entry_context *)context)->boot->locate_device_path(protocol,
		path, handle);
}

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	return ((struct scsi_entry_context *)context)->boot->allocate_pool(4U, size, buffer);
}

static void release(void *context, void *buffer)
{
	(void)((struct scsi_entry_context *)context)->boot->free_pool(buffer);
}

static EFI_STATUS signal(void *context, void *event)
{
	return ((struct scsi_entry_context *)context)->boot->signal_event(event);
}

static const struct cdk2_scsi_binding_ops ops = {
	open, close, install, uninstall, locate_path, allocate, release, signal
};

static CHAR16 entry_driver_name[] = L"CDK2 SCSI Bus Driver";
static CHAR16 entry_controller_name[] = L"SCSI Controller";

static struct scsi_controller_entry *find_controller(void *controller,
	struct scsi_controller_entry ***previous)
{
	struct scsi_controller_entry **link = &entry_context.controllers;

	while (*link != NULL && (*link)->binding.controller != controller)
		link = &(*link)->next;
	if (previous != NULL)
		*previous = link;
	return *link;
}

static EFI_STATUS CDK2_MS_ABI entry_supported(
	struct cdk2_scsi_driver_binding *driver, void *controller,
	struct cdk2_device_path *remaining)
{
	struct cdk2_scsi_binding binding;

	if (driver != &entry_context.driver)
		return EFI_INVALID_PARAMETER;
	cdk2_scsi_binding_init(&binding, &ops, &entry_context, entry_context.image);
	return cdk2_scsi_binding_supported(&binding, controller, remaining);
}

static EFI_STATUS CDK2_MS_ABI entry_start(struct cdk2_scsi_driver_binding *driver,
	void *controller, struct cdk2_device_path *remaining)
{
	struct scsi_controller_entry *entry;
	EFI_STATUS status;

	if (driver != &entry_context.driver)
		return EFI_INVALID_PARAMETER;
	entry = find_controller(controller, NULL);
	if (entry != NULL)
		return cdk2_scsi_binding_start(&entry->binding, controller, remaining);
	status = allocate(&entry_context, sizeof(*entry), (void **)&entry);
	if (EFI_ERROR(status))
		return status;
	*entry = (struct scsi_controller_entry) { 0 };
	cdk2_scsi_binding_init(&entry->binding, &ops, &entry_context,
		entry_context.image);
	status = cdk2_scsi_binding_start(&entry->binding, controller, remaining);
	if (EFI_ERROR(status) && entry->binding.controller == NULL) {
		release(&entry_context, entry);
		return status;
	}
	entry->next = entry_context.controllers;
	entry_context.controllers = entry;
	return status;
}

static EFI_STATUS CDK2_MS_ABI entry_stop(struct cdk2_scsi_driver_binding *driver,
	void *controller, UINTN count, void **children)
{
	struct scsi_controller_entry **link;
	struct scsi_controller_entry *entry;
	EFI_STATUS status;

	if (driver != &entry_context.driver)
		return EFI_INVALID_PARAMETER;
	entry = find_controller(controller, &link);
	if (entry == NULL)
		return EFI_NOT_FOUND;
	status = cdk2_scsi_binding_stop(&entry->binding, controller, count, children);
	if (!EFI_ERROR(status) && entry->binding.controller == NULL) {
		*link = entry->next;
		release(&entry_context, entry);
	}
	return status;
}

static BOOLEAN language_equal(const CHAR8 *left, const CHAR8 *right)
{
	if (left == NULL || right == NULL)
		return FALSE;
	while (*left != '\0' && *left == *right) {
		left++;
		right++;
	}
	return *left == '\0' && *right == '\0';
}

static EFI_STATUS CDK2_MS_ABI entry_driver_name_fn(
	struct cdk2_scsi_component_name *component, CHAR8 *language, CHAR16 **name)
{
	if (component == NULL || name == NULL ||
	    !language_equal(language, component->supported_languages))
		return language == NULL || name == NULL ? EFI_INVALID_PARAMETER :
			EFI_UNSUPPORTED;
	*name = entry_driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI entry_controller_name_fn(
	struct cdk2_scsi_component_name *component, void *controller, void *child,
	CHAR8 *language, CHAR16 **name)
{
	struct scsi_controller_entry *entry;
	struct cdk2_scsi_child *candidate;

	if (component == NULL || name == NULL ||
	    !language_equal(language, component->supported_languages))
		return language == NULL || name == NULL ? EFI_INVALID_PARAMETER :
			EFI_UNSUPPORTED;
	entry = find_controller(controller, NULL);
	if (entry == NULL)
		return EFI_UNSUPPORTED;
	if (child != NULL) {
		for (candidate = entry->binding.children; candidate != NULL;
		     candidate = candidate->next)
			if (candidate->handle == child)
				break;
		if (candidate == NULL)
			return EFI_UNSUPPORTED;
	}
	*name = entry_controller_name;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_scsi_bus_unload(void *image)
{
	struct scsi_controller_entry *entry;
	EFI_STATUS status;

	if (!entry_context.published || image != entry_context.image)
		return EFI_INVALID_PARAMETER;
	while ((entry = entry_context.controllers) != NULL) {
		while (entry->binding.children != NULL) {
			void *child = entry->binding.children->handle;

			status = entry_stop(&entry_context.driver,
				entry->binding.controller, 1, &child);
			if (EFI_ERROR(status))
				return status;
		}
		status = entry_stop(&entry_context.driver, entry->binding.controller,
			0, NULL);
		if (EFI_ERROR(status))
			return status;
	}
	status = entry_context.boot->uninstall_multiple(entry_context.driver_handle,
		&driver_binding_guid, &entry_context.driver, &component_name_guid,
		&entry_context.component_name, &component_name2_guid,
		&entry_context.component_name2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry_context.loaded->unload = entry_context.original_unload;
	entry_context.published = FALSE;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_scsi_bus_entry(void *image,
	struct cdk2_system_table *system_table)
{
	EFI_STATUS status;

	if (system_table == NULL || system_table->boot == NULL ||
	    entry_context.published ||
	    system_table->boot->handle_protocol == NULL ||
	    system_table->boot->open_protocol == NULL ||
	    system_table->boot->close_protocol == NULL ||
	    system_table->boot->allocate_pool == NULL ||
	    system_table->boot->free_pool == NULL ||
	    system_table->boot->install_multiple == NULL ||
	    system_table->boot->uninstall_multiple == NULL ||
	    system_table->boot->locate_device_path == NULL ||
	    system_table->boot->signal_event == NULL)
		return EFI_INVALID_PARAMETER;
	entry_context = (struct scsi_entry_context) { 0 };
	entry_context.boot = system_table->boot;
	entry_context.image = image;
	status = entry_context.boot->handle_protocol(image, &loaded_image_guid,
		(void **)&entry_context.loaded);
	if (EFI_ERROR(status) || entry_context.loaded == NULL)
		return EFI_ERROR(status) ? status : EFI_NOT_FOUND;
	entry_context.driver = (struct cdk2_scsi_driver_binding) {
		entry_supported, entry_start, entry_stop, 0x0aU, image, NULL };
	entry_context.component_name = (struct cdk2_scsi_component_name) {
		entry_driver_name_fn, entry_controller_name_fn, "eng" };
	entry_context.component_name2 = (struct cdk2_scsi_component_name) {
		entry_driver_name_fn, entry_controller_name_fn, "en" };
	entry_context.driver_handle = image;
	status = entry_context.boot->install_multiple(&entry_context.driver_handle,
		&driver_binding_guid, &entry_context.driver, &component_name_guid,
		&entry_context.component_name, &component_name2_guid,
		&entry_context.component_name2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry_context.driver.driver_binding_handle = entry_context.driver_handle;
	entry_context.original_unload = entry_context.loaded->unload;
	entry_context.loaded->unload = cdk2_scsi_bus_unload;
	entry_context.published = TRUE;
	return EFI_SUCCESS;
}
