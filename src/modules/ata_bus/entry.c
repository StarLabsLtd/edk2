/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_bus_entry.h>

#include <stddef.h>
#include <string.h>

typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const EFI_GUID *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const EFI_GUID *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI event_fn(void *, UINT32, UINT64);
typedef EFI_STATUS CDK2_MS_ABI create_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI signal_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef UINTN CDK2_MS_ABI raise_tpl_fn(UINTN);
typedef void CDK2_MS_ABI restore_tpl_fn(UINTN);
typedef EFI_STATUS CDK2_MS_ABI wait_fn(UINTN, void **, UINTN *);

struct cdk2_ata_bus_boot_services {
	UINT8 header[24];
	raise_tpl_fn *raise_tpl; restore_tpl_fn *restore_tpl;
	void *allocate_pages, *free_pages, *get_memory_map;
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	create_fn *create_event;
	event_fn *set_timer;
	wait_fn *wait_for_event;
	signal_fn *signal_event;
	close_event_fn *close_event;
	void *check_event, *install_protocol, *reinstall_protocol, *uninstall_protocol;
	handle_fn *handle_protocol;
	void *reserved, *register_notify, *locate_handle, *locate_device_path;
	void *install_config, *load_image, *start_image, *exit, *unload_image;
	void *exit_boot_services, *monotonic, *stall, *watchdog, *connect, *disconnect;
	open_fn *open_protocol;
	close_fn *close_protocol;
	void *open_info, *protocols_per_handle, *locate_handle_buffer, *locate_protocol;
	install_fn *install_multiple;
	uninstall_fn *uninstall_multiple;
};
struct system_view { UINT8 prefix[96]; struct cdk2_ata_bus_boot_services *boot; };
typedef char allocate_offset_check[offsetof(struct cdk2_ata_bus_boot_services,
	allocate_pool) == 64 ? 1 : -1];
typedef char event_offset_check[offsetof(struct cdk2_ata_bus_boot_services,
	create_event) == 80 ? 1 : -1];
typedef char signal_offset_check[offsetof(struct cdk2_ata_bus_boot_services,
	signal_event) == 104 ? 1 : -1];
typedef char handle_offset_check[offsetof(struct cdk2_ata_bus_boot_services,
	handle_protocol) == 152 ? 1 : -1];
typedef char open_offset_check[offsetof(struct cdk2_ata_bus_boot_services,
	open_protocol) == 280 ? 1 : -1];
typedef char install_offset_check[offsetof(struct cdk2_ata_bus_boot_services,
	install_multiple) == 328 ? 1 : -1];

static const EFI_GUID loaded_image_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID driver_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const EFI_GUID ata_guid = { 0x1d3de7f0, 0x0807, 0x424f,
	{ 0xaa, 0x69, 0x11, 0xa5, 0x4e, 0x19, 0xa4, 0x6f } };
static const EFI_GUID path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID block_guid = { 0x964e5b21, 0x6459, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID block2_guid = { 0xa77b2472, 0xe282, 0x4e9f,
	{ 0xa2, 0x45, 0xc2, 0xc0, 0xe2, 0x7b, 0xbc, 0xc1 } };
static const EFI_GUID disk_guid = { 0xd432a67f, 0x14dc, 0x484b,
	{ 0xb3, 0xbb, 0x3f, 0x02, 0x91, 0x84, 0x93, 0x27 } };
static const EFI_GUID security_guid = { 0xc88b0b6d, 0x0dfc, 0x49a7,
	{ 0x9c, 0xb4, 0x49, 0x07, 0x4b, 0x4c, 0x3a, 0x78 } };
static const EFI_GUID marker_guid = { 0x19df145a, 0xb1d4, 0x453f,
	{ 0x85, 0x07, 0x38, 0x81, 0x66, 0x76, 0xd7, 0xf6 } };
static CHAR16 driver_name[] = u"ATA Bus Driver";
static CHAR16 controller_name[] = u"ATA Disk Controller";
static struct cdk2_ata_bus_entry image_entry;
static struct cdk2_ata_bus_entry *active;

struct deferred_call {
	struct cdk2_ata_bus_entry *entry;
	struct cdk2_ata_bus_block_instance *instance;
	void *event;
};
struct parent_call {
	struct cdk2_ata_bus_entry *entry;
	cdk2_ata_bus_complete_fn *complete;
	void *complete_context;
	void *event;
	struct parent_call *next;
	UINTN references;
	BOOLEAN notified;
};

static EFI_STATUS service_allocate(void *context, UINTN size, void **buffer)
{
	struct cdk2_ata_bus_entry *entry = context;
	return entry->boot->allocate_pool(4U, size, buffer);
}
static void service_release(void *context, void *buffer)
{
	struct cdk2_ata_bus_entry *entry = context;
	(void)entry->boot->free_pool(buffer);
}
static void release_parent_call(struct parent_call *call)
{
	if (--call->references == 0U)
		service_release(call->entry, call);
}
static void CDK2_MS_ABI worker_notify(void *event, void *context)
{
	struct deferred_call *call = context;
	struct cdk2_ata_bus_entry *entry = call->entry;

	(void)cdk2_ata_bus_block_worker(call->instance);
	(void)entry->boot->close_event(event);
	service_release(entry, call);
}
static EFI_STATUS service_defer(void *context,
	struct cdk2_ata_bus_block_instance *instance)
{
	struct cdk2_ata_bus_entry *entry = context;
	struct deferred_call *call;
	EFI_STATUS status;

	status = service_allocate(entry, sizeof(*call), (void **)&call);
	if (EFI_ERROR(status))
		return status;
	*call = (struct deferred_call) { entry, instance, NULL };
	status = entry->boot->create_event(0x200U, 8U, worker_notify, call, &call->event);
	if (!EFI_ERROR(status))
		status = entry->boot->signal_event(call->event);
	if (EFI_ERROR(status)) {
		if (call->event != NULL)
			(void)entry->boot->close_event(call->event);
		service_release(entry, call);
	}
	return status;
}

static EFI_STATUS service_open(void *context, void *controller, BOOLEAN by_driver,
	struct cdk2_ata_pass_thru_protocol **protocol)
{
	struct cdk2_ata_bus_entry *entry = context;
	void *path = NULL;
	EFI_STATUS status;

	status = entry->boot->open_protocol(controller, &ata_guid, (void **)protocol,
		entry->image, controller, by_driver ? 0x10U : 0x02U);
	if (EFI_ERROR(status) || !by_driver)
		return status;
	status = entry->boot->open_protocol(controller, &path_guid, &path,
		entry->image, controller, 0x02U);
	if (EFI_ERROR(status))
		(void)entry->boot->close_protocol(controller, &ata_guid,
			entry->image, controller);
	return status;
}
static EFI_STATUS service_close(void *context, void *controller, BOOLEAN by_driver)
{
	struct cdk2_ata_bus_entry *entry = context;
	return by_driver ? entry->boot->close_protocol(controller, &ata_guid,
		entry->image, controller) : EFI_SUCCESS;
}
static EFI_STATUS service_marker(void *context, void *controller, BOOLEAN install)
{
	struct cdk2_ata_bus_entry *entry = context;
	return install ? entry->boot->install_multiple(&controller, &marker_guid, entry, NULL) :
		entry->boot->uninstall_multiple(controller, &marker_guid, entry, NULL);
}
static EFI_STATUS service_install_child(void *context, void **handle,
	struct cdk2_ata_bus_bound_child *child, BOOLEAN security)
{
	struct cdk2_ata_bus_entry *entry = context;
	UINT8 *parent = NULL, *full;
	UINTN parent_size = 0;
	EFI_STATUS status;

	status = entry->boot->open_protocol(child->model.controller, &path_guid,
		(void **)&parent, entry->image, child->model.controller, 0x02U);
	if (EFI_ERROR(status) || parent == NULL)
		return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
	while (parent_size < 4096U) {
		UINTN length = parent[parent_size + 2U] |
			((UINTN)parent[parent_size + 3U] << 8);

		if (length < 4U || length > 4096U - parent_size)
			return EFI_COMPROMISED_DATA;
		if (parent[parent_size] == 0x7fU && parent[parent_size + 1U] == 0xffU) {
			if (length != 4U)
				return EFI_COMPROMISED_DATA;
			break;
		}
		parent_size += length;
	}
	if (parent_size >= 4096U || child->model.device_path_size >
	    (UINTN)-1 - parent_size - 4U)
		return EFI_COMPROMISED_DATA;
	status = service_allocate(entry, parent_size + child->model.device_path_size + 4U,
		(void **)&full);
	if (EFI_ERROR(status))
		return status;
	memcpy(full, parent, parent_size);
	memcpy(full + parent_size, child->model.device_path, child->model.device_path_size);
	full[parent_size + child->model.device_path_size] = 0x7fU;
	full[parent_size + child->model.device_path_size + 1U] = 0xffU;
	full[parent_size + child->model.device_path_size + 2U] = 4U;
	full[parent_size + child->model.device_path_size + 3U] = 0U;
	child->full_device_path = full;
	child->full_device_path_size = parent_size + child->model.device_path_size + 4U;
	if (security)
		status = entry->boot->install_multiple(handle, &path_guid, full,
			&block_guid, &child->block.block, &block2_guid, &child->block.block2,
			&disk_guid, &child->disk_info, &security_guid, &child->security, NULL);
	else
		status = entry->boot->install_multiple(handle, &path_guid, full,
			&block_guid, &child->block.block, &block2_guid, &child->block.block2,
			&disk_guid, &child->disk_info, NULL);
	if (EFI_ERROR(status)) {
		service_release(entry, full);
		child->full_device_path = NULL; child->full_device_path_size = 0;
	}
	return status;
}
static EFI_STATUS service_uninstall_child(void *context, void *handle,
	struct cdk2_ata_bus_bound_child *child, BOOLEAN security)
{
	struct cdk2_ata_bus_entry *entry = context;
	EFI_STATUS status;
	if (security)
		status = entry->boot->uninstall_multiple(handle, &path_guid,
			child->full_device_path,
			&block_guid, &child->block.block, &block2_guid, &child->block.block2,
			&disk_guid, &child->disk_info, &security_guid, &child->security, NULL);
	else
		status = entry->boot->uninstall_multiple(handle, &path_guid,
			child->full_device_path, &block_guid, &child->block.block,
			&block2_guid, &child->block.block2, &disk_guid, &child->disk_info, NULL);
	if (!EFI_ERROR(status)) {
		service_release(entry, child->full_device_path);
		child->full_device_path = NULL; child->full_device_path_size = 0;
	}
	return status;
}
static EFI_STATUS service_link(void *context, void *controller, void *child,
	BOOLEAN open)
{
	struct cdk2_ata_bus_entry *entry = context;
	void *protocol = NULL;
	return open ? entry->boot->open_protocol(controller, &ata_guid, &protocol,
		entry->image, child, 0x08U) : entry->boot->close_protocol(controller,
		&ata_guid, entry->image, child);
}
static struct cdk2_ata_bus_bound_controller *owner_for(
	struct cdk2_ata_bus_entry *entry, void *controller)
{
	for (UINTN index = 0; index < entry->binding.controller_count; index++)
		if (entry->binding.controllers[index]->handle == controller)
			return entry->binding.controllers[index];
	return NULL;
}
static EFI_STATUS service_execute(void *context, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet)
{
	struct cdk2_ata_bus_entry *entry = context;
	struct cdk2_ata_bus_bound_controller *owner = owner_for(entry, child->controller);
	return owner == NULL ? EFI_NOT_READY : owner->pass_thru->pass_thru(owner->pass_thru,
		child->port, child->multiplier, packet, NULL);
}
static void CDK2_MS_ABI parent_notify(void *event, void *context)
{
	struct parent_call *call = context;
	EFI_STATUS status = EFI_SUCCESS;
	struct parent_call **link;

	call->notified = 1;
	call->complete(call->complete_context, status);
	for (link = (struct parent_call **)&call->entry->parent_calls;
	    *link != NULL; link = &(*link)->next)
		if (*link == call) { *link = call->next; break; }
	(void)call->entry->boot->close_event(event);
	release_parent_call(call);
}
static EFI_STATUS service_submit(void *context, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet, cdk2_ata_bus_complete_fn *complete,
	void *complete_context)
{
	struct cdk2_ata_bus_entry *entry = context;
	struct cdk2_ata_bus_bound_controller *owner = owner_for(entry, child->controller);
	struct parent_call *call;
	EFI_STATUS status;

	if (owner == NULL)
		return EFI_NOT_READY;
	status = service_allocate(entry, sizeof(*call), (void **)&call);
	if (EFI_ERROR(status))
		return status;
	*call = (struct parent_call) { entry, complete, complete_context, NULL, NULL, 2U, 0 };
	status = entry->boot->create_event(0x200U, 8U, parent_notify, call, &call->event);
	if (!EFI_ERROR(status)) {
		call->next = entry->parent_calls;
		entry->parent_calls = call;
		status = owner->pass_thru->pass_thru(owner->pass_thru, child->port,
			child->multiplier, packet, call->event);
	}
	if (EFI_ERROR(status)) {
		if (!call->notified) {
			struct parent_call **link;
			for (link = (struct parent_call **)&entry->parent_calls;
			    *link != NULL; link = &(*link)->next)
				if (*link == call) { *link = call->next; break; }
			if (call->event != NULL)
				(void)entry->boot->close_event(call->event);
			release_parent_call(call);
		}
	}
	release_parent_call(call);
	return status;
}
static EFI_STATUS service_wait(void *context)
{
	struct cdk2_ata_bus_entry *entry = context;
	struct parent_call *call = entry->parent_calls;
	UINTN index, old_tpl;
	if (call == NULL)
		return EFI_NOT_READY;
	if (entry->boot->raise_tpl == NULL || entry->boot->restore_tpl == NULL ||
	    entry->boot->wait_for_event == NULL)
		return EFI_UNSUPPORTED;
	old_tpl = entry->boot->raise_tpl(31U);
	entry->boot->restore_tpl(old_tpl);
	if (old_tpl > 4U)
		return EFI_UNSUPPORTED;
	return entry->boot->wait_for_event(1U, &call->event, &index);
}
static EFI_STATUS service_reset(void *context, struct cdk2_ata_bus_child *child,
	BOOLEAN extended)
{
	struct cdk2_ata_bus_entry *entry = context;
	struct cdk2_ata_bus_bound_controller *owner = owner_for(entry, child->controller);
	(void)extended;
	return owner == NULL || owner->pass_thru->reset_device == NULL ? EFI_UNSUPPORTED :
		owner->pass_thru->reset_device(owner->pass_thru, child->port, child->multiplier);
}
static void service_signal(void *context, void *event)
{
	struct cdk2_ata_bus_entry *entry = context;
	(void)entry->boot->signal_event(event);
}

static struct cdk2_ata_bus_entry *from_driver(struct cdk2_ata_driver_binding *driver)
{
	return (struct cdk2_ata_bus_entry *)((UINT8 *)driver -
		offsetof(struct cdk2_ata_bus_entry, driver));
}
static EFI_STATUS CDK2_MS_ABI supported(struct cdk2_ata_driver_binding *driver,
	void *controller, void *remaining)
{ return cdk2_ata_bus_binding_supported(&from_driver(driver)->binding,
	controller, remaining); }
static EFI_STATUS CDK2_MS_ABI start(struct cdk2_ata_driver_binding *driver,
	void *controller, void *remaining)
{ return cdk2_ata_bus_binding_start(&from_driver(driver)->binding,
	controller, remaining); }
static EFI_STATUS CDK2_MS_ABI stop(struct cdk2_ata_driver_binding *driver,
	void *controller, UINTN children, void **child_buffer)
{ return cdk2_ata_bus_binding_stop(&from_driver(driver)->binding,
	controller, children, child_buffer); }
static int language_equal(const CHAR8 *a, const CHAR8 *b)
{ return a != NULL && b != NULL && strcmp(a, b) == 0; }
static EFI_STATUS CDK2_MS_ABI get_driver_name(struct cdk2_ata_component_name *component,
	CHAR8 *language, CHAR16 **name)
{
	if (component == NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (!language_equal(language, component->languages))
		return EFI_UNSUPPORTED;
	*name = driver_name; return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_ata_component_name *component, void *controller, void *child,
	CHAR8 *language, CHAR16 **name)
{
	struct cdk2_ata_bus_entry *entry;
	struct cdk2_ata_bus_bound_controller *owner;
	BOOLEAN found = 0;

	if (component == NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (!language_equal(language, component->languages))
		return EFI_UNSUPPORTED;
	entry = (struct cdk2_ata_bus_entry *)((UINT8 *)component -
		(component->languages[2] == 0 ? offsetof(struct cdk2_ata_bus_entry, component2) :
		offsetof(struct cdk2_ata_bus_entry, component)));
	owner = owner_for(entry, controller);
	if (owner == NULL)
		return EFI_UNSUPPORTED;
	if (child != NULL) {
		for (UINTN index = 0; index < owner->child_count; index++)
			if (owner->children[index]->handle == child)
				found = 1;
		if (!found)
			return EFI_UNSUPPORTED;
	}
	*name = controller_name; return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_entry_publish(struct cdk2_ata_bus_entry *entry,
	void *image, void *system_table)
{
	struct system_view *system = system_table;
	struct cdk2_ata_bus_binding_services services;
	EFI_STATUS status;

	if (entry == NULL || image == NULL || system == NULL || system->boot == NULL ||
	    active != NULL)
		return EFI_INVALID_PARAMETER;
	memset(entry, 0, sizeof(*entry)); entry->boot = system->boot; entry->image = image;
	status = entry->boot->handle_protocol(image, &loaded_image_guid,
		(void **)&entry->loaded);
	if (EFI_ERROR(status) || entry->loaded == NULL)
		return EFI_ERROR(status) ? status : EFI_NOT_FOUND;
	services = (struct cdk2_ata_bus_binding_services) {
		entry, service_open, service_close, service_marker, service_allocate,
		service_release, service_install_child, service_uninstall_child, service_link,
		service_defer, { entry, service_execute, service_submit, service_wait,
		service_reset, service_signal } };
	status = cdk2_ata_bus_binding_init(&entry->binding, &services);
	if (EFI_ERROR(status))
		return status;
	entry->driver = (struct cdk2_ata_driver_binding) {
		supported, start, stop, 0x10U, image, NULL };
	entry->component = (struct cdk2_ata_component_name) {
		get_driver_name, get_controller_name, "eng" };
	entry->component2 = (struct cdk2_ata_component_name) {
		get_driver_name, get_controller_name, "en" };
	status = entry->boot->install_multiple(&entry->driver_handle,
		&driver_guid, &entry->driver, &component_guid, &entry->component,
		&component2_guid, &entry->component2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->driver.handle = entry->driver_handle;
	entry->original_unload = entry->loaded->unload;
	entry->loaded->unload = cdk2_ata_bus_entry_unload;
	entry->published = 1; active = entry;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_ata_bus_entry_unload(void *image)
{
	struct cdk2_ata_bus_entry *entry = active;
	EFI_STATUS status;

	if (entry == NULL || image != entry->image || !entry->published)
		return EFI_INVALID_PARAMETER;
	while (entry->binding.controller_count != 0U) {
		void *controller = entry->binding.controllers[
			entry->binding.controller_count - 1U]->handle;
		status = cdk2_ata_bus_binding_stop(&entry->binding, controller, 0, NULL);
		if (EFI_ERROR(status))
			return status;
	}
	status = entry->boot->uninstall_multiple(entry->driver_handle,
		&driver_guid, &entry->driver, &component_guid, &entry->component,
		&component2_guid, &entry->component2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->loaded->unload = entry->original_unload;
	entry->published = 0; active = NULL;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_ata_bus_entry(void *image, void *system_table)
{ return cdk2_ata_bus_entry_publish(&image_entry, image, system_table); }
