/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/fat_binding.h>

#define OPEN_BY_DRIVER 0x10U
typedef EFI_STATUS CDK2_MS_ABI alloc_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI signal_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI set_timer_fn(void *, UINT32, UINT64);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const EFI_GUID *, void **, void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, ...);
struct boot_view { UINT8 hdr[24]; void *raise_tpl, *restore_tpl, *allocate_pages,
	*free_pages, *get_memory_map; alloc_fn *allocate_pool; free_fn *free_pool;
	create_event_fn *create_event; set_timer_fn *set_timer; void *wait_for_event;
	signal_fn *signal_event; close_event_fn *close_event;
	void *check_event, *install_protocol, *reinstall_protocol,
	*uninstall_protocol, *handle_protocol, *reserved, *register_protocol_notify,
	*locate_handle, *locate_device_path, *install_configuration_table, *load_image,
	*start_image, *exit, *unload_image, *exit_boot_services,
	*get_next_monotonic_count, *stall, *set_watchdog_timer, *connect_controller,
	*disconnect_controller; open_fn *open_protocol; close_fn *close_protocol;
	void *open_protocol_information, *protocols_per_handle, *locate_handle_buffer;
	locate_protocol_fn *locate_protocol; install_fn *install_multiple;
	uninstall_fn *uninstall_multiple; };
struct system_view { UINT8 before_boot[96]; struct boot_view *boot; };
struct driver_view;
typedef EFI_STATUS CDK2_MS_ABI driver_supported_fn(struct driver_view *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI driver_start_fn(struct driver_view *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI driver_stop_fn(struct driver_view *, void *, UINTN, void **);
struct driver_view { driver_supported_fn *supported; driver_start_fn *start;
	driver_stop_fn *stop; UINT32 version; void *image_handle, *binding_handle; };
struct component_view;
typedef EFI_STATUS CDK2_MS_ABI name_fn(struct component_view *, CHAR8 *, CHAR16 **);
typedef EFI_STATUS CDK2_MS_ABI controller_name_fn(struct component_view *, void *, void *, CHAR8 *, CHAR16 **);
struct component_view { name_fn *driver_name; controller_name_fn *controller_name; CHAR8 *languages; };
struct entry_context { struct boot_view *boot; void *image; struct cdk2_fat_binding binding;
	struct driver_view driver; struct component_view component, component2; };
static struct entry_context entry;
struct queued_call { struct entry_context *entry; void (*function)(void *); void *context;
	void *event; };
static const EFI_GUID driver_guid = { 0x18a031abU, 0xb443U, 0x4d1aU,
	{ 0xa5U, 0xc0U, 0x0cU, 0x09U, 0x26U, 0x1eU, 0x9fU, 0x71U } };
static const EFI_GUID component_guid = { 0x107a772cU, 0xd5e1U, 0x11d4U,
	{ 0x9aU, 0x46U, 0x00U, 0x90U, 0x27U, 0x3fU, 0xc1U, 0x4dU } };
static const EFI_GUID component2_guid = { 0x6a7a5cffU, 0xe8d9U, 0x4f70U,
	{ 0xbaU, 0xdaU, 0x75U, 0xabU, 0x30U, 0x25U, 0xceU, 0x14U } };
static const EFI_GUID collation2_guid = { 0xa4c751fcU, 0x23aeU, 0x4c3eU,
	{ 0x92U, 0xe9U, 0x49U, 0x64U, 0xcfU, 0x63U, 0xf3U, 0x49U } };
static const EFI_GUID collation_guid = { 0x1d85cd7fU, 0xf43dU, 0x11d2U,
	{ 0x9aU, 0x0cU, 0x00U, 0x90U, 0x27U, 0x3fU, 0xc1U, 0x4dU } };
static CHAR16 fat_name[] = L"CDK2 FAT File System Driver";
static struct entry_context *entry_of(struct driver_view *d)
{ return (struct entry_context *)((UINT8 *)d - offsetof(struct entry_context, driver)); }
static EFI_STATUS op_open(void *c, void *controller, const EFI_GUID *g, void **interface)
{ struct entry_context *e = c; return e->boot->open_protocol(controller, g, interface,
	e->image, controller, OPEN_BY_DRIVER); }
static EFI_STATUS op_close(void *c, void *controller, const EFI_GUID *g)
{ struct entry_context *e = c; return e->boot->close_protocol(controller, g, e->image, controller); }
static EFI_STATUS op_publish(void *c, void *controller, const EFI_GUID *g, void *interface)
{ return ((struct entry_context *)c)->boot->install_multiple(&controller, g, interface, NULL); }
static EFI_STATUS op_unpublish(void *c, void *controller, const EFI_GUID *g, void *interface)
{ return ((struct entry_context *)c)->boot->uninstall_multiple(controller, g, interface, NULL); }
static EFI_STATUS op_allocate(void *c, UINTN size, void **buffer)
{ return ((struct entry_context *)c)->boot->allocate_pool(4U, size, buffer); }
static void op_release(void *c, void *buffer)
{ (void)((struct entry_context *)c)->boot->free_pool(buffer); }
static EFI_STATUS op_signal(void *c, void *event)
{ return ((struct entry_context *)c)->boot->signal_event(event); }
static void CDK2_MS_ABI queued_notify(void *event, void *opaque)
{
	struct queued_call *call = opaque;
	call->function(call->context);
	(void)call->entry->boot->close_event(event);
	op_release(call->entry, call);
}
static EFI_STATUS op_queue(void *c, void (*function)(void *), void *context, void **cookie)
{
	struct entry_context *e = c; struct queued_call *call; EFI_STATUS status;
	if (function == NULL || cookie == NULL || e->boot->create_event == NULL || e->boot->set_timer == NULL ||
	    e->boot->close_event == NULL) return EFI_UNSUPPORTED;
	status = op_allocate(e, sizeof(*call), (void **)&call); if (EFI_ERROR(status)) return status;
	*call = (struct queued_call) { e, function, context, NULL };
	status = e->boot->create_event(0x80000200U, 8U, queued_notify, call, &call->event);
	if (!EFI_ERROR(status)) status = e->boot->set_timer(call->event, 2U, 10000U);
	if (EFI_ERROR(status)) { if (call->event != NULL) (void)e->boot->close_event(call->event);
		op_release(e, call); }
	if (!EFI_ERROR(status)) *cookie = call;
	return status;
}
static void op_drain(void *c, void *cookie)
{
	struct entry_context *e = c; struct queued_call *call = cookie;
	if (call == NULL) return;
	(void)e->boot->set_timer(call->event, 0U, 0U);
	(void)e->boot->close_event(call->event);
	call->function(call->context); op_release(e, call);
}
static EFI_STATUS CDK2_MS_ABI supported(struct driver_view *d, void *controller, void *remaining)
{
	struct entry_context *e = entry_of(d); void *interface; EFI_STATUS status;
	(void)remaining; status = op_open(e, controller, &cdk2_fat_block_io_guid, &interface);
	if (EFI_ERROR(status)) return status;
	status = op_open(e, controller, &cdk2_fat_disk_io_guid, &interface);
	if (!EFI_ERROR(status)) (void)op_close(e, controller, &cdk2_fat_disk_io_guid);
	(void)op_close(e, controller, &cdk2_fat_block_io_guid); return status;
}
static EFI_STATUS CDK2_MS_ABI start(struct driver_view *d, void *controller, void *remaining)
{
	struct entry_context *e = entry_of(d);
	EFI_STATUS status;
	(void)remaining;
	if (e->boot->locate_protocol == NULL)
		return EFI_UNSUPPORTED;
	status = e->boot->locate_protocol(&collation2_guid, NULL,
		(void **)&e->binding.collation);
	if (EFI_ERROR(status))
		status = e->boot->locate_protocol(&collation_guid, NULL,
			(void **)&e->binding.collation);
	return EFI_ERROR(status) ? status : cdk2_fat_binding_start(&e->binding, controller);
}
static EFI_STATUS CDK2_MS_ABI stop(struct driver_view *d, void *controller, UINTN children, void **buffer)
{ (void)buffer; if (children != 0U) return EFI_INVALID_PARAMETER;
	return cdk2_fat_binding_stop(&entry_of(d)->binding, controller); }
static EFI_STATUS CDK2_MS_ABI driver_name(struct component_view *c, CHAR8 *language, CHAR16 **name)
{ return cdk2_fat_driver_name(c != &entry.component, language, name); }
EFI_STATUS cdk2_fat_driver_name(BOOLEAN component_name2, CHAR8 *language, CHAR16 **name)
{ if (language == NULL || name == NULL) return EFI_INVALID_PARAMETER;
	if (!component_name2) {
		if (language[0] != 'e' || language[1] != 'n' || language[2] != 'g' || language[3] != 0)
			return EFI_UNSUPPORTED;
	} else if (language[0] != 'e' || language[1] != 'n' || language[2] != 0) {
		return EFI_UNSUPPORTED;
	}
	*name = fat_name; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI controller_name(struct component_view *c, void *controller,
	void *child, CHAR8 *language, CHAR16 **name)
{ (void)c; (void)controller; (void)child; (void)language; (void)name; return EFI_UNSUPPORTED; }
EFI_STATUS CDK2_MS_ABI cdk2_fat_entry(void *image, void *table)
{
	static const struct cdk2_fat_binding_ops ops = { op_open, op_close, op_publish,
		op_unpublish, op_allocate, op_release, op_signal, op_queue, op_drain };
	struct system_view *system = table; EFI_STATUS status;
	if (image == NULL || system == NULL || system->boot == NULL) return EFI_INVALID_PARAMETER;
	__builtin_memset(&entry, 0, sizeof(entry)); entry.boot = system->boot; entry.image = image;
	entry.binding.ops = &ops; entry.binding.context = &entry;
	entry.driver = (struct driver_view) { supported, start, stop, 0x10U, image, image };
	entry.component = (struct component_view) { driver_name, controller_name, "eng" };
	entry.component2 = (struct component_view) { driver_name, controller_name, "en" };
	status = entry.boot->install_multiple(&image, &driver_guid, &entry.driver,
		&component_guid, &entry.component, &component2_guid, &entry.component2, NULL);
	return status;
}
