/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mouse.h>

typedef void CDK2_MS_ABI notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN, notify_fn *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI signal_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI set_timer_fn(void *, UINT32, UINT64);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *, void *);
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
	set_timer_fn *set_timer;
	void *wait_for_event;
	signal_event_fn *signal_event;
	close_event_fn *close_event;
	void *check_event;
	void *install_protocol;
	void *reinstall_protocol;
	void *uninstall_protocol;
	void *handle_protocol;
	void *reserved;
	void *register_protocol_notify;
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
	void *locate_protocol;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};

struct system_table_view { UINT8 before_boot_services[96]; struct boot_services_view *boot; };
struct entry_context { struct boot_services_view *boot; struct cdk2_usb_mouse_binding binding; };
static struct entry_context entry_context;
static const EFI_GUID driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };

static EFI_STATUS open(void *context, void *controller, const EFI_GUID *protocol,
	void **interface, void *agent, void *child, UINT32 attributes)
{ return ((struct entry_context *)context)->boot->open_protocol(controller,
	protocol, interface, agent, child, attributes); }
static EFI_STATUS close(void *context, void *controller, const EFI_GUID *protocol,
	void *agent, void *child)
{ return ((struct entry_context *)context)->boot->close_protocol(controller,
	protocol, agent, child); }
static EFI_STATUS install(void *context, void *controller, const EFI_GUID *protocol,
	void *interface)
{ return ((struct entry_context *)context)->boot->install_multiple(&controller,
	protocol, interface, NULL); }
static EFI_STATUS uninstall(void *context, void *controller, const EFI_GUID *protocol,
	void *interface)
{ return ((struct entry_context *)context)->boot->uninstall_multiple(controller,
	protocol, interface, NULL); }
static EFI_STATUS create_event(void *context, UINT32 type, UINTN tpl, void *notify,
	void *notify_context, void **event)
{ return ((struct entry_context *)context)->boot->create_event(type, tpl, notify,
	notify_context, event); }
static EFI_STATUS close_event(void *context, void *event)
{ return ((struct entry_context *)context)->boot->close_event(event); }
static EFI_STATUS signal_event(void *context, void *event)
{ return ((struct entry_context *)context)->boot->signal_event(event); }
static EFI_STATUS set_timer(void *context, void *event, UINT32 type, UINT64 trigger)
{ return ((struct entry_context *)context)->boot->set_timer(event, type, trigger); }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ return ((struct entry_context *)context)->boot->allocate_pool(4U, size, buffer); }
static void release(void *context, void *buffer)
{ (void)((struct entry_context *)context)->boot->free_pool(buffer); }

static const struct cdk2_usb_mouse_ops ops = { open, close, install, uninstall,
	create_event, close_event, signal_event, set_timer, allocate, release };

EFI_STATUS CDK2_MS_ABI cdk2_usb_mouse_entry(void *image,
	struct system_table_view *system)
{
	void *handle = image;

	if (system == NULL || system->boot == NULL || system->boot->open_protocol == NULL ||
	    system->boot->close_protocol == NULL || system->boot->allocate_pool == NULL ||
	    system->boot->free_pool == NULL || system->boot->create_event == NULL ||
	    system->boot->set_timer == NULL || system->boot->signal_event == NULL ||
	    system->boot->close_event == NULL || system->boot->install_multiple == NULL ||
	    system->boot->uninstall_multiple == NULL)
		return EFI_INVALID_PARAMETER;
	entry_context.boot = system->boot;
	cdk2_usb_mouse_binding_init(&entry_context.binding, &ops, &entry_context, image);
	return system->boot->install_multiple(&handle, &driver_binding_guid,
		&entry_context.binding.driver, &component_name_guid,
		&entry_context.binding.component_name, &component_name2_guid,
		&entry_context.binding.component_name2, NULL);
}
