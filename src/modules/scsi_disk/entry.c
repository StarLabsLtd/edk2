/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_bus_binding.h>
#include <cdk2/scsi_disk_entry.h>

#include <stddef.h>
#include <string.h>

#ifndef EFI_ALREADY_STARTED
#define EFI_ALREADY_STARTED EFIERR(20)
#endif

typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI signal_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI wait_fn(UINTN, void **, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const EFI_GUID *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const EFI_GUID *, void *, ...);
typedef UINTN CDK2_MS_ABI raise_tpl_fn(UINTN);
typedef void CDK2_MS_ABI restore_tpl_fn(UINTN);

struct boot_services {
	UINT8 header[24];
	raise_tpl_fn *raise_tpl;
	restore_tpl_fn *restore_tpl;
	void *allocate_pages, *free_pages, *memory_map;
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	create_fn *create_event;
	void *set_timer;
	wait_fn *wait_for_event;
	signal_fn *signal_event;
	close_event_fn *close_event;
	void *check_event, *install_protocol, *reinstall_protocol, *uninstall_protocol;
	handle_fn *handle_protocol;
	UINT8 before_open[120];
	open_fn *open_protocol;
	close_fn *close_protocol;
	UINT8 before_install[32];
	install_fn *install_multiple;
	uninstall_fn *uninstall_multiple;
};
struct system_view { UINT8 prefix[96]; struct boot_services *boot; };
typedef char raise_offset[offsetof(struct boot_services, raise_tpl) == 24 ? 1 : -1];
typedef char allocate_offset[offsetof(struct boot_services, allocate_pool) == 64 ? 1 : -1];
typedef char event_offset[offsetof(struct boot_services, create_event) == 80 ? 1 : -1];
typedef char wait_offset[offsetof(struct boot_services, wait_for_event) == 96 ? 1 : -1];
typedef char signal_offset[offsetof(struct boot_services, signal_event) == 104 ? 1 : -1];
typedef char handle_offset[offsetof(struct boot_services, handle_protocol) == 152 ? 1 : -1];
typedef char open_offset[offsetof(struct boot_services, open_protocol) == 280 ? 1 : -1];
typedef char install_offset[offsetof(struct boot_services, install_multiple) == 328 ? 1 : -1];

static const EFI_GUID loaded_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID driver_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const EFI_GUID scsi_io_guid = { 0x932f47e6, 0x2362, 0x4002,
	{ 0x80, 0x3e, 0x3c, 0xd5, 0x4b, 0x13, 0x8f, 0x85 } };
static const EFI_GUID block_guid = { 0x964e5b21, 0x6459, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID block2_guid = { 0xa77b2472, 0xe282, 0x4e9f,
	{ 0xa2, 0x45, 0xc2, 0xc0, 0xe2, 0x7b, 0xbc, 0xc1 } };
static const EFI_GUID disk_info_guid = { 0xd432a67f, 0x14dc, 0x484b,
	{ 0xb3, 0xbb, 0x3f, 0x02, 0x91, 0x84, 0x93, 0x27 } };
static struct cdk2_scsi_disk_entry image_entry;
static struct cdk2_scsi_disk_entry *active;
static CHAR16 driver_name[] = { 'C', 'D', 'K', '2', ' ', 'S', 'C', 'S', 'I',
	' ', 'D', 'i', 's', 'k', ' ', 'D', 'r', 'i', 'v', 'e', 'r', 0 };
static CHAR16 controller_name[] = { 'S', 'C', 'S', 'I', ' ', 'D', 'i', 's', 'k',
	0 };

static struct boot_services *boot(struct cdk2_scsi_disk_entry *entry)
{
	return entry->boot;
}

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	return boot(context)->allocate_pool(4U, size, buffer);
}

static void release(void *context, void *buffer)
{
	(void)boot(context)->free_pool(buffer);
}

static EFI_STATUS create_event(void *context,
	void (CDK2_MS_ABI *notify)(void *, void *), void *notify_context, void **event)
{
	return boot(context)->create_event(0x200U, 8U, notify, notify_context, event);
}

static EFI_STATUS close_event(void *context, void *event)
{
	return boot(context)->close_event(event);
}

static EFI_STATUS wait_event(void *context, void *event)
{
	struct boot_services *services = boot(context);
	UINTN old_tpl = services->raise_tpl(8U);
	UINTN index;

	services->restore_tpl(old_tpl);
	if (old_tpl >= 8U)
		return EFI_NOT_READY;
	return services->wait_for_event(1U, &event, &index);
}

static EFI_STATUS signal(void *context, void *event)
{
	return boot(context)->signal_event(event);
}

static UINTN lock(void *context)
{
	return boot(context)->raise_tpl(8U);
}

static void unlock(void *context, UINTN state)
{
	boot(context)->restore_tpl(state);
}

static EFI_STATUS open_parent(void *context, void *controller, void **scsi_io)
{
	struct cdk2_scsi_disk_entry *entry = context;

	return boot(entry)->open_protocol(controller, &scsi_io_guid, scsi_io,
		entry->image, controller, 0x10U);
}

static EFI_STATUS close_parent(void *context, void *controller)
{
	struct cdk2_scsi_disk_entry *entry = context;

	return boot(entry)->close_protocol(controller, &scsi_io_guid, entry->image,
		controller);
}

static EFI_STATUS probe(void *context,
	struct cdk2_scsi_disk_bound_controller *bound)
{
	struct cdk2_scsi_disk_backend_services services = { .context = context,
		.allocate = allocate, .release = release, .create_event = create_event,
		.close_event = close_event, .wait_event = wait_event };
	EFI_STATUS status = cdk2_scsi_disk_backend_init(bound->backend, bound->scsi_io,
		&services, &bound->disk);

	return status;
}

static EFI_STATUS install(void *context, void *controller,
	struct cdk2_scsi_disk_bound_controller *bound)
{
	struct cdk2_scsi_disk_entry *entry = context;

	return boot(entry)->install_multiple(&controller, &block_guid,
		&bound->block.block, &block2_guid, &bound->block.block2, &disk_info_guid,
		&bound->disk_info, NULL);
}

static EFI_STATUS uninstall(void *context, void *controller,
	struct cdk2_scsi_disk_bound_controller *bound)
{
	struct cdk2_scsi_disk_entry *entry = context;

	return boot(entry)->uninstall_multiple(controller, &block_guid,
		&bound->block.block, &block2_guid, &bound->block.block2, &disk_info_guid,
		&bound->disk_info, NULL);
}

static struct cdk2_scsi_disk_entry *from_driver(
	struct cdk2_scsi_disk_driver_binding *driver)
{
	return (void *)((UINT8 *)driver - offsetof(struct cdk2_scsi_disk_entry, driver));
}

static struct cdk2_scsi_disk_entry *from_component(
	struct cdk2_scsi_disk_component_name *component)
{
	UINTN offset = component->supported_languages[2] == '\0' ?
		offsetof(struct cdk2_scsi_disk_entry, component_name2) :
		offsetof(struct cdk2_scsi_disk_entry, component_name);

	return (void *)((UINT8 *)component - offset);
}

static BOOLEAN language_matches(struct cdk2_scsi_disk_component_name *component,
	const char *language)
{
	const char *expected = component->supported_languages;

	if (language == NULL)
		return FALSE;
	while (*expected != '\0' && *expected == *language) {
		expected++;
		language++;
	}
	return *expected == '\0' && *language == '\0';
}

static EFI_STATUS CDK2_MS_ABI get_driver_name(
	struct cdk2_scsi_disk_component_name *component, const char *language,
	CHAR16 **name)
{
	if (component == NULL || name == NULL || !language_matches(component, language))
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_scsi_disk_component_name *component, void *controller, void *child,
	const char *language, CHAR16 **name)
{
	struct cdk2_scsi_disk_entry *entry;

	if (component == NULL || controller == NULL || name == NULL || child != NULL ||
	    !language_matches(component, language))
		return EFI_UNSUPPORTED;
	entry = from_component(component);
	for (UINTN index = 0; index < entry->binding.count; index++)
		if (entry->binding.controllers[index]->handle == controller) {
			*name = controller_name;
			return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED;
}

static EFI_STATUS CDK2_MS_ABI supported(
	struct cdk2_scsi_disk_driver_binding *driver, void *controller, void *remaining)
{
	struct cdk2_scsi_disk_entry *entry = from_driver(driver);
	void *io;
	EFI_STATUS status;

	(void)remaining;
	status = open_parent(entry, controller, &io);
	if (status == EFI_ALREADY_STARTED)
		return EFI_SUCCESS;
	if (!EFI_ERROR(status))
		status = close_parent(entry, controller);
	return status;
}

static EFI_STATUS CDK2_MS_ABI start(
	struct cdk2_scsi_disk_driver_binding *driver, void *controller, void *remaining)
{
	(void)remaining;
	return cdk2_scsi_disk_binding_start(&from_driver(driver)->binding, controller);
}

static EFI_STATUS CDK2_MS_ABI stop(
	struct cdk2_scsi_disk_driver_binding *driver, void *controller, UINTN children,
	void **child_buffer)
{
	(void)child_buffer;
	return children != 0U ? EFI_INVALID_PARAMETER :
		cdk2_scsi_disk_binding_stop(&from_driver(driver)->binding, controller);
}

EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_entry_unload(void *image)
{
	struct cdk2_scsi_disk_entry *entry = active;
	EFI_STATUS status;

	if (entry == NULL || entry->image != image)
		return EFI_NOT_FOUND;
	while (entry->binding.count != 0U) {
		void *controller = entry->binding.controllers[entry->binding.count - 1U]->handle;

		status = cdk2_scsi_disk_binding_stop(&entry->binding, controller);
		if (EFI_ERROR(status))
			return status;
	}
	status = boot(entry)->uninstall_multiple(entry->driver.driver_binding_handle,
		&driver_guid, &entry->driver, &component_guid, &entry->component_name,
		&component2_guid, &entry->component_name2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->loaded->unload = entry->original_unload;
	entry->published = FALSE;
	active = NULL;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_entry_publish(struct cdk2_scsi_disk_entry *entry,
	void *image, void *system)
{
	struct cdk2_scsi_disk_binding_services services;
	EFI_STATUS status;

	if (entry == NULL || image == NULL || system == NULL)
		return EFI_INVALID_PARAMETER;
	memset(entry, 0, sizeof(*entry));
	entry->image = image;
	entry->system = system;
	entry->boot = ((struct system_view *)system)->boot;
	status = boot(entry)->handle_protocol(image, &loaded_guid,
		(void **)&entry->loaded);
	if (EFI_ERROR(status))
		return status;
	entry->driver = (struct cdk2_scsi_disk_driver_binding) { supported, start,
		stop, 0x10U, image, image };
	entry->component_name = (struct cdk2_scsi_disk_component_name) {
		get_driver_name, get_controller_name, "eng" };
	entry->component_name2 = (struct cdk2_scsi_disk_component_name) {
		get_driver_name, get_controller_name, "en" };
	services = (struct cdk2_scsi_disk_binding_services) { .context = entry,
		.open_parent = open_parent, .close_parent = close_parent, .probe = probe,
		.install = install, .uninstall = uninstall, .signal = signal,
		.lock = lock, .unlock = unlock,
		.allocate = allocate, .release = release };
	status = cdk2_scsi_disk_binding_init(&entry->binding, &services);
	if (EFI_ERROR(status))
		return status;
	status = boot(entry)->install_multiple(&entry->driver.driver_binding_handle,
		&driver_guid, &entry->driver, &component_guid, &entry->component_name,
		&component2_guid, &entry->component_name2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->original_unload = entry->loaded->unload;
	entry->loaded->unload = cdk2_scsi_disk_entry_unload;
	entry->published = TRUE;
	active = entry;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_entry(void *image, void *system)
{
	return cdk2_scsi_disk_entry_publish(&image_entry, image, system);
}
