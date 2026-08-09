/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_entry.h>

#include <stddef.h>
#include <string.h>

struct guid { UINT32 data1; UINT16 data2, data3; UINT8 data4[8]; };
typedef EFI_STATUS CDK2_MS_ABI handle_t(void *, const struct guid *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_t(void **, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_t(void *, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI open_t(void *, const struct guid *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_t(void *, const struct guid *, void *, void *);
struct cdk2_ata_boot_services {
	UINT8 before_handle[152]; handle_t *handle_protocol;
	UINT8 before_open[120]; open_t *open_protocol; close_t *close_protocol;
	UINT8 before_install[32]; install_t *install_multiple;
	uninstall_t *uninstall_multiple;
};
struct system_table_view {
	UINT8 header[24]; cdk2_char16_t *vendor; UINT32 revision, pad;
	void *console[6], *runtime; struct cdk2_ata_boot_services *boot;
};
typedef char handle_offset_check[offsetof(struct cdk2_ata_boot_services,
	handle_protocol) == 152 ? 1 : -1];
typedef char install_offset_check[offsetof(struct cdk2_ata_boot_services,
	install_multiple) == 328 ? 1 : -1];
typedef char uninstall_offset_check[offsetof(struct cdk2_ata_boot_services,
	uninstall_multiple) == 336 ? 1 : -1];
typedef char open_offset_check[offsetof(struct cdk2_ata_boot_services,
	open_protocol) == 280 ? 1 : -1];
typedef char close_offset_check[offsetof(struct cdk2_ata_boot_services,
	close_protocol) == 288 ? 1 : -1];

static const struct guid loaded_image_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const struct guid component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const struct guid component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const struct guid device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid pci_io_guid = { 0x4cf5b200, 0x68b8, 0x4ca5,
	{ 0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a } };
static const struct guid ide_init_guid = { 0xa1e37052, 0x80d9, 0x4e65,
	{ 0xa3, 0x17, 0x3e, 0x9a, 0x55, 0xc4, 0x3e, 0xc9 } };
static CHAR16 driver_name[] = L"ATA/ATAPI Pass Thru Driver";
static CHAR16 controller_name[] = L"ATA/ATAPI Controller";
static struct cdk2_ata_entry *active_entry;

static EFI_STATUS open_protocol(struct cdk2_ata_entry *entry, void *controller,
	const struct guid *guid, void **interface, UINT32 attributes)
{
	return entry->boot->open_protocol(controller, guid, interface, entry->image,
		controller, attributes);
}
static EFI_STATUS service_open_path(void *opaque, void *controller)
{
	struct cdk2_ata_entry *entry = active_entry;
	void *path = NULL;

	(void)opaque;
	if (entry == NULL)
		return EFI_NOT_READY;
	return open_protocol(entry, controller, &device_path_guid, &path, 0x10U);
}
static EFI_STATUS service_close_path(void *opaque, void *controller)
{
	struct cdk2_ata_entry *entry = active_entry;

	(void)opaque;
	if (entry == NULL)
		return EFI_NOT_READY;
	return entry->boot->close_protocol(controller,
		&device_path_guid, entry->image, controller);
}
static EFI_STATUS service_open_ide(void *opaque, void *controller, void **ide)
{
	(void)opaque;
	return active_entry == NULL ? EFI_NOT_READY :
		open_protocol(active_entry, controller, &ide_init_guid, ide, 0x10U);
}
static EFI_STATUS service_close_ide(void *opaque, void *controller)
{
	struct cdk2_ata_entry *entry = active_entry;

	(void)opaque;
	if (entry == NULL)
		return EFI_NOT_READY;
	return entry->boot->close_protocol(controller,
		&ide_init_guid, entry->image, controller);
}
static EFI_STATUS service_get_pci(void *opaque, void *controller, void **pci)
{
	(void)opaque;
	return active_entry == NULL ? EFI_NOT_READY :
		open_protocol(active_entry, controller, &pci_io_guid, pci, 0x02U);
}

static struct cdk2_ata_entry *from_driver(struct cdk2_ata_driver_binding *driver)
{ return (struct cdk2_ata_entry *)((UINT8 *)driver - offsetof(struct cdk2_ata_entry, driver)); }
static EFI_STATUS CDK2_MS_ABI supported(struct cdk2_ata_driver_binding *driver,
	void *controller, void *remaining)
{ (void)remaining; return cdk2_ata_binding_supported(from_driver(driver)->binding,
	controller); }
static EFI_STATUS CDK2_MS_ABI start(struct cdk2_ata_driver_binding *driver,
	void *controller, void *remaining)
{ (void)remaining; return cdk2_ata_binding_start(from_driver(driver)->binding, controller); }
static EFI_STATUS CDK2_MS_ABI stop(struct cdk2_ata_driver_binding *driver,
	void *controller, UINTN children, void **child_buffer)
{
	if (children != 0U || child_buffer != NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_ata_binding_stop(from_driver(driver)->binding, controller);
}
static int language_equal(const CHAR8 *left, const CHAR8 *right)
{
	if (left == NULL || right == NULL)
		return 0;
	while (*left != 0 && *left == *right) {
		left++;
		right++;
	}
	return *left == *right;
}
static EFI_STATUS CDK2_MS_ABI get_driver_name(struct cdk2_ata_component_name *protocol,
	CHAR8 *language, CHAR16 **name)
{
	if (protocol == NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (!language_equal(language, protocol->languages))
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_ata_component_name *protocol, void *controller, void *child,
	CHAR8 *language, CHAR16 **name)
{
	struct cdk2_ata_entry *entry = (struct cdk2_ata_entry *)((UINT8 *)protocol -
		(protocol->languages[0] == 'e' && protocol->languages[1] == 'n' &&
		 protocol->languages[2] == 0 ? offsetof(struct cdk2_ata_entry, component2) :
		offsetof(struct cdk2_ata_entry, component)));
	if (controller == NULL || child != NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (!language_equal(language, protocol->languages) ||
	    entry->binding == NULL || entry->binding->count == 0U)
		return EFI_UNSUPPORTED;
	for (size_t index = 0; index < entry->binding->count; index++)
		if (entry->binding->controllers[index].handle == controller) {
			*name = controller_name;
			return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED;
}

EFI_STATUS cdk2_ata_entry_publish(struct cdk2_ata_entry *entry,
	struct cdk2_ata_binding *binding, void *image, void *system_table)
{
	struct system_table_view *system = system_table; EFI_STATUS status;
	if (entry == NULL || binding == NULL || image == NULL || system == NULL ||
	    system->boot == NULL || active_entry != NULL)
		return EFI_INVALID_PARAMETER;
	memset(entry, 0, sizeof(*entry)); entry->binding = binding; entry->image = image;
	entry->boot = system->boot;
	status = entry->boot->handle_protocol(image, &loaded_image_guid,
		(void **)&entry->loaded);
	if (EFI_ERROR(status) || entry->loaded == NULL)
		return EFI_ERROR(status) ? status : EFI_NOT_FOUND;
	entry->driver = (struct cdk2_ata_driver_binding) { supported, start, stop,
		0x10U, image, NULL };
	entry->component = (struct cdk2_ata_component_name) {
		get_driver_name, get_controller_name, "eng" };
	entry->component2 = (struct cdk2_ata_component_name) {
		get_driver_name, get_controller_name, "en" };
	status = entry->boot->install_multiple(&entry->driver_handle,
		&driver_binding_guid, &entry->driver, &component_name_guid, &entry->component,
		&component_name2_guid, &entry->component2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->driver.handle = entry->driver_handle;
	entry->original_unload = entry->loaded->unload;
	entry->loaded->unload = cdk2_ata_entry_unload;
	entry->published = 1; active_entry = entry;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_entry_publish_with_services(struct cdk2_ata_entry *entry,
	struct cdk2_ata_binding *binding,
	const struct cdk2_ata_binding_services *hardware_services,
	void *image, void *system_table)
{
	struct cdk2_ata_binding_services services;
	EFI_STATUS status;

	if (binding == NULL || hardware_services == NULL)
		return EFI_INVALID_PARAMETER;
	services = *hardware_services;
	services.open_path = service_open_path;
	services.close_path = service_close_path;
	services.open_ide = service_open_ide;
	services.close_ide = service_close_ide;
	services.get_pci = service_get_pci;
	status = cdk2_ata_binding_init(binding, &services);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_ata_entry_publish(entry, binding, image, system_table);
	if (EFI_ERROR(status))
		memset(binding, 0, sizeof(*binding));
	return status;
}

EFI_STATUS CDK2_MS_ABI cdk2_ata_entry_unload(void *image)
{
	struct cdk2_ata_entry *entry = active_entry; EFI_STATUS status;
	if (entry == NULL || image != entry->image || !entry->published)
		return EFI_INVALID_PARAMETER;
	while (entry->binding->count != 0U) {
		void *controller = entry->binding->controllers[entry->binding->count - 1U].handle;
		status = cdk2_ata_binding_stop(entry->binding, controller);
		if (EFI_ERROR(status))
			return status;
	}
	status = entry->boot->uninstall_multiple(entry->driver_handle,
		&driver_binding_guid, &entry->driver, &component_name_guid, &entry->component,
		&component_name2_guid, &entry->component2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->loaded->unload = entry->original_unload;
	entry->published = 0; active_entry = NULL;
	return EFI_SUCCESS;
}
