/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_bus.h>

#include <stddef.h>
#include <string.h>

struct guid { UINT32 a; UINT16 b, c; UINT8 d[8]; };
static const struct guid driver_guid = { 0x240612b7, 0xa063, 0x11d4,
	{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const struct guid host_guid = { 0x3e745226, 0x9818, 0x45b6,
	{ 0xa2, 0xac, 0xd7, 0xcd, 0x0e, 0x8b, 0xa2, 0xbc } };
static const struct guid path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid usb_io_guid = { 0x2b2f68d6, 0x0cd2, 0x44cf,
	{ 0x8e, 0x8b, 0xbb, 0xa2, 0x0b, 0x1b, 0x5b, 0x75 } };
static const struct guid loaded_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid component_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const struct guid component2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };

typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const struct guid *, void **);
typedef void CDK2_MS_ABI stall_fn(UINTN);
typedef EFI_STATUS CDK2_MS_ABI connect_fn(void *, void **, void *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const struct guid *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const struct guid *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI unload_fn(void *);
struct boot_services {
	UINT8 before_allocate[64]; allocate_fn * allocate_pool; free_fn * free_pool;
	UINT8 before_handle[72]; handle_fn * handle_protocol;
	UINT8 before_stall[88]; stall_fn * stall; UINT8 before_connect[8];
	connect_fn *connect_controller; UINT8 before_open[8]; open_fn * open_protocol;
	close_fn *close_protocol; UINT8 before_install[32];
	install_fn *install_multiple; uninstall_fn * uninstall_multiple;
};
struct system_table { UINT8 before_boot[96]; struct boot_services *boot; };
struct loaded_image { UINT8 before_unload[88]; unload_fn * unload; };
struct driver_binding;
typedef EFI_STATUS CDK2_MS_ABI supported_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI start_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI stop_fn(struct driver_binding *, void *, UINTN, void **);
struct driver_binding { supported_fn * supported; start_fn * start; stop_fn * stop;
	UINT32 version; void *image, *handle; };
typedef EFI_STATUS CDK2_MS_ABI driver_name_fn(void *, CHAR8 *, CHAR16 * *);
typedef EFI_STATUS CDK2_MS_ABI controller_name_fn(void *, void *, void *, CHAR8 *,
	CHAR16 * *);
struct component_name { driver_name_fn * driver_name;
	controller_name_fn *controller_name; CHAR8 * languages; };

typedef char connect_offset_check[offsetof(struct boot_services,
	connect_controller) == 264U ? 1 : -1];
typedef char open_offset_check[offsetof(struct boot_services, open_protocol) == 280U ? 1 : -1];
typedef char install_offset_check[offsetof(struct boot_services,
	install_multiple) == 328U ? 1 : -1];

static struct boot_services *bs;
static struct loaded_image *loaded;
static struct cdk2_usb_binding usb_binding;
static struct driver_binding binding;
static struct component_name component, component2;
static unload_fn *original_unload;
static CHAR16 driver_name[] = L"USB Bus Driver";
static CHAR16 controller_name[] = L"USB Host Controller";
static CHAR16 child_name[] = L"USB Device";

static BOOLEAN language_equal(const CHAR8 *left, const CHAR8 *right)
{
	while (*left != 0 && *left == *right) {
		left++;
		right++;
	}
	return *left == *right;
}

static void delay(void *context, UINTN microseconds)
{ (void)context; bs->stall(microseconds); }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; return bs->allocate_pool(4U, size, buffer); }
static void release(void *context, void *buffer)
{ (void)context; (void)bs->free_pool(buffer); }
static EFI_STATUS open_host(void *context, void *controller,
	struct cdk2_usb2_hc_protocol **host)
{ (void)context; return bs->open_protocol(controller, &host_guid, (void **)host,
	binding.handle, controller, 0x10U); }
static EFI_STATUS close_host(void *context, void *controller)
{ (void)context; return bs->close_protocol(controller, &host_guid, binding.handle,
	controller); }
static EFI_STATUS marker_install(void *context, void *controller, void *marker)
{ (void)context; return bs->install_multiple(&controller, &driver_guid, marker, NULL); }
static EFI_STATUS marker_remove(void *context, void *controller, void *marker)
{ (void)context; return bs->uninstall_multiple(controller, &driver_guid, marker, NULL); }

static EFI_STATUS parent_path(void *controller, void **path, UINTN *size)
{
	UINT8 *bytes;
	EFI_STATUS status;
	UINTN offset = 0U;

	status = bs->open_protocol(controller, &path_guid, path, binding.handle,
		controller, 0x02U);
	if (EFI_ERROR(status))
		return status;
	bytes = *path;
	while (offset <= 4092U) {
		UINT16 length = bytes[offset + 2U] | (UINT16)bytes[offset + 3U] << 8;

		if (length < 4U || length > 4096U - offset)
			return EFI_COMPROMISED_DATA;
		if (bytes[offset] == 0x7fU && bytes[offset + 1U] == 0xffU) {
			*size = offset;
			return EFI_SUCCESS;
		}
		offset += length;
	}
	return EFI_COMPROMISED_DATA;
}

static EFI_STATUS publish_child(void *context, void *controller,
	struct cdk2_usb_child *child, void **handle)
{
	static const UINT8 end[4] = { 0x7fU, 0xffU, 4U, 0U };
	void *parent;
	UINT8 *path;
	UINTN size;
	EFI_STATUS status;

	(void)context;
	status = parent_path(controller, &parent, &size);
	if (EFI_ERROR(status))
		return status;
	status = bs->allocate_pool(4U, size + sizeof(child->path) + sizeof(end),
		(void **)&path);
	if (EFI_ERROR(status))
		return status;
	memcpy(path, parent, size);
	memcpy(path + size, &child->path, sizeof(child->path));
	memcpy(path + size + sizeof(child->path), end, sizeof(end));
	child->device_path = path;
	*handle = NULL;
	status = bs->install_multiple(handle, &path_guid, path, &usb_io_guid,
		&child->io.protocol, NULL);
	if (EFI_ERROR(status)) {
		child->device_path = NULL;
		(void)bs->free_pool(path);
	} else {
		(void)bs->connect_controller(*handle, NULL, NULL, TRUE);
	}
	return status;
}

static EFI_STATUS remove_child(void *context, void *controller,
	struct cdk2_usb_child *child, void *handle)
{
	EFI_STATUS status;

	(void)context; (void)controller;
	status = bs->uninstall_multiple(handle, &path_guid, child->device_path,
		&usb_io_guid, &child->io.protocol, NULL);
	if (!EFI_ERROR(status)) {
		(void)bs->free_pool(child->device_path);
		child->device_path = NULL;
	}
	return status;
}
static EFI_STATUS link_child(void *context, void *controller, void *child)
{ void *host; (void)context; return bs->open_protocol(controller, &host_guid, &host,
	binding.handle, child, 0x08U); }
static EFI_STATUS unlink_child(void *context, void *controller, void *child)
{ (void)context; return bs->close_protocol(controller, &host_guid, binding.handle,
	child); }

static EFI_STATUS CDK2_MS_ABI supported(struct driver_binding *driver,
	void *controller, void *remaining)
{ (void)driver; (void)remaining;
	return cdk2_usb_binding_supported(&usb_binding, controller); }
static EFI_STATUS CDK2_MS_ABI start(struct driver_binding *driver,
	void *controller, void *remaining)
{ (void)driver; (void)remaining; return cdk2_usb_binding_start(&usb_binding,
	controller); }
static EFI_STATUS CDK2_MS_ABI stop(struct driver_binding *driver,
	void *controller, UINTN count, void **children)
{ (void)driver; return cdk2_usb_binding_stop(&usb_binding, controller, count,
	children); }

static EFI_STATUS CDK2_MS_ABI get_driver_name(void *this, CHAR8 *language,
	CHAR16 **name)
{
	if (language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if ((this == &component && !language_equal(language, "eng")) ||
	    (this == &component2 && !language_equal(language, "en")))
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_controller_name(void *this, void *controller,
	void *child, CHAR8 *language, CHAR16 **name)
{
	if (controller == NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if ((this == &component && !language_equal(language, "eng")) ||
	    (this == &component2 && !language_equal(language, "en")))
		return EFI_UNSUPPORTED;
	for (UINTN index = 0U; index < usb_binding.count; index++)
		if (usb_binding.controllers[index].handle == controller) {
			if (child != NULL) {
				UINTN item = 0U;
				while (item < usb_binding.controllers[index].bus->child_count &&
				       usb_binding.controllers[index].bus->children[item].handle != child)
					item++;
				if (item == usb_binding.controllers[index].bus->child_count)
					return EFI_UNSUPPORTED;
			}
			*name = child == NULL ? controller_name : child_name;
			return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED;
}

static EFI_STATUS CDK2_MS_ABI unload(void *image)
{
	while (usb_binding.count != 0U) {
		EFI_STATUS status = cdk2_usb_binding_stop(&usb_binding,
			usb_binding.controllers[usb_binding.count - 1U].handle, 0U, NULL);

		if (EFI_ERROR(status))
			return status;
	}
	if (EFI_ERROR(bs->uninstall_multiple(binding.handle, &driver_guid, &binding,
		&component_guid, &component, &component2_guid, &component2, NULL)))
		return EFI_DEVICE_ERROR;
	loaded->unload = original_unload;
	(void)image;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_usb_bus_entry(void *image, struct system_table *system)
{
	struct cdk2_usb_binding_services services = { .open_host = open_host,
		.close_host = close_host, .install_marker = marker_install,
		.uninstall_marker = marker_remove, .publish_child = publish_child,
		.remove_child = remove_child, .link_child = link_child,
		.unlink_child = unlink_child, .allocate = allocate, .free = release,
		.delay = delay };
	EFI_STATUS status;

	if (image == NULL || system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	bs = system->boot;
	status = bs->handle_protocol(image, &loaded_guid, (void **)&loaded);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_usb_binding_init(&usb_binding, &services);
	if (EFI_ERROR(status))
		return status;
	binding = (struct driver_binding) { supported, start, stop, 0x10U, image, image };
	component = (struct component_name) { get_driver_name, get_controller_name, "eng" };
	component2 = (struct component_name) { get_driver_name, get_controller_name, "en" };
	status = bs->install_multiple(&binding.handle, &driver_guid, &binding,
		&component_guid, &component, &component2_guid, &component2, NULL);
	if (EFI_ERROR(status))
		return status;
	original_unload = loaded->unload;
	loaded->unload = unload;
	return EFI_SUCCESS;
}
