/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/xhci.h>

#include <stddef.h>
#include <string.h>

struct guid { UINT32 a; UINT16 b, c; UINT8 d[8]; };
static const struct guid driver_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const struct guid pci_guid = { 0x4cf5b200, 0x68b8, 0x4ca5,
	{ 0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a } };
static const struct guid path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid usb2_guid = { 0x3e745226, 0x9818, 0x45b6,
	{ 0xa2, 0xac, 0xd7, 0xcd, 0x0e, 0x8b, 0xa2, 0xbc } };
static const struct guid loaded_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid component_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const struct guid component2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };

typedef EFI_STATUS CDK2_MS_ABI raise_fn(UINTN);
typedef void CDK2_MS_ABI restore_fn(UINTN);
typedef EFI_STATUS CDK2_MS_ABI alloc_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
	event_notify_fn *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI set_timer_fn(void *, UINTN, UINT64);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef void CDK2_MS_ABI stall_fn(UINTN);
typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const struct guid *, void **);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const struct guid *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const struct guid *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI unload_fn(void *);
struct boot_services {
	UINT8 header[24]; raise_fn * raise_tpl; restore_fn * restore_tpl;
	UINT8 before_allocate[24]; alloc_fn * allocate_pool; free_fn * free_pool;
	create_event_fn *create_event;
	set_timer_fn *set_timer;
	UINT8 before_close_event[16]; close_event_fn * close_event;
	UINT8 before_handle[32]; handle_fn * handle_protocol;
	UINT8 before_stall[88]; stall_fn * stall;
	UINT8 before_open[24]; open_fn * open_protocol; close_fn * close_protocol;
	UINT8 before_install[32]; install_fn * install_multiple;
	uninstall_fn *uninstall_multiple;
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
struct context { struct cdk2_xhci_pci_adapter adapter;
	struct cdk2_xhci_controller controller; struct cdk2_xhci_usb2 *usb2;
	void *handle, *timer; struct context *next; };

typedef char stall_offset_check[offsetof(struct boot_services, stall) == 248U ? 1 : -1];
typedef char create_offset_check[offsetof(struct boot_services, create_event) == 80U ? 1 : -1];
typedef char close_event_offset_check[offsetof(struct boot_services, close_event) == 112U ? 1 : -1];
typedef char open_offset_check[offsetof(struct boot_services, open_protocol) == 280U ? 1 : -1];
typedef char install_offset_check[offsetof(struct boot_services, install_multiple) == 328U ? 1 : -1];

static struct boot_services *bs;
static struct loaded_image *loaded;
static struct context *managed;
static struct driver_binding binding;
static struct component_name component, component2;
static unload_fn *original_unload;
static CHAR16 driver_name[] = L"XHCI Host Controller Driver";
static CHAR16 controller_name[] = L"XHCI Host Controller";

static void delay(void *unused, UINTN microseconds)
{
	(void)unused;
	bs->stall(microseconds);
}

static void CDK2_MS_ABI timer_notify(void *event, void *opaque)
{
	(void)event;
	cdk2_xhci_usb2_poll(((struct context *)opaque)->usb2);
}

static BOOLEAN language_equal(const CHAR8 *left, const CHAR8 *right)
{
	while (*left != 0 && *left == *right) {
		left++;
		right++;
	}
	return *left == *right;
}

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
	struct context *context = managed;

	if (controller == NULL || child != NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if ((this == &component && !language_equal(language, "eng")) ||
	    (this == &component2 && !language_equal(language, "en")))
		return EFI_UNSUPPORTED;
	while (context != NULL && context->handle != controller)
		context = context->next;
	if (context == NULL)
		return EFI_UNSUPPORTED;
	*name = controller_name;
	return EFI_SUCCESS;
}

static EFI_STATUS read_capability(struct cdk2_efi_pci_io_protocol *pci,
	struct cdk2_xhci_capabilities *capability)
{
	UINT32 values[7];
	EFI_STATUS status;

	status = pci->mem.read(pci, 2U, 0U, 0U, 1U, &values[0]);
	if (!EFI_ERROR(status))
		status = pci->mem.read(pci, 2U, 0U, 4U, 1U, &values[1]);
	if (!EFI_ERROR(status))
		status = pci->mem.read(pci, 2U, 0U, 8U, 1U, &values[2]);
	if (!EFI_ERROR(status))
		status = pci->mem.read(pci, 2U, 0U, 0x10U, 1U, &values[3]);
	if (!EFI_ERROR(status))
		status = pci->mem.read(pci, 2U, 0U, 0x14U, 1U, &values[4]);
	if (!EFI_ERROR(status))
		status = pci->mem.read(pci, 2U, 0U, 0x18U, 1U, &values[5]);
	if (!EFI_ERROR(status))
		status = pci->mem.read(pci, 2U, 0U, (values[0] & 0xffU) + 8U,
			1U, &values[6]);
	return EFI_ERROR(status) ? status : cdk2_xhci_parse_capabilities(values[0],
		values[1], values[2], values[3], values[4], values[5], values[6], capability);
}

static EFI_STATUS CDK2_MS_ABI supported(struct driver_binding *driver,
	void *controller, void *remaining)
{
	struct cdk2_efi_pci_io_protocol *pci;
	void *path;
	UINT8 class_code[3];
	EFI_STATUS status;

	(void)remaining;
	status = bs->open_protocol(controller, &pci_guid, (void **)&pci, driver->handle,
		controller, 0x10U);
	if (EFI_ERROR(status))
		return status;
	(void)bs->close_protocol(controller, &pci_guid, driver->handle, controller);
	status = bs->open_protocol(controller, &path_guid, &path, driver->handle,
		controller, 0x02U);
	if (EFI_ERROR(status))
		return status;
	status = bs->open_protocol(controller, &pci_guid, (void **)&pci, driver->handle,
		controller, 0x02U);
	if (!EFI_ERROR(status))
		status = pci->pci.read(pci, 0U, 9U, 3U, class_code);
	return !EFI_ERROR(status) && class_code[0] == 0x30U &&
		class_code[1] == 0x03U && class_code[2] == 0x0cU ?
		EFI_SUCCESS : EFI_UNSUPPORTED;
}

static EFI_STATUS CDK2_MS_ABI start(struct driver_binding *driver, void *handle,
	void *remaining)
{
	struct cdk2_xhci_controller_services services;
	struct cdk2_xhci_capabilities capability;
	struct cdk2_efi_pci_io_protocol *pci;
	struct context *context;
	EFI_STATUS status;

	(void)remaining;
	status = bs->open_protocol(handle, &pci_guid, (void **)&pci, driver->handle,
		handle, 0x10U);
	if (EFI_ERROR(status))
		return status;
	status = bs->allocate_pool(4U, sizeof(*context), (void **)&context);
	if (EFI_ERROR(status))
		goto close;
	memset(context, 0, sizeof(*context));
	context->handle = handle;
	status = bs->allocate_pool(4U, sizeof(*context->usb2),
		(void **)&context->usb2);
	if (EFI_ERROR(status))
		goto free_context;
	status = cdk2_xhci_pci_adapter_init(&context->adapter, pci, 0U, NULL, delay);
	if (EFI_ERROR(status))
		goto free_usb;
	status = read_capability(pci, &capability);
	if (EFI_ERROR(status))
		goto release_adapter;
	cdk2_xhci_pci_controller_services(&context->adapter, &services);
	status = cdk2_xhci_controller_init(&context->controller, &services, &capability);
	if (EFI_ERROR(status))
		goto release_adapter;
	status = cdk2_xhci_usb2_init(context->usb2, &context->controller);
	if (EFI_ERROR(status))
		goto destroy_controller;
	status = bs->create_event(0x80000200U, 8U, timer_notify, context,
		&context->timer);
	if (!EFI_ERROR(status))
		status = bs->set_timer(context->timer, 1U, 100000U);
	if (EFI_ERROR(status))
		goto close_timer;
	status = bs->install_multiple(&handle, &usb2_guid,
		&context->usb2->protocol, NULL);
	if (EFI_ERROR(status))
		goto release_usb;
	context->next = managed;
	managed = context;
	return EFI_SUCCESS;
release_usb:
	(void)cdk2_xhci_usb2_release(context->usb2);
close_timer:
	if (context->timer != NULL)
		(void)bs->close_event(context->timer);
destroy_controller:
	cdk2_xhci_controller_destroy(&context->controller);
release_adapter:
	(void)cdk2_xhci_pci_adapter_release(&context->adapter);
free_usb:
	(void)bs->free_pool(context->usb2);
free_context:
	(void)bs->free_pool(context);
close:
	(void)bs->close_protocol(handle, &pci_guid, driver->handle, handle);
	return status;
}

static EFI_STATUS CDK2_MS_ABI stop(struct driver_binding *driver, void *handle,
	UINTN children, void **child_handles)
{
	struct context **owner = &managed;
	struct context *context;
	EFI_STATUS status;

	(void)children;
	(void)child_handles;
	while (*owner != NULL && (*owner)->handle != handle)
		owner = &(*owner)->next;
	if (*owner == NULL)
		return EFI_UNSUPPORTED;
	context = *owner;
	status = bs->uninstall_multiple(handle, &usb2_guid,
		&context->usb2->protocol, NULL);
	if (EFI_ERROR(status))
		return status;
	status = bs->close_event(context->timer);
	if (EFI_ERROR(status)) {
		(void)bs->install_multiple(&handle, &usb2_guid,
			&context->usb2->protocol, NULL);
		return status;
	}
	context->timer = NULL;
	status = cdk2_xhci_usb2_release(context->usb2);
	if (EFI_ERROR(status)) {
		if (!EFI_ERROR(bs->create_event(0x80000200U, 8U, timer_notify, context,
			&context->timer)))
			(void)bs->set_timer(context->timer, 1U, 100000U);
		(void)bs->install_multiple(&handle, &usb2_guid,
			&context->usb2->protocol, NULL);
		return status;
	}
	*owner = context->next;
	cdk2_xhci_controller_destroy(&context->controller);
	(void)cdk2_xhci_pci_adapter_release(&context->adapter);
	(void)bs->free_pool(context->usb2);
	(void)bs->free_pool(context);
	return bs->close_protocol(handle, &pci_guid, driver->handle, handle);
}

static EFI_STATUS CDK2_MS_ABI unload(void *image)
{
	EFI_STATUS status;

	while (managed != NULL) {
		status = stop(&binding, managed->handle, 0U, NULL);
		if (EFI_ERROR(status))
			return status;
	}
	status = bs->uninstall_multiple(binding.handle, &driver_guid, &binding,
		&component_guid, &component, &component2_guid, &component2, NULL);
	if (EFI_ERROR(status))
		return status;
	loaded->unload = original_unload;
	(void)image;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_xhci_entry(void *image, struct system_table *system)
{
	EFI_STATUS status;

	if (image == NULL || system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	bs = system->boot;
	status = bs->handle_protocol(image, &loaded_guid, (void **)&loaded);
	if (EFI_ERROR(status))
		return status;
	binding = (struct driver_binding) { supported, start, stop, 0x10U,
		image, image };
	component = (struct component_name) { get_driver_name, get_controller_name,
		"eng" };
	component2 = (struct component_name) { get_driver_name, get_controller_name,
		"en" };
	status = bs->install_multiple(&binding.handle, &driver_guid, &binding,
		&component_guid, &component, &component2_guid, &component2, NULL);
	if (EFI_ERROR(status))
		return status;
	original_unload = loaded->unload;
	loaded->unload = unload;
	return EFI_SUCCESS;
}
