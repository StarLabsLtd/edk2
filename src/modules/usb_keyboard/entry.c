/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_keyboard.h>

#include <stddef.h>
#include <string.h>

struct guid { UINT32 a; UINT16 b, c; UINT8 d[8]; };
static const struct guid binding_guid = { 0x2d2e62cf, 0x9ecf, 0x43b7,
	{ 0x82, 0x19, 0x94, 0xe7, 0xfc, 0x71, 0x3d, 0xfe } };
static const struct guid usb_io_guid = { 0x2b2f68d6, 0x0cd2, 0x44cf,
	{ 0x8e, 0x8b, 0xbb, 0xa2, 0x0b, 0x1b, 0x5b, 0x75 } };
static const struct guid input_guid = { 0x387477c1, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid input_ex_guid = { 0xdd9e7534, 0x7762, 0x4698,
	{ 0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa } };
static const struct guid loaded_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid component_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const struct guid component2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };

typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
	event_notify_fn *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI signal_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const struct guid *, void **);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const struct guid *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const struct guid *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI unload_fn(void *);
struct boot_services {
	UINT8 header[24], before_allocate[40];
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	create_event_fn *create_event; UINT8 before_signal[16];
	signal_event_fn *signal_event;
	close_event_fn *close_event;
	UINT8 before_handle[32]; handle_fn * handle_protocol;
	UINT8 before_open[120]; open_fn * open_protocol; close_fn * close_protocol;
	UINT8 before_install[32]; install_fn * install_multiple;
	uninstall_fn *uninstall_multiple;
};
struct system_table { UINT8 before_boot[96]; struct boot_services *boot; };
struct loaded_image { UINT8 before_unload[88]; unload_fn * unload; };
struct driver_binding;
typedef EFI_STATUS CDK2_MS_ABI supported_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI start_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI stop_fn(struct driver_binding *, void *, UINTN, void **);
struct driver_binding { supported_fn * supported; start_fn * start;
	stop_fn *stop;
	UINT32 version; void *image, *handle; };
typedef EFI_STATUS CDK2_MS_ABI driver_name_fn(void *, CHAR8 *, CHAR16 * *);
typedef EFI_STATUS CDK2_MS_ABI controller_name_fn(void *, void *, void *, CHAR8 *,
	CHAR16 * *);
struct component_name { driver_name_fn * driver_name;
	controller_name_fn *controller_name;
	CHAR8 *languages;
};

typedef char allocate_offset_check[offsetof(struct boot_services,
	allocate_pool) == 64U ? 1 : -1];
typedef char create_offset_check[offsetof(struct boot_services,
	create_event) == 80U ? 1 : -1];
typedef char signal_offset_check[offsetof(struct boot_services,
	signal_event) == 104U ? 1 : -1];
typedef char handle_offset_check[offsetof(struct boot_services,
	handle_protocol) == 152U ? 1 : -1];
typedef char open_offset_check[offsetof(struct boot_services,
	open_protocol) == 280U ? 1 : -1];
typedef char install_offset_check[offsetof(struct boot_services,
	install_multiple) == 328U ? 1 : -1];

static struct boot_services *bs;
static struct loaded_image *loaded;
static struct cdk2_usb_keyboard_binding keyboard_binding;
static struct driver_binding binding;
static struct component_name component, component2;
static unload_fn *original_unload;
static CHAR16 driver_name[] = L"USB Keyboard Driver";
static CHAR16 controller_name[] = L"USB Keyboard";

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; return bs->allocate_pool(4U, size, buffer); }
static void release(void *context, void *buffer)
{ (void)context; (void)bs->free_pool(buffer); }
static EFI_STATUS open_usb(void *context, void *controller,
	struct cdk2_usb_io_protocol **usb)
{ (void)context; return bs->open_protocol(controller, &usb_io_guid, (void **)usb,
	binding.handle, controller, 0x10U); }
static EFI_STATUS close_usb(void *context, void *controller)
{ (void)context; return bs->close_protocol(controller, &usb_io_guid,
	binding.handle, controller); }
static void CDK2_MS_ABI wait_notify(void *event, void *context)
{
	struct cdk2_usb_keyboard_controller *owner = context;

	if (owner != NULL && owner->device.keyboard.count != 0U)
		(void)bs->signal_event(event);
}
static EFI_STATUS create_wait(void *context,
	struct cdk2_usb_keyboard_controller *owner, BOOLEAN extended, void **event)
{ (void)context; (void)extended;
	return bs->create_event(0x100U, 16U, wait_notify, owner, event); }
static EFI_STATUS close_wait(void *context, void *event)
{ (void)context; return bs->close_event(event); }
static EFI_STATUS publish(void *context, void *controller,
	struct cdk2_usb_keyboard_controller *owner)
{ void *handle = controller; (void)context;
	return bs->install_multiple(&handle, &input_guid, &owner->device.input,
		&input_ex_guid, &owner->device.input_ex, NULL); }
static EFI_STATUS remove_owner(void *context, void *controller,
	struct cdk2_usb_keyboard_controller *owner)
{ (void)context; return bs->uninstall_multiple(controller, &input_guid,
	&owner->device.input, &input_ex_guid, &owner->device.input_ex, NULL); }

static EFI_STATUS CDK2_MS_ABI supported(struct driver_binding *driver,
	void *controller, void *remaining)
{ (void)driver; (void)remaining;
	return cdk2_usb_keyboard_binding_supported(&keyboard_binding, controller); }
static EFI_STATUS CDK2_MS_ABI start(struct driver_binding *driver,
	void *controller, void *remaining)
{ (void)driver; (void)remaining;
	return cdk2_usb_keyboard_binding_start(&keyboard_binding, controller); }
static EFI_STATUS CDK2_MS_ABI stop(struct driver_binding *driver,
	void *controller, UINTN count, void **children)
{ (void)driver; (void)children; return count == 0U ?
	cdk2_usb_keyboard_binding_stop(&keyboard_binding, controller) :
	EFI_INVALID_PARAMETER; }
static BOOLEAN language_equal(const CHAR8 *left, const CHAR8 *right)
{ while (*left != 0 && *left == *right) { left++; right++; }
	return *left == *right; }
static EFI_STATUS CDK2_MS_ABI get_driver_name(void *this, CHAR8 *language,
	CHAR16 **name)
{ if (language == NULL || name == NULL) return EFI_INVALID_PARAMETER;
	if ((this == &component && !language_equal(language, "eng")) ||
	    (this == &component2 && !language_equal(language, "en")))
		return EFI_UNSUPPORTED;
	*name = driver_name; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI get_controller_name(void *this, void *controller,
	void *child, CHAR8 *language, CHAR16 **name)
{ (void)child; if (controller == NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if ((this == &component && !language_equal(language, "eng")) ||
	    (this == &component2 && !language_equal(language, "en")))
		return EFI_UNSUPPORTED;
	for (UINTN index = 0U; index < keyboard_binding.count; index++)
		if (keyboard_binding.controllers[index]->handle == controller) {
			*name = controller_name; return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED; }
static EFI_STATUS CDK2_MS_ABI unload(void *image)
{
	while (keyboard_binding.count != 0U) {
		EFI_STATUS status = cdk2_usb_keyboard_binding_stop(&keyboard_binding,
			keyboard_binding.controllers[keyboard_binding.count - 1U]->handle);
		if (EFI_ERROR(status))
			return status;
	}
	if (EFI_ERROR(bs->uninstall_multiple(binding.handle, &binding_guid, &binding,
	    &component_guid, &component, &component2_guid, &component2, NULL)))
		return EFI_DEVICE_ERROR;
	loaded->unload = original_unload; (void)image; return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_usb_keyboard_entry(void *image,
	struct system_table *system)
{
	struct cdk2_usb_keyboard_binding_services services = { .open = open_usb,
		.close = close_usb, .create_event = create_wait,
		.close_event = close_wait, .publish = publish, .remove = remove_owner,
		.allocate = allocate, .release = release };
	EFI_STATUS status;

	if (image == NULL || system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	bs = system->boot;
	status = bs->handle_protocol(image, &loaded_guid, (void **)&loaded);
	if (!EFI_ERROR(status))
		status = cdk2_usb_keyboard_binding_init(&keyboard_binding, &services);
	if (EFI_ERROR(status))
		return status;
	binding = (struct driver_binding) { supported, start, stop, 0x10U,
		image, image };
	component = (struct component_name) { get_driver_name, get_controller_name,
		"eng" };
	component2 = (struct component_name) { get_driver_name, get_controller_name,
		"en" };
	status = bs->install_multiple(&binding.handle, &binding_guid, &binding,
		&component_guid, &component, &component2_guid, &component2, NULL);
	if (EFI_ERROR(status))
		return status;
	original_unload = loaded->unload; loaded->unload = unload;
	return EFI_SUCCESS;
}
