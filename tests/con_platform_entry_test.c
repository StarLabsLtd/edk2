/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_platform_entry.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI locate_device_path_fn(const EFI_GUID *, void **, void **);
typedef EFI_STATUS CDK2_MS_ABI handle_protocol_fn(void *, const EFI_GUID *, void **);

struct boot_services {
	UINT8 header[24];
	void *raise_tpl, *restore_tpl, *allocate_pages, *free_pages, *get_memory_map;
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	void *create_event, *set_timer, *wait_for_event, *signal_event, *close_event,
		*check_event, *install_protocol, *reinstall_protocol, *uninstall_protocol;
	handle_protocol_fn *handle_protocol;
	void *reserved, *register_protocol_notify, *locate_handle;
	locate_device_path_fn *locate_device_path;
	void *install_configuration_table, *load_image, *start_image, *exit, *unload_image,
		*exit_boot_services, *get_next_monotonic_count, *stall, *set_watchdog_timer,
		*connect_controller, *disconnect_controller;
	open_protocol_fn *open_protocol;
	close_protocol_fn *close_protocol;
	void *open_protocol_information, *protocols_per_handle, *locate_handle_buffer,
		*locate_protocol;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};

typedef EFI_STATUS CDK2_MS_ABI get_variable_fn(CHAR16 *, const EFI_GUID *, UINT32 *,
	UINTN *, void *);
typedef EFI_STATUS CDK2_MS_ABI set_variable_fn(CHAR16 *, const EFI_GUID *, UINT32,
	UINTN, const void *);
struct runtime_services {
	UINT8 header[24];
	void *get_time, *set_time, *get_wakeup_time, *set_wakeup_time,
		*set_virtual_address_map, *convert_pointer;
	get_variable_fn *get_variable;
	set_variable_fn *set_variable;
};

struct usb_device_descriptor {
	UINT8 length, type; UINT16 bcd_usb;
	UINT8 device_class, device_subclass, device_protocol, packet;
	UINT16 vendor, product, bcd_device;
	UINT8 manufacturer, product_string, serial, configurations;
} __packed;
struct usb_interface_descriptor {
	UINT8 length, type, number, alternate, endpoints, interface_class,
		interface_subclass, interface_protocol, interface;
} __packed;
struct usb_io;
typedef EFI_STATUS CDK2_MS_ABI get_device_fn(struct usb_io *,
	struct usb_device_descriptor *);
typedef EFI_STATUS CDK2_MS_ABI get_interface_fn(struct usb_io *,
	struct usb_interface_descriptor *);
typedef EFI_STATUS CDK2_MS_ABI get_string_fn(struct usb_io *, UINT16, UINT8, CHAR16 **);
typedef EFI_STATUS CDK2_MS_ABI get_languages_fn(struct usb_io *, UINT16 **, UINT16 *);
struct usb_io {
	void *slots[6]; get_device_fn *get_device; void *get_config;
	get_interface_fn *get_interface; void *get_endpoint;
	get_string_fn *get_string; get_languages_fn *get_languages; void *reset;
};

static const UINT8 full_path[] = { 1, 1, 4, 0, 0x7f, 0xff, 4, 0 };
static const UINT8 short_path[] = {
	3, 0x10, 12, 0, 2, 0, 0x34, 0x12, 0x78, 0x56, 'X', 0,
	0x7f, 0xff, 4, 0
};
static struct cdk2_con_driver_binding *input_driver;
static UINTN installs, uninstalls, fail_at, marker_installs, allocations, frees;
static BOOLEAN fail_string;
static BOOLEAN fail_descriptor;

static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{
	(void)type; *buffer = calloc(1, size); allocations++;
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{ frees++; free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install_multiple_fixed(void **handle,
	const EFI_GUID *guid, void *interface, void *end)
{
	installs++;
	if (*handle == NULL)
		*handle = (void *)(UINTN)(installs + 10U);
	(void)guid; (void)end;
	if (interface != NULL && input_driver == NULL)
		input_driver = interface;
	if (interface == NULL)
		marker_installs++;
	return installs == fail_at ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI uninstall_multiple_fixed(void *handle,
	const EFI_GUID *guid, void *interface, void *end)
{
	(void)guid; (void)interface; (void)end;
	if (handle == NULL)
		return EFI_INVALID_PARAMETER;
	uninstalls++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI open_protocol(void *controller, const EFI_GUID *guid,
	void **interface, void *agent, void *child, UINT32 attributes)
{
	(void)controller; (void)guid; (void)agent; (void)child;
	if (attributes == CDK2_CON_OPEN_GET && interface != NULL)
		*interface = (void *)full_path;
	else if (attributes == CDK2_CON_OPEN_BY_DRIVER && interface != NULL)
		*interface = (void *)1;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI close_protocol(void *controller, const EFI_GUID *guid,
	void *agent, void *child)
{ (void)controller; (void)guid; (void)agent; (void)child; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI get_variable(CHAR16 *name, const EFI_GUID *guid,
	UINT32 *attributes, UINTN *size, void *data)
{
	(void)name; (void)guid; (void)attributes;
	if (data == NULL) { *size = sizeof(short_path); return EFI_BUFFER_TOO_SMALL; }
	memcpy(data, short_path, sizeof(short_path)); *size = sizeof(short_path);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI set_variable(CHAR16 *name, const EFI_GUID *guid,
	UINT32 attributes, UINTN size, const void *data)
{ (void)name; (void)guid; (void)size; (void)data; return attributes == 6U ? EFI_SUCCESS : EFI_INVALID_PARAMETER; }

static EFI_STATUS CDK2_MS_ABI get_device(struct usb_io *usb,
	struct usb_device_descriptor *descriptor)
{
	(void)usb;
	if (fail_descriptor)
		return EFI_DEVICE_ERROR;
	*descriptor = (struct usb_device_descriptor) {
		.vendor = 0x1234, .product = 0x5678, .serial = 1
	}; return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_interface(struct usb_io *usb,
	struct usb_interface_descriptor *descriptor)
{
	(void)usb; *descriptor = (struct usb_interface_descriptor) { .number = 2 };
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_languages(struct usb_io *usb, UINT16 **languages,
	UINT16 *count)
{ static UINT16 language = 0x409; (void)usb; *languages = &language; *count = 1; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI get_string(struct usb_io *usb, UINT16 language, UINT8 index,
	CHAR16 **string)
{
	(void)usb; (void)language; (void)index;
	if (fail_string)
		return EFI_DEVICE_ERROR;
	if (EFI_ERROR(allocate_pool(4U, 2U * sizeof(**string), (void **)string)))
		return EFI_OUT_OF_RESOURCES;
	(*string)[0] = 'X'; (*string)[1] = 0;
	return EFI_SUCCESS;
}
static struct usb_io usb = {
	.get_device = get_device, .get_interface = get_interface,
	.get_string = get_string, .get_languages = get_languages,
};
static EFI_STATUS CDK2_MS_ABI locate_device_path(const EFI_GUID *guid, void **path,
	void **handle)
{ (void)guid; (void)path; *handle = &usb; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle, const EFI_GUID *guid,
	void **interface)
{ (void)guid; *interface = handle; return EFI_SUCCESS; }

static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "con platform entry test: %s\n", message); return !condition; }

int main(void)
{
	struct boot_services boot = {
		.allocate_pool = allocate_pool, .free_pool = free_pool,
		.handle_protocol = handle_protocol, .locate_device_path = locate_device_path,
		.open_protocol = open_protocol, .close_protocol = close_protocol,
		.install_multiple = (install_multiple_fn *)install_multiple_fixed,
		.uninstall_multiple = (uninstall_multiple_fn *)uninstall_multiple_fixed,
	};
	struct runtime_services runtime = { .get_variable = get_variable,
		.set_variable = set_variable };
	struct cdk2_con_system_table system = { .runtime = &runtime, .boot = (void *)&boot };
	UINTN index;
	int failures = 0;

	failures += expect(cdk2_con_platform_entry((void *)1, &system) == EFI_SUCCESS &&
		installs == 6U && input_driver != NULL, "protocol publication failed");
	for (index = 1; index <= 6; index++) {
		installs = uninstalls = 0U; fail_at = index; input_driver = NULL;
		failures += expect(cdk2_con_platform_entry((void *)1, &system) == EFI_DEVICE_ERROR &&
			uninstalls == index - 1U, "protocol publication rollback failed");
	}
	installs = uninstalls = fail_at = marker_installs = 0U; input_driver = NULL;
	failures += expect(cdk2_con_platform_entry((void *)1, &system) == EFI_SUCCESS,
		"entry republish failed");
	failures += expect(input_driver->start(input_driver, (void *)1, NULL) == EFI_SUCCESS &&
		input_driver->start(input_driver, (void *)2, NULL) == EFI_SUCCESS &&
		marker_installs == 2U, "USB WWID did not select two independent controllers");
	failures += expect(input_driver->start(input_driver, (void *)1, NULL) ==
		CDK2_CON_ALREADY_STARTED, "duplicate controller Start was accepted");
	failures += expect(input_driver->stop(input_driver, (void *)1, 0U, NULL) == EFI_SUCCESS &&
		input_driver->stop(input_driver, (void *)2, 0U, NULL) == EFI_SUCCESS,
		"per-controller Stop did not release both instances");
	fail_string = TRUE; marker_installs = 0U;
	failures += expect(input_driver->start(input_driver, (void *)3, NULL) == EFI_SUCCESS &&
		marker_installs == 0U &&
		input_driver->stop(input_driver, (void *)3, 0U, NULL) == EFI_SUCCESS,
		"USB string failure incorrectly matched the WWID");
	fail_string = FALSE; fail_descriptor = TRUE; marker_installs = 0U;
	failures += expect(input_driver->start(input_driver, (void *)4, NULL) == EFI_SUCCESS &&
		marker_installs == 0U &&
		input_driver->stop(input_driver, (void *)4, 0U, NULL) == EFI_SUCCESS,
		"USB descriptor failure incorrectly matched the WWID");
	failures += expect(frees != 0U && allocations != 0U,
		"pool-backed adapter did not release owned allocations");
	return failures == 0 ? 0 : 1;
}
