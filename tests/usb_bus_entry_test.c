/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/modules/usb_bus/entry.c"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { struct loaded_image loaded; struct cdk2_usb2_hc_protocol host;
	UINT8 path[8]; UINTN allocs, frees, installs, uninstalls, opens, closes, connects;
	struct driver_binding *binding; struct cdk2_usb_io_protocol *usb_io; };
static struct fixture fixture;
static const UINT8 device[18] = { 18U, 1U, 0U, 2U, 0U, 0U, 0U, 8U,
	0x34U, 0x12U, 0x78U, 0x56U, 0U, 1U, 0U, 0U, 0U, 1U };
static const UINT8 configuration[25] = { 9U, 2U, 25U, 0U, 1U, 1U, 0U, 0x80U,
	50U, 9U, 4U, 0U, 0U, 1U, 8U, 6U, 80U, 0U,
	7U, 5U, 0x81U, 2U, 0U, 2U, 0U };

static EFI_STATUS CDK2_MS_ABI alloc_pool(UINT32 type, UINTN size, void **value)
{ (void)type; *value = calloc(1U, size); if (*value != NULL) fixture.allocs++;
	return *value == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI free_pool(void *value)
{ fixture.frees++; free(value); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle,
	const struct guid *protocol, void **value)
{ (void)handle; if (protocol != &loaded_guid) return EFI_UNSUPPORTED;
	*value = &fixture.loaded; return EFI_SUCCESS; }
static void CDK2_MS_ABI stall(UINTN microseconds) { (void)microseconds; }
static EFI_STATUS CDK2_MS_ABI connect(void *handle, void **drivers,
	void *remaining, BOOLEAN recursive)
{ (void)handle; (void)drivers; (void)remaining; CHECK(recursive); fixture.connects++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI open_protocol(void *handle,
	const struct guid *protocol, void **value, void *agent, void *controller,
	UINT32 attributes)
{
	(void)handle; (void)agent; (void)controller; fixture.opens++;
	if (protocol == &host_guid)
		*value = &fixture.host;
	else if (protocol == &path_guid && attributes == 0x02U)
		*value = fixture.path;
	else if (protocol == &host_guid && attributes == 0x08U)
		*value = &fixture.host;
	else
		return EFI_UNSUPPORTED;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI close_protocol(void *handle,
	const struct guid *protocol, void *agent, void *controller)
{ (void)handle; (void)protocol; (void)agent; (void)controller; fixture.closes++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle,
	const struct guid *protocol, void *interface, ...)
{
	fixture.installs++;
	if (protocol == &driver_guid && interface == &binding)
		fixture.binding = interface;
	if (protocol == &path_guid) {
		*handle = (void *)0x222U;
	}
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle,
	const struct guid *protocol, void *interface, ...)
{ (void)handle; (void)protocol; (void)interface; fixture.uninstalls++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI capability(struct cdk2_usb2_hc_protocol *host,
	UINT8 *speed, UINT8 *ports, UINT8 *is_64bit)
{ (void)host; *speed = 3U; *ports = 1U; *is_64bit = 1U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI port_status(struct cdk2_usb2_hc_protocol *host,
	UINT8 port, struct cdk2_usb_port_status *status)
{ (void)host; (void)port; *status = (struct cdk2_usb_port_status) {
	1U | 1U << 11, 1U }; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI port_feature(struct cdk2_usb2_hc_protocol *host,
	UINT8 port, UINTN feature)
{ (void)host; (void)port; (void)feature; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb2_hc_protocol *host,
	UINT8 address, UINT8 speed, UINTN packet, struct cdk2_usb_request *request,
	UINTN direction, void *data, UINTN *length, UINTN timeout, void *translator,
	UINT32 * result)
{ (void)host; (void)address; (void)speed; (void)packet; (void)direction;
	(void)timeout; (void)translator; *result = 0U;
	if ((request->value >> 8) == 1U)
		memcpy(data, device, *length);
	else if ((request->value >> 8) == 2U)
		memcpy(data, configuration, *length);
	return EFI_SUCCESS; }

int main(void)
{
	struct boot_services boot = { 0 };
	struct system_table system = { .boot = &boot };
	CHAR16 *name;

	fixture.path[0] = 1U; fixture.path[1] = 1U; fixture.path[2] = 4U;
	fixture.path[4] = 0x7fU; fixture.path[5] = 0xffU; fixture.path[6] = 4U;
	fixture.host = (struct cdk2_usb2_hc_protocol) { .get_capability = capability,
		.control_transfer = control, .get_root_hub_port_status = port_status,
		.set_root_hub_port_feature = port_feature };
	boot.allocate_pool = alloc_pool; boot.free_pool = free_pool;
	boot.handle_protocol = handle_protocol; boot.stall = stall;
	boot.connect_controller = connect; boot.open_protocol = open_protocol;
	boot.close_protocol = close_protocol; boot.install_multiple = install_multiple;
	boot.uninstall_multiple = uninstall_multiple;
	CHECK(cdk2_usb_bus_entry(&fixture, &system) == EFI_SUCCESS &&
		fixture.binding != NULL && fixture.loaded.unload != NULL);
	CHECK(fixture.binding->supported(fixture.binding, &fixture, NULL) == EFI_SUCCESS);
	CHECK(fixture.binding->start(fixture.binding, &fixture, NULL) == EFI_SUCCESS &&
		usb_binding.controllers[0].bus->children[0].handle == (void *)0x222U &&
		fixture.connects == 1U);
	CHECK(component.driver_name(&component, "eng", &name) == EFI_SUCCESS &&
		name == driver_name && component2.controller_name(&component2, &fixture,
		(void *)0x222U, "en", &name) == EFI_SUCCESS && name == child_name);
	CHECK(fixture.binding->stop(fixture.binding, &fixture, 0U, NULL) == EFI_SUCCESS &&
		fixture.allocs == fixture.frees);
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	puts("usb bus entry tests: PASS");
	return 0;
}
