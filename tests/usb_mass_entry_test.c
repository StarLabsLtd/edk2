/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/modules/usb_mass/entry.c"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { struct loaded_image loaded; struct cdk2_usb_io_protocol usb;
	UINT8 path[8], opcode; UINT32 tag; UINTN phase, allocs, frees, installs;
	UINTN uninstalls, opens, closes, connects; struct driver_binding *binding;
	struct cdk2_block_io *block; };
static struct fixture fixture;

static EFI_STATUS CDK2_MS_ABI alloc_pool(UINT32 type, UINTN size, void **value)
{ (void)type; *value = calloc(1U, size); if (*value != NULL) fixture.allocs++;
	return *value == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI free_pool(void *value)
{ fixture.frees++; free(value); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle,
	const struct guid *protocol, void **value)
{ (void)handle; if (protocol != &loaded_guid) return EFI_UNSUPPORTED;
	*value = &fixture.loaded; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI connect(void *handle, void **drivers,
	void *remaining, BOOLEAN recursive)
{ (void)handle; (void)drivers; (void)remaining; CHECK(recursive);
	fixture.connects++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI open_protocol(void *handle,
	const struct guid *protocol, void **value, void *agent, void *controller,
	UINT32 attributes)
{
	(void)handle; (void)agent; (void)controller; fixture.opens++;
	if (protocol == &usb_io_guid)
		*value = &fixture.usb;
	else if (protocol == &path_guid && attributes == 0x02U)
		*value = fixture.path;
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
{ fixture.installs++; if (protocol == &binding_guid) fixture.binding = interface;
	if (protocol == &path_guid) {
		*handle = (void *)0x123U;
		fixture.block = (struct cdk2_block_io *)((UINT8 *)interface +
			sizeof(struct cdk2_usb_mass_lun_path) + 4U);
	}
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle,
	const struct guid *protocol, void *interface, ...)
{ (void)handle; (void)protocol; (void)interface; fixture.uninstalls++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI interface_descriptor(struct cdk2_usb_io_protocol *usb,
	void *descriptor)
{ UINT8 value[9] = { 9U, 4U, 0U, 0U, 2U, 8U, 6U, 0x50U, 0U };
	(void)usb; memcpy(descriptor, value, sizeof(value)); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI endpoint_descriptor(struct cdk2_usb_io_protocol *usb,
	UINT8 index, void *descriptor)
{ UINT8 value[7] = { 7U, 5U, index == 0U ? 0x81U : 2U, 2U, 0U, 2U, 0U };
	(void)usb; memcpy(descriptor, value, sizeof(value)); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb_io_protocol *usb,
	struct cdk2_usb_request *request, UINTN direction, UINT32 timeout, void *data,
	UINTN *length, UINT32 * result)
{ (void)usb; (void)direction; (void)timeout; *result = 0U;
	if (request->request == 0xfeU) {
		*(UINT8 *)data = 0U;
		*length = 1U;
	}
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI bulk(struct cdk2_usb_io_protocol *usb,
	UINT8 endpoint, void *data, UINTN *length, UINTN timeout, UINT32 * result)
{ (void)usb; (void)endpoint; (void)timeout; *result = 0U;
	if (fixture.phase++ % 3U == 0U) {
		struct cdk2_usb_mass_cbw *cbw = data;

		fixture.tag = cbw->tag;
		fixture.opcode = cbw->command[0];
	} else if (fixture.phase % 3U == 2U) {
		memset(data, 0, *length);
		if (fixture.opcode == 0x12U)
			((UINT8 *)data)[4] = 31U;
		if (fixture.opcode == 0x25U) {
			UINT8 capacity[8] = { 0U, 0U, 0U, 31U,
				0U, 0U, 2U, 0U };

			memcpy(data, capacity, sizeof(capacity));
		}
	} else {
		*(struct cdk2_usb_mass_csw *)data = (struct cdk2_usb_mass_csw) {
			CDK2_USB_MASS_CSW_SIGNATURE, fixture.tag, 0U, 0U };
	}
	return EFI_SUCCESS; }

int main(void)
{
	struct boot_services boot = { 0 };
	struct system_table system = { .boot = &boot };
	CHAR16 *name;

	fixture.path[0] = 1U; fixture.path[1] = 1U; fixture.path[2] = 4U;
	fixture.path[4] = 0x7fU; fixture.path[5] = 0xffU; fixture.path[6] = 4U;
	fixture.usb = (struct cdk2_usb_io_protocol) { .control_transfer = control,
		.bulk_transfer = bulk, .get_interface_descriptor = interface_descriptor,
		.get_endpoint_descriptor = endpoint_descriptor };
	boot.allocate_pool = alloc_pool; boot.free_pool = free_pool;
	boot.handle_protocol = handle_protocol; boot.connect_controller = connect;
	boot.open_protocol = open_protocol; boot.close_protocol = close_protocol;
	boot.install_multiple = install_multiple; boot.uninstall_multiple = uninstall_multiple;
	CHECK(cdk2_usb_mass_entry(&fixture, &system) == EFI_SUCCESS &&
		fixture.binding != NULL && fixture.loaded.unload != NULL);
	CHECK(fixture.binding->supported(fixture.binding, &fixture, NULL) == EFI_SUCCESS);
	CHECK(fixture.binding->start(fixture.binding, &fixture, NULL) == EFI_SUCCESS &&
		mass_binding.count == 1U && fixture.connects == 1U);
	CHECK(component.driver_name(&component, "eng", &name) == EFI_SUCCESS &&
		name == driver_name && component2.controller_name(&component2, &fixture,
		(void *)0x123U, "en", &name) == EFI_SUCCESS && name == controller_name);
	CHECK(fixture.binding->stop(fixture.binding, &fixture, 0U, NULL) == EFI_SUCCESS &&
		fixture.allocs == fixture.frees);
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	puts("usb mass entry tests: PASS");
	return 0;
}
