/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_mass.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { struct cdk2_usb_io_protocol usb; UINTN opens, closes, allocs, frees;
	UINTN publishes, removes, links, unlinks, fault, phase; UINT32 tag;
	UINT8 opcode; };
static struct fixture fixture;

static EFI_STATUS CDK2_MS_ABI interface(struct cdk2_usb_io_protocol *usb,
	void *descriptor)
{ UINT8 value[9] = { 9U, 4U, 0U, 0U, 2U, 8U, 6U, 0x50U, 0U };
	(void)usb; memcpy(descriptor, value, sizeof(value)); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI endpoint(struct cdk2_usb_io_protocol *usb,
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
	UINT8 endpoint_value, void *data, UINTN *length, UINTN timeout,
	UINT32 * result)
{
	(void)usb; (void)endpoint_value; (void)timeout; *result = 0U;
	if (fixture.phase++ % 3U == 0U) {
		struct cdk2_usb_mass_cbw *cbw = data;

		fixture.tag = cbw->tag; fixture.opcode = cbw->command[0];
	} else if (fixture.phase % 3U == 2U) {
		memset(data, 0, *length);
		if (fixture.opcode == 0x12U)
			((UINT8 *)data)[4] = 31U;
		if (fixture.opcode == 0x25U) {
			UINT8 capacity[8] = { 0U, 0U, 0U, 31U, 0U, 0U, 2U, 0U };

			memcpy(data, capacity, sizeof(capacity));
		}
	} else {
		*(struct cdk2_usb_mass_csw *)data = (struct cdk2_usb_mass_csw) {
			CDK2_USB_MASS_CSW_SIGNATURE, fixture.tag, 0U, 0U };
	}
	return EFI_SUCCESS;
}
static EFI_STATUS open_usb(void *context, void *controller,
	struct cdk2_usb_io_protocol **usb)
{ struct fixture *f = context; (void)controller; f->opens++; *usb = &f->usb;
	return f->fault == 1U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS close_usb(void *context, void *controller)
{ struct fixture *f = context; (void)controller; f->closes++;
	return f->fault == 7U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS publish(void *context, void *controller,
	struct cdk2_usb_mass_child *child, void **handle)
{ struct fixture *f = context; (void)controller; CHECK(child->path.lun == 0U);
	f->publishes++; if (f->fault == 3U) return EFI_DEVICE_ERROR;
	*handle = (void *)(UINTN)(0x100U + f->publishes); return EFI_SUCCESS; }
static EFI_STATUS remove_child(void *context, void *controller,
	struct cdk2_usb_mass_child *child, void *handle)
{ struct fixture *f = context; (void)controller; (void)child; CHECK(handle != NULL);
	f->removes++; return f->fault == 6U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS link_child(void *context, void *controller, void *child)
{ struct fixture *f = context; (void)controller; CHECK(child != NULL); f->links++;
	return f->fault == 4U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS unlink_child(void *context, void *controller, void *child)
{ struct fixture *f = context; (void)controller; CHECK(child != NULL); f->unlinks++;
	return f->fault == 5U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	struct fixture *f = context;

	if (f->fault == 2U)
		return EFI_OUT_OF_RESOURCES;
	*buffer = malloc(size);
	if (*buffer != NULL) {
		memset(*buffer, 0xaf, size);
		f->allocs++;
	}
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static void release(void *context, void *buffer)
{ struct fixture *f = context; f->frees++; free(buffer); }

static void setup(struct cdk2_usb_mass_binding *binding)
{
	struct cdk2_usb_mass_binding_services services = { .context = &fixture,
		.open_usb = open_usb, .close_usb = close_usb, .publish = publish,
		.remove = remove_child, .link = link_child, .unlink = unlink_child,
		.allocate = allocate, .release = release };

	memset(&fixture, 0, sizeof(fixture));
	fixture.usb = (struct cdk2_usb_io_protocol) { .control_transfer = control,
		.bulk_transfer = bulk, .get_interface_descriptor = interface,
		.get_endpoint_descriptor = endpoint };
	CHECK(cdk2_usb_mass_binding_init(binding, &services) == EFI_SUCCESS);
}

int main(void)
{
	struct cdk2_usb_mass_binding binding;
	void *controller1 = (void *)1U, *controller2 = (void *)2U, *child;

	setup(&binding);
	CHECK(cdk2_usb_mass_binding_supported(&binding, controller1) == EFI_SUCCESS);
	CHECK(cdk2_usb_mass_binding_start(&binding, controller1) == EFI_SUCCESS &&
		binding.count == 1U && binding.controllers[0]->child_count == 1U);
	child = binding.controllers[0]->children[0].handle;
	CHECK(cdk2_usb_mass_binding_start(&binding, controller2) == EFI_SUCCESS &&
		binding.count == 2U);
	CHECK(cdk2_usb_mass_binding_stop(&binding, controller1, 1U, &child) ==
		EFI_SUCCESS && binding.controllers[0]->child_count == 0U);
	CHECK(cdk2_usb_mass_binding_stop(&binding, controller1, 0U, NULL) == EFI_SUCCESS &&
		binding.count == 1U && binding.controllers[0]->handle == controller2);
	CHECK(cdk2_usb_mass_binding_stop(&binding, controller2, 0U, NULL) == EFI_SUCCESS &&
		binding.count == 0U && fixture.allocs == fixture.frees);
	for (UINTN fault = 1U; fault <= 7U; fault++) {
		setup(&binding); fixture.fault = fault;
		CHECK(EFI_ERROR(cdk2_usb_mass_binding_start(&binding, controller1)) ||
			fault >= 5U);
		if (binding.count != 0U) {
			fixture.fault = 0U;
			CHECK(cdk2_usb_mass_binding_stop(&binding, controller1, 0U, NULL) ==
				EFI_SUCCESS);
		}
		CHECK(binding.count == 0U && fixture.allocs == fixture.frees);
	}
	puts("usb mass binding tests: PASS");
	return 0;
}
