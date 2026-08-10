/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_bus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	struct cdk2_usb2_hc_protocol host;
	UINTN opens, closes, markers, unmarkers, publishes, removes, links, unlinks;
	UINTN allocations, frees, fault;
	UINT8 address;
};
static struct fixture fixture;
static const UINT8 device[18] = { 18U, 1U, 0U, 2U, 0U, 0U, 0U, 8U,
	0x34U, 0x12U, 0x78U, 0x56U, 0U, 1U, 0U, 0U, 0U, 1U };
static const UINT8 configuration[25] = { 9U, 2U, 25U, 0U, 1U, 1U, 0U, 0x80U,
	50U, 9U, 4U, 0U, 0U, 1U, 8U, 6U, 80U, 0U,
	7U, 5U, 0x81U, 2U, 0U, 2U, 0U };

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
{
	(void)host; (void)address; (void)speed; (void)packet; (void)direction;
	(void)timeout; (void)translator; *result = 0U;
	if (request->request == 5U)
		fixture.address = request->value;
	else if ((request->value >> 8) == 1U)
		memcpy(data, device, *length);
	else if ((request->value >> 8) == 2U)
		memcpy(data, configuration, *length);
	return EFI_SUCCESS;
}
static EFI_STATUS open_host(void *context, void *controller,
	struct cdk2_usb2_hc_protocol **host)
{ struct fixture *f = context; (void)controller; f->opens++; *host = &f->host;
	return f->fault == 1U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS close_host(void *context, void *controller)
{ struct fixture *f = context; (void)controller; f->closes++;
	return f->fault == 8U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS marker(void *context, void *controller, void *interface)
{ struct fixture *f = context; (void)controller; CHECK(interface != NULL);
	f->markers++; return f->fault == 3U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS unmarker(void *context, void *controller, void *interface)
{ struct fixture *f = context; (void)controller; CHECK(interface != NULL);
	f->unmarkers++; return f->fault == 7U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS publish(void *context, void *controller,
	struct cdk2_usb_child *child, void **handle)
{ struct fixture *f = context; (void)controller; CHECK(child->active);
	f->publishes++; if (f->fault == 4U) return EFI_DEVICE_ERROR;
	*handle = (void *)(UINTN)(0x100U + f->publishes); return EFI_SUCCESS; }
static EFI_STATUS remove_published(void *context, void *controller,
	struct cdk2_usb_child *child, void *handle)
{ struct fixture *f = context; (void)controller; (void)child; CHECK(handle != NULL);
	f->removes++; return f->fault == 6U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS link_child(void *context, void *controller, void *child)
{ struct fixture *f = context; (void)controller; CHECK(child != NULL); f->links++;
	return f->fault == 5U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS unlink_child(void *context, void *controller, void *child)
{ struct fixture *f = context; (void)controller; CHECK(child != NULL); f->unlinks++;
	return f->fault == 6U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	struct fixture *f = context;

	if (f->fault == 2U)
		return EFI_OUT_OF_RESOURCES;
	*buffer = malloc(size);
	if (*buffer != NULL)
		memset(*buffer, 0xaf, size);
	if (*buffer != NULL)
		f->allocations++;
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static void release(void *context, void *buffer)
{ struct fixture *f = context; f->frees++; free(buffer); }
static void delay(void *context, UINTN microseconds)
{ (void)context; (void)microseconds; }

static void setup(struct cdk2_usb_binding *binding)
{
	struct cdk2_usb_binding_services services = { .context = &fixture,
		.open_host = open_host, .close_host = close_host, .install_marker = marker,
		.uninstall_marker = unmarker, .publish_child = publish,
		.remove_child = remove_published, .link_child = link_child,
		.unlink_child = unlink_child, .allocate = allocate, .free = release,
		.delay = delay };

	memset(&fixture, 0, sizeof(fixture));
	fixture.host = (struct cdk2_usb2_hc_protocol) { .get_capability = capability,
		.control_transfer = control, .get_root_hub_port_status = port_status,
		.set_root_hub_port_feature = port_feature };
	CHECK(cdk2_usb_binding_init(binding, &services) == EFI_SUCCESS);
}

int main(void)
{
	struct cdk2_usb_binding binding;
	void *controller1 = (void *)1U, *controller2 = (void *)2U, *child;

	setup(&binding);
	CHECK(cdk2_usb_binding_supported(&binding, controller1) == EFI_SUCCESS &&
		fixture.opens == 1U && fixture.closes == 1U);
	CHECK(cdk2_usb_binding_start(&binding, controller1) == EFI_SUCCESS &&
		binding.count == 1U && binding.controllers[0].bus->child_count == 1U &&
		fixture.address == 1U && fixture.publishes == 1U && fixture.links == 1U);
	child = binding.controllers[0].bus->children[0].handle;
	CHECK(cdk2_usb_binding_start(&binding, controller1) == EFI_ALREADY_STARTED);
	CHECK(cdk2_usb_binding_start(&binding, controller2) == EFI_SUCCESS &&
		binding.count == 2U);
	CHECK(cdk2_usb_binding_stop(&binding, controller1, 1U, &child) == EFI_SUCCESS &&
		binding.controllers[0].bus->child_count == 0U);
	CHECK(cdk2_usb_binding_stop(&binding, controller1, 0U, NULL) == EFI_SUCCESS &&
		binding.count == 1U && binding.controllers[0].handle == controller2);
	CHECK(cdk2_usb_binding_stop(&binding, controller2, 0U, NULL) == EFI_SUCCESS &&
		binding.count == 0U && fixture.allocations == fixture.frees);

	for (UINTN fault = 1U; fault <= 8U; fault++) {
		setup(&binding); fixture.fault = fault;
		CHECK(EFI_ERROR(cdk2_usb_binding_start(&binding, controller1)) || fault >= 6U);
		if (binding.count != 0U) {
			fixture.fault = 0U;
			CHECK(cdk2_usb_binding_stop(&binding, controller1, 0U, NULL) == EFI_SUCCESS);
		}
		CHECK(binding.count == 0U && fixture.allocations == fixture.frees);
	}
	puts("usb bus binding tests: PASS");
	return 0;
}
