/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_mouse.h>
#include <stdio.h>
#include <stdlib.h>

static UINTN closes, installs, uninstalls, events, event_closes, async_starts, async_stops;
static EFI_STATUS async_status;
static struct cdk2_usb_io usb_io;
static const UINT8 hid_report[] = { 0x05, 0x09, 0x19, 0x01, 0x29, 0x03 };
static const UINT8 full_config[] = { 9, 2, 18, 0, 1, 1, 0, 0x80, 50,
	9, 0x21, 0x11, 0x01, 0, 1, 0x22, sizeof(hid_report), 0 };

static EFI_STATUS CDK2_MS_ABI control_transfer(struct cdk2_usb_io *self,
	struct cdk2_usb_request *request, UINTN direction, UINT32 timeout, void *data,
	UINTN *length, UINT32 *result)
{
	const UINT8 *source = NULL;
	UINTN index;

	(void)self;
	(void)direction;
	(void)timeout;
	*result = 0U;
	if (request->request == 6U && (request->value >> 8) == 2U)
		source = full_config;
	else if (request->request == 6U && (request->value >> 8) == 0x22U)
		source = hid_report;
	else if (request->request == 3U) {
		*(UINT8 *)data = 1U;
		return EFI_SUCCESS;
	} else if (request->request == 11U)
		return EFI_SUCCESS;
	else
		return EFI_UNSUPPORTED;
	for (index = 0; index < *length; index++)
		((UINT8 *)data)[index] = source[index];
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI config_descriptor(struct cdk2_usb_io *self,
	void *buffer)
{
	struct cdk2_usb_config_descriptor *descriptor = buffer;
	(void)self;
	*descriptor = (struct cdk2_usb_config_descriptor) { .length = 9,
		.descriptor_type = 2, .total_length = sizeof(full_config),
		.interface_count = 1, .configuration_value = 1 };
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI interface_descriptor(struct cdk2_usb_io *self,
	void *buffer)
{
	struct cdk2_usb_interface_descriptor *descriptor = buffer;
	(void)self;
	*descriptor = (struct cdk2_usb_interface_descriptor) { .endpoint_count = 1,
		.interface_class = 3, .interface_subclass = 1, .interface_protocol = 2 };
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI endpoint_descriptor(struct cdk2_usb_io *self, UINT8 index,
	void *buffer)
{
	struct cdk2_usb_endpoint_descriptor *descriptor = buffer;
	(void)self;
	if (index != 0U)
		return EFI_NOT_FOUND;
	*descriptor = (struct cdk2_usb_endpoint_descriptor) { .endpoint_address = 0x81,
		.attributes = 3, .maximum_packet_size = 4, .interval = 10 };
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI asynchronous(struct cdk2_usb_io *self, UINT8 endpoint,
	BOOLEAN new_transfer, UINTN interval, UINTN length,
	cdk2_usb_async_callback_fn *callback, void *context)
{
	(void)self;
	(void)endpoint;
	(void)interval;
	(void)length;
	(void)callback;
	(void)context;
	if (new_transfer) {
		async_starts++;
		return async_status;
	}
	async_stops++;
	return EFI_SUCCESS;
}

static EFI_STATUS open_usb(void *context, void *controller, const EFI_GUID *protocol,
	void **interface, void *agent, void *child, UINT32 attributes)
{
	(void)context;
	(void)controller;
	(void)protocol;
	(void)agent;
	(void)child;
	(void)attributes;
	*interface = &usb_io;
	return EFI_SUCCESS;
}

static EFI_STATUS close_usb(void *context, void *controller, const EFI_GUID *protocol,
	void *agent, void *child)
{
	(void)context;
	(void)controller;
	(void)protocol;
	(void)agent;
	(void)child;
	closes++;
	return EFI_SUCCESS;
}

static EFI_STATUS install(void *context, void *controller, const EFI_GUID *protocol,
	void *interface)
{
	(void)context;
	(void)controller;
	(void)protocol;
	(void)interface;
	installs++;
	return EFI_SUCCESS;
}

static EFI_STATUS uninstall(void *context, void *controller, const EFI_GUID *protocol,
	void *interface)
{
	(void)context;
	(void)controller;
	(void)protocol;
	(void)interface;
	uninstalls++;
	return EFI_SUCCESS;
}

static EFI_STATUS create_event(void *context, UINT32 type, UINTN tpl, void *notify,
	void *notify_context, void **event)
{
	(void)context;
	(void)type;
	(void)tpl;
	(void)notify;
	(void)notify_context;
	*event = (void *)(++events);
	return EFI_SUCCESS;
}

static EFI_STATUS close_event(void *context, void *event)
{
	(void)context;
	(void)event;
	event_closes++;
	return EFI_SUCCESS;
}

static EFI_STATUS success_event(void *context, void *event)
{ (void)context; (void)event; return EFI_SUCCESS; }
static EFI_STATUS success_timer(void *context, void *event, UINT32 type, UINT64 trigger)
{ (void)context; (void)event; (void)type; (void)trigger; return EFI_SUCCESS; }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }
static int check(int value, const char *message)
{ if (!value) fprintf(stderr, "usb mouse: %s\n", message); return !value; }

int main(void)
{
	const UINT8 descriptor[] = { 0x05, 0x09, 0x19, 0x01, 0x29, 0x03 };
	INT8 report[] = { 3, 4, -5, 1 };
	struct cdk2_usb_mouse_ops ops = { open_usb, close_usb, install, uninstall,
		create_event, close_event, success_event, success_timer, allocate, release };
	struct cdk2_usb_mouse mouse = { .ops = &ops, .image = (void *)1 };
	struct cdk2_simple_pointer_state state;
	int failures = 0;

	failures += check(sizeof(struct cdk2_simple_pointer) == 4U * sizeof(void *),
		"SimplePointer ABI size");
	failures += check(sizeof(struct cdk2_usb_io) == 13U * sizeof(void *),
		"USB I/O ABI size");
	usb_io.async_interrupt_transfer = asynchronous;
	usb_io.control_transfer = control_transfer;
	usb_io.get_config_descriptor = config_descriptor;
	usb_io.get_interface_descriptor = interface_descriptor;
	usb_io.get_endpoint_descriptor = endpoint_descriptor;
	failures += check(cdk2_usb_mouse_parse_report(&mouse, descriptor,
		sizeof(descriptor)) == EFI_SUCCESS && mouse.button_count == 3,
		"HID button range parse");
	failures += check(cdk2_usb_mouse_start(&mouse, (void *)2) == EFI_SUCCESS &&
		mouse.polling && installs == 1 && events == 2, "start lifecycle");
	failures += check(cdk2_usb_mouse_interrupt(report, sizeof(report), &mouse, 0) ==
		EFI_SUCCESS, "interrupt report");
	failures += check(mouse.pointer.get_state(&mouse.pointer, &state) == EFI_SUCCESS &&
		state.relative_movement_x == 4 && state.relative_movement_y == -5 &&
		state.left_button && state.right_button, "SimplePointer state");
	failures += check(mouse.pointer.get_state(&mouse.pointer, &state) == EFI_NOT_READY,
		"state consumption");
	failures += check(cdk2_usb_mouse_stop(&mouse) == EFI_SUCCESS && async_stops == 1 &&
		uninstalls == 1 && event_closes == 2 && closes == 1, "stop lifecycle");
	mouse = (struct cdk2_usb_mouse) { .ops = &ops, .image = (void *)1 };
	async_status = EFI_DEVICE_ERROR;
	failures += check(cdk2_usb_mouse_start(&mouse, (void *)2) == EFI_DEVICE_ERROR &&
		!mouse.usb_open && !mouse.pointer_installed, "async failure rollback");
	return failures != 0;
}
