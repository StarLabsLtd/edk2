/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_keyboard.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

static struct cdk2_usb_io_protocol usb;
static UINTN opens, closes, events, closed_events, publishes, removes, pools;
static EFI_STATUS open_usb(void *context, void *controller,
	struct cdk2_usb_io_protocol **result)
{ (void)context; CHECK(controller != NULL); opens++; *result = &usb;
	return EFI_SUCCESS; }
static EFI_STATUS close_usb(void *context, void *controller)
{ (void)context; CHECK(controller != NULL); closes++; return EFI_SUCCESS; }
static EFI_STATUS create_event(void *context,
	struct cdk2_usb_keyboard_controller *owner, BOOLEAN extended, void **event)
{ (void)context; CHECK(owner != NULL && extended == (events != 0U)); events++;
	*event = (void *)(events + 0x100U); return EFI_SUCCESS; }
static EFI_STATUS close_event(void *context, void *event)
{ (void)context; CHECK(event != NULL); closed_events++; return EFI_SUCCESS; }
static EFI_STATUS publish(void *context, void *controller,
	struct cdk2_usb_keyboard_controller *owner)
{ (void)context; CHECK(controller != NULL && owner != NULL); publishes++;
	return EFI_SUCCESS; }
static EFI_STATUS remove_owner(void *context, void *controller,
	struct cdk2_usb_keyboard_controller *owner)
{ (void)context; CHECK(controller != NULL && owner != NULL); removes++;
	return EFI_SUCCESS; }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	(void)context;
	*buffer = malloc(size);
	if (*buffer == NULL)
		return EFI_OUT_OF_RESOURCES;
	memset(*buffer, 0xaf, size);
	pools++;
	return EFI_SUCCESS;
}
static void release(void *context, void *buffer)
{ (void)context; free(buffer); pools--; }
static EFI_STATUS CDK2_MS_ABI interface_descriptor(
	struct cdk2_usb_io_protocol *protocol, void *data)
{ UINT8 * bytes = data; (void)protocol; memset(bytes, 0, 9U); bytes[5] = 3U;
	bytes[6] = 1U; bytes[7] = 1U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI endpoint_descriptor(
	struct cdk2_usb_io_protocol *protocol, UINT8 index, void *data)
{ UINT8 *bytes = data; (void)protocol; CHECK(index == 0U); memset(bytes, 0, 7U);
	bytes[2] = 0x81U; bytes[3] = 3U; bytes[4] = 8U; bytes[6] = 8U;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb_io_protocol *protocol,
	struct cdk2_usb_request *request, UINTN direction, UINT32 timeout, void *data,
	UINTN *length, UINT32 *result)
{ (void)protocol; (void)request; (void)direction; (void)timeout; (void)data;
	(void)length; *result = 0U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI interrupt(struct cdk2_usb_io_protocol *protocol,
	UINT8 endpoint, BOOLEAN start, UINTN interval, UINTN length,
	cdk2_usb2_async_callback_fn *callback, void *context)
{ (void)protocol; (void)endpoint; (void)interval; (void)length; (void)context;
	CHECK(start ? callback != NULL : callback == NULL); return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_usb_keyboard_binding binding;
	struct cdk2_usb_keyboard_binding_services services = { .open = open_usb,
		.close = close_usb, .create_event = create_event,
		.close_event = close_event, .publish = publish, .remove = remove_owner,
		.allocate = allocate, .release = release };
	void *controller = &binding;

	usb = (struct cdk2_usb_io_protocol) { .control_transfer = control,
		.async_interrupt_transfer = interrupt,
		.get_interface_descriptor = interface_descriptor,
		.get_endpoint_descriptor = endpoint_descriptor };
	CHECK(cdk2_usb_keyboard_binding_init(&binding, &services) == EFI_SUCCESS);
	CHECK(cdk2_usb_keyboard_binding_supported(&binding, controller) ==
		EFI_SUCCESS && opens == 1U && closes == 1U);
	CHECK(cdk2_usb_keyboard_binding_start(&binding, controller) == EFI_SUCCESS &&
		binding.count == 1U && events == 2U && publishes == 1U && pools == 1U);
	CHECK(cdk2_usb_keyboard_binding_start(&binding, controller) ==
		EFI_ALREADY_STARTED);
	CHECK(cdk2_usb_keyboard_binding_stop(&binding, controller) == EFI_SUCCESS &&
		binding.count == 0U && removes == 1U && closed_events == 2U && pools == 0U);
	puts("usb keyboard binding tests: PASS");
	return 0;
}
