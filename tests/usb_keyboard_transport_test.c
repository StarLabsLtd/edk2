/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_keyboard.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

static cdk2_usb2_async_callback_fn *notify;
static void *notify_context;
static UINTN controls, starts, stops;
static EFI_STATUS CDK2_MS_ABI interface_descriptor(
	struct cdk2_usb_io_protocol *usb, void *data)
{ UINT8 *bytes = data; (void)usb; memset(bytes, 0, 9U); bytes[2] = 4U;
	bytes[5] = 3U; bytes[6] = 1U; bytes[7] = 1U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI endpoint_descriptor(
	struct cdk2_usb_io_protocol *usb, UINT8 index, void *data)
{ UINT8 *bytes = data; (void)usb; CHECK(index == 0U); memset(bytes, 0, 7U);
	bytes[2] = 0x81U; bytes[3] = 3U; bytes[4] = 8U; bytes[6] = 10U;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb_io_protocol *usb,
	struct cdk2_usb_request *request, UINTN direction, UINT32 timeout, void *data,
	UINTN *length, UINT32 *result)
{ (void)usb; (void)timeout; (void)data; CHECK(direction == 2U && *length == 0U);
	CHECK(request->request == 10U || request->request == 11U); controls++;
	*result = 0U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI interrupt(struct cdk2_usb_io_protocol *usb,
	UINT8 endpoint, BOOLEAN start, UINTN interval, UINTN length,
	cdk2_usb2_async_callback_fn *callback, void *context)
{ (void)usb; CHECK(endpoint == 0x81U && interval == 10U && length == 8U);
	if (start) { starts++; notify = callback; notify_context = context; }
	else { stops++; CHECK(callback == NULL); }
	return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_usb_io_protocol usb = { .control_transfer = control,
		.async_interrupt_transfer = interrupt,
		.get_interface_descriptor = interface_descriptor,
		.get_endpoint_descriptor = endpoint_descriptor };
	struct cdk2_usb_keyboard_device device;
	struct cdk2_usb_keyboard_report report = { .keys = { 4U } };
	struct cdk2_usb_keyboard_key key;

	CHECK(cdk2_usb_keyboard_start_io(&device, &usb) == EFI_SUCCESS &&
		controls == 2U && starts == 1U && notify != NULL);
	CHECK(notify(&report, sizeof(report), notify_context, 0U) == EFI_SUCCESS);
	CHECK(cdk2_usb_keyboard_read(&device.keyboard, &key) == EFI_SUCCESS &&
		key.unicode_char == 'a');
	CHECK(cdk2_usb_keyboard_stop_io(&device) == EFI_SUCCESS && stops == 1U &&
		!device.active);
	puts("usb keyboard transport tests: PASS");
	return 0;
}
