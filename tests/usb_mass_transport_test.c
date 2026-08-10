/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_mass.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { UINTN phase, controls, resets; UINT32 tag; };
static struct fixture fixture;
static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb_io_protocol *usb,
	struct cdk2_usb_request *request, UINTN direction, UINT32 timeout, void *data,
	UINTN * length, UINT32 * result)
{ (void)usb; (void)direction; (void)timeout; *result = 0U; fixture.controls++;
	if (request->request == 0xfeU) {
		*(UINT8 *)data = 2U;
		*length = 1U;
	}
	if (request->request == 0xffU)
		fixture.resets++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI bulk(struct cdk2_usb_io_protocol *usb,
	UINT8 endpoint, void *data, UINTN * length, UINTN timeout, UINT32 * result)
{
	(void)usb; (void)endpoint; (void)timeout; *result = 0U;
	if (fixture.phase++ % 3U == 0U) {
		struct cdk2_usb_mass_cbw *cbw = data;
		CHECK(*length == sizeof(*cbw)); fixture.tag = cbw->tag;
	} else if (fixture.phase % 3U == 2U) {
		memset(data, 0xa5, *length);
	} else {
		struct cdk2_usb_mass_csw *csw = data;
		*csw = (struct cdk2_usb_mass_csw) { CDK2_USB_MASS_CSW_SIGNATURE,
			fixture.tag, 0U, 0U };
	}
	return EFI_SUCCESS;
}

int main(void)
{
	struct cdk2_usb_io_protocol usb = { .control_transfer = control,
		.bulk_transfer = bulk };
	struct cdk2_usb_mass_device device = { .usb = &usb, .bulk_in = 0x81U,
		.bulk_out = 2U };
	UINT8 command[10] = { 0x28U }, data[512];
	UINT32 length = sizeof(data);

	CHECK(cdk2_usb_mass_get_max_lun(&device) == EFI_SUCCESS &&
		device.maximum_lun == 2U);
	CHECK(cdk2_usb_mass_transport(&device, 0U, command, sizeof(command), data,
		&length, TRUE, 1000U) == EFI_SUCCESS && length == sizeof(data) &&
		data[0] == 0xa5U);
	CHECK(cdk2_usb_mass_reset(&device) == EFI_SUCCESS && fixture.resets == 1U &&
		fixture.controls == 4U);
	puts("usb mass transport tests: PASS");
	return 0;
}
