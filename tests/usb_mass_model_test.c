/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_mass.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

static EFI_STATUS CDK2_MS_ABI interface(struct cdk2_usb_io_protocol *usb,
	void *descriptor)
{ UINT8 value[9] = { 9U, 4U, 0U, 0U, 3U, 8U, 6U, 0x50U, 0U };
	(void)usb; memcpy(descriptor, value, sizeof(value)); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI endpoint(struct cdk2_usb_io_protocol *usb,
	UINT8 index, void *descriptor)
{ UINT8 value[7] = { 7U, 5U, 0U, 2U, 0U, 2U, 0U }; (void)usb;
	value[2] = index == 0U ? 0x81U : index == 1U ? 0x02U : 0x83U;
	value[3] = index == 2U ? 3U : 2U; memcpy(descriptor, value, sizeof(value));
	return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_usb_io_protocol usb = { .get_interface_descriptor = interface,
		.get_endpoint_descriptor = endpoint };
	struct cdk2_usb_mass_device device;
	struct cdk2_usb_mass_cbw cbw;
	struct cdk2_usb_mass_csw csw;
	struct cdk2_usb_mass_media media = { 0 };
	UINT8 command[10] = { 0x28U };
	UINT8 capacity10[8] = { 0U, 0U, 0x0fU, 0xffU, 0U, 0U, 2U, 0U };
	UINT8 capacity16[32] = { 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U,
		0U, 0U, 0x10U, 0U };
	UINT32 transferred;

	CHECK(sizeof(cbw) == 31U && sizeof(csw) == 13U &&
		cdk2_usb_mass_init(&device, &usb) == EFI_SUCCESS &&
		device.bulk_in == 0x81U && device.bulk_out == 2U);
	CHECK(cdk2_usb_mass_build_cbw(&device, 2U, command, sizeof(command),
		4096U, TRUE, &cbw) == EFI_SUCCESS && cbw.tag == 1U &&
		cbw.flags == 0x80U && cbw.command[0] == 0x28U);
	csw = (struct cdk2_usb_mass_csw) { CDK2_USB_MASS_CSW_SIGNATURE,
		cbw.tag, 512U, 0U };
	CHECK(cdk2_usb_mass_validate_csw(&cbw, &csw, sizeof(csw), &transferred) ==
		EFI_SUCCESS && transferred == 3584U);
	csw.tag++;
	CHECK(cdk2_usb_mass_validate_csw(&cbw, &csw, sizeof(csw), &transferred) ==
		EFI_COMPROMISED_DATA);
	CHECK(cdk2_usb_mass_parse_capacity10(capacity10, &media) == EFI_SUCCESS &&
		media.last_block == 4095U && media.block_size == 512U);
	CHECK(cdk2_usb_mass_parse_capacity16(capacity16, &media) == EFI_SUCCESS &&
		media.last_block == 0x100000000ULL && media.block_size == 4096U);
	puts("usb mass model tests: PASS");
	return 0;
}
