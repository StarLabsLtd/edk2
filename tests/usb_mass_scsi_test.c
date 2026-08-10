/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_mass.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { UINTN command_count; UINT8 opcode[16]; };
static struct fixture fixture;
static EFI_STATUS CDK2_MS_ABI bulk(struct cdk2_usb_io_protocol *usb,
	UINT8 endpoint, void *data, UINTN * length, UINTN timeout, UINT32 * result)
{
	static UINT32 tag;
	static UINT32 transfer_length;
	static UINTN phase;
	(void)usb; (void)endpoint; (void)timeout; *result = 0U;
	if (phase++ % 3U == 0U) {
		struct cdk2_usb_mass_cbw *cbw = data;
		tag = cbw->tag; transfer_length = cbw->transfer_length;
		fixture.opcode[fixture.command_count++] = cbw->command[0];
	} else if (phase % 3U == 2U) {
		UINT8 opcode = fixture.opcode[fixture.command_count - 1U];
		memset(data, 0, *length);
		if (opcode == 0x12U) {
			((UINT8 *)data)[0] = 0U;
			((UINT8 *)data)[4] = 31U;
		}
		if (opcode == 0x25U) {
			UINT8 capacity[8] = { 0U, 0U, 3U, 0xffU,
				0U, 0U, 2U, 0U };

			memcpy(data, capacity, sizeof(capacity));
		}
		if (opcode == 0x28U || opcode == 0x88U)
			memset(data, 0x5a, *length);
	} else {
		struct cdk2_usb_mass_csw *csw = data;
		*csw = (struct cdk2_usb_mass_csw) { CDK2_USB_MASS_CSW_SIGNATURE,
			tag, 0U, 0U }; (void)transfer_length;
	}
	return EFI_SUCCESS;
}

int main(void)
{
	struct cdk2_usb_io_protocol usb = { .bulk_transfer = bulk };
	struct cdk2_usb_mass_device device = { .usb = &usb, .bulk_in = 0x81U,
		.bulk_out = 2U, .maximum_lun = 0U };
	UINT8 buffer[1024];

	CHECK(cdk2_usb_mass_probe_lun(&device, 0U) == EFI_SUCCESS &&
		device.media_count == 1U && device.media[0].last_block == 0x3ffU &&
		device.media[0].block_size == 512U);
	CHECK(cdk2_usb_mass_read(&device, 0U, 2U, 2U, buffer) == EFI_SUCCESS &&
		buffer[0] == 0x5aU && fixture.opcode[2] == 0x28U);
	CHECK(cdk2_usb_mass_write(&device, 0U, 3U, 2U, buffer) == EFI_SUCCESS &&
		fixture.opcode[3] == 0x2aU);
	CHECK(cdk2_usb_mass_read(&device, 0U, 0x3ffU, 2U, buffer) ==
		EFI_INVALID_PARAMETER);
	puts("usb mass SCSI tests: PASS");
	return 0;
}
