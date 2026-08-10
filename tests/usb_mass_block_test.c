/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_mass.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

static EFI_STATUS CDK2_MS_ABI bulk(struct cdk2_usb_io_protocol *usb,
	UINT8 endpoint, void *data, UINTN * length, UINTN timeout, UINT32 * result)
{
	static UINT32 tag;
	static UINTN phase;
	(void)usb; (void)endpoint; (void)timeout; *result = 0U;
	if (phase++ % 3U == 0U)
		tag = ((struct cdk2_usb_mass_cbw *)data)->tag;
	else if (phase % 3U == 2U)
		memset(data, 0x33, *length);
	else
		*(struct cdk2_usb_mass_csw *)data = (struct cdk2_usb_mass_csw) {
			CDK2_USB_MASS_CSW_SIGNATURE, tag, 0U, 0U };
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb_io_protocol *usb,
	struct cdk2_usb_request *request, UINTN direction, UINT32 timeout, void *data,
	UINTN *length, UINT32 *result)
{ (void)usb; (void)request; (void)direction; (void)timeout; (void)data;
	(void)length; *result = 0U; return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_usb_io_protocol usb = { .control_transfer = control,
		.bulk_transfer = bulk };
	struct cdk2_usb_mass_device device = { .usb = &usb, .bulk_in = 0x81U,
		.bulk_out = 2U, .media_count = 1U, .media = { { .last_block = 31U,
		.block_size = 512U, .present = TRUE } } };
	struct cdk2_usb_mass_block block;
	struct cdk2_block_io2_token token = { 0 };
	UINT8 buffer[512];

	CHECK(cdk2_usb_mass_block_init(&block, &device, 0U) == EFI_SUCCESS &&
		block.block.media == block.block2.media && sizeof(block.media) == 48U);
	CHECK(block.block.read_blocks(&block.block, 0U, 1U, sizeof(buffer), buffer) ==
		EFI_SUCCESS && buffer[0] == 0x33U);
	CHECK(block.block2.write_blocks(&block.block2, 0U, 2U, &token,
		sizeof(buffer), buffer) == EFI_SUCCESS &&
		token.transaction_status == EFI_SUCCESS);
	token.event = &token;
	CHECK(block.block2.read_blocks(&block.block2, 0U, 2U, &token,
		sizeof(buffer), buffer) == EFI_UNSUPPORTED);
	CHECK(block.block.read_blocks(&block.block, 1U, 0U, 0U, NULL) ==
		EFI_MEDIA_CHANGED && block.block.read_blocks(&block.block, 0U, 32U,
		sizeof(buffer), buffer) == EFI_INVALID_PARAMETER);
	puts("usb mass block tests: PASS");
	return 0;
}
