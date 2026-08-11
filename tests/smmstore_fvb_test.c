/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

#include <stdio.h>
#include <string.h>

#define BLOCKS 4U
#define BLOCK_SIZE 128U

struct fixture {
	UINT8 flash[BLOCKS][BLOCK_SIZE];
	UINT8 communication[BLOCK_SIZE];
};

static UINTN conversions;
static UINTN fail_conversion;

static UINT32 invoke(void *context, UINT8 command, void *request_buffer)
{
	struct fixture *fixture = context;
	struct cdk2_smmstore_request *request = request_buffer;

	if (command == CDK2_SMMSTORE_RAW_CLEAR) {
		memset(fixture->flash[request->block], 0xff, BLOCK_SIZE);
		return 0;
	}
	if (command == CDK2_SMMSTORE_RAW_READ)
		memcpy(fixture->communication + request->offset,
		       fixture->flash[request->block] + request->offset,
		       request->size);
	else if (command == CDK2_SMMSTORE_RAW_WRITE)
		memcpy(fixture->flash[request->block] + request->offset,
		       fixture->communication + request->offset, request->size);
	else
		return 1U;
	return 0;
}

static EFI_STATUS convert(void **pointer)
{
	conversions++;
	if (conversions == fail_conversion)
		return EFI_DEVICE_ERROR;
	*pointer = (UINT8 *)*pointer + 0x1000U;
	return EFI_SUCCESS;
}

static int expect(BOOLEAN condition, const char *expression, int line)
{
	if (condition)
		return 0;
	fprintf(stderr, "%s:%d: %s\n", __FILE__, line, expression);
	return 1;
}

#define EXPECT(condition)                                                      \
	(failures += expect((condition), #condition, __LINE__))

int main(void)
{
	struct fixture fixture;
	struct cdk2_smmstore_fvb fvb;
	SMMSTORE_INFO info = {
		.com_buffer_size = sizeof(fixture.communication),
		.num_blocks = BLOCKS,
		.block_size = BLOCK_SIZE,
		.mmio_address = 0x300000U,
		.apm_cmd = 0xedU,
	};
	EFI_PHYSICAL_ADDRESS address;
	UINT32 attributes;
	UINT8 bytes[4] = {1U, 2U, 3U, 4U};
	UINT8 output[4];
	UINTN block_size;
	UINTN remaining;
	UINTN size;
	int failures = 0;

	memset(&fixture, 0xff, sizeof(fixture));
	info.com_buffer = (UINTN)fixture.communication;
	EXPECT(cdk2_smmstore_fvb_initialize(&fvb, &info, invoke, &fixture) ==
	       EFI_SUCCESS);
	EXPECT(fvb.protocol.get_attributes(&fvb.protocol, &attributes) ==
		       EFI_SUCCESS &&
	       attributes == CDK2_SMMSTORE_FVB_ATTRIBUTES);
	attributes ^= CDK2_FVB_WRITE_STATUS;
	EXPECT(fvb.protocol.set_attributes(&fvb.protocol, &attributes) ==
		       EFI_UNSUPPORTED &&
	       attributes == CDK2_SMMSTORE_FVB_ATTRIBUTES);
	EXPECT(fvb.protocol.get_physical_address(&fvb.protocol, &address) ==
		       EFI_SUCCESS &&
	       address == info.mmio_address);
	EXPECT(fvb.protocol.get_block_size(&fvb.protocol, 2U, &block_size,
					   &remaining) == EFI_SUCCESS &&
	       block_size == BLOCK_SIZE && remaining == 2U);
	size = sizeof(bytes);
	EXPECT(fvb.protocol.write(&fvb.protocol, 2U, 9U, &size, bytes) ==
	       EFI_SUCCESS);
	memset(output, 0, sizeof(output));
	size = sizeof(output);
	EXPECT(fvb.protocol.read(&fvb.protocol, 2U, 9U, &size, output) ==
		       EFI_SUCCESS &&
	       memcmp(bytes, output, sizeof(bytes)) == 0);
	EXPECT(cdk2_smmstore_fvb_erase_range(&fvb, 1U, 2U) == EFI_SUCCESS &&
	       fixture.flash[2][9] == 0xffU);
	EXPECT(cdk2_smmstore_fvb_erase_range(&fvb, 3U, 2U) ==
	       EFI_INVALID_PARAMETER);
	conversions = 0;
	fail_conversion = 2U;
	EXPECT(cdk2_smmstore_fvb_virtualize(&fvb, convert) ==
		       EFI_DEVICE_ERROR &&
	       conversions == 2U);
	EXPECT((UINTN)fvb.store.communication_buffer ==
	       info.com_buffer + 0x1000U);
	if (failures == 0)
		puts("SMMSTORE FVB runtime tests: PASS");
	return failures != 0;
}
