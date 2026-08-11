/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

#include <stdio.h>
#include <string.h>

#define BLOCKS 3U
#define BLOCK_SIZE 64U

struct fixture {
	UINT8 flash[BLOCKS][BLOCK_SIZE];
	UINT8 communication[BLOCK_SIZE];
	UINT8 last_command;
	BOOLEAN fail;
};

static UINT32 invoke(void *context, UINT8 command, void *request_buffer)
{
	struct fixture *fixture = context;
	struct cdk2_smmstore_request *request = request_buffer;
	UINTN index;

	fixture->last_command = command;
	if (fixture->fail || request->block >= BLOCKS)
		return 1U;
	if (command == CDK2_SMMSTORE_RAW_CLEAR) {
		memset(fixture->flash[request->block], 0xff, BLOCK_SIZE);
		return 0;
	}
	if (request->offset >= BLOCK_SIZE ||
	    request->size > BLOCK_SIZE - request->offset)
		return 1U;
	if (command == CDK2_SMMSTORE_RAW_READ) {
		memcpy(fixture->communication + request->offset,
		       fixture->flash[request->block] + request->offset,
		       request->size);
		return 0;
	}
	if (command != CDK2_SMMSTORE_RAW_WRITE)
		return 2U;
	for (index = 0; index < request->size; index++)
		if ((UINT8)~fixture
			    ->flash[request->block][request->offset + index] &
		    fixture->communication[request->offset + index])
			return 1U;
	for (index = 0; index < request->size; index++)
		fixture->flash[request->block][request->offset + index] &=
			fixture->communication[request->offset + index];
	return 0;
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
	struct cdk2_smmstore store;
	SMMSTORE_INFO info;
	UINT8 input[] = {0xa5U, 0x5aU, 0x00U, 0xf0U};
	UINT8 output[8];
	UINT64 total;
	UINTN size;
	int failures = 0;

	memset(&fixture, 0xff, sizeof(fixture));
	fixture.fail = FALSE;
	info = (SMMSTORE_INFO){
		.com_buffer = (UINTN)fixture.communication,
		.com_buffer_size = sizeof(fixture.communication),
		.num_blocks = BLOCKS,
		.block_size = BLOCK_SIZE,
		.mmio_address = 0x100000U,
		.apm_cmd = 0xedU,
	};
	EXPECT(cdk2_smmstore_initialize(&store, &info, invoke, &fixture) ==
	       EFI_SUCCESS);
	EXPECT(store.info.mmio_address == 0x100000U);
	EXPECT(cdk2_smmstore_total_size(&store, &total) == EFI_SUCCESS &&
	       total == BLOCKS * BLOCK_SIZE);
	size = sizeof(input);
	EXPECT(cdk2_smmstore_write(&store, 1U, 7U, &size, input) ==
		       EFI_SUCCESS &&
	       fixture.last_command == CDK2_SMMSTORE_RAW_WRITE);
	memset(output, 0, sizeof(output));
	size = sizeof(input);
	EXPECT(cdk2_smmstore_read(&store, 1U, 7U, &size, output) ==
		       EFI_SUCCESS &&
	       memcmp(input, output, sizeof(input)) == 0);
	size = sizeof(input);
	memset(input, 0xff, sizeof(input));
	EXPECT(cdk2_smmstore_write(&store, 1U, 7U, &size, input) ==
	       EFI_DEVICE_ERROR);
	EXPECT(cdk2_smmstore_erase(&store, 1U) == EFI_SUCCESS &&
	       fixture.flash[1][7] == 0xffU);
	size = sizeof(output);
	EXPECT(cdk2_smmstore_read(&store, 2U, BLOCK_SIZE - 3U, &size, output) ==
		       EFI_BAD_BUFFER_SIZE &&
	       size == 3U);
	size = 1U;
	EXPECT(cdk2_smmstore_read(&store, BLOCKS, 0, &size, output) ==
	       EFI_INVALID_PARAMETER);
	fixture.fail = TRUE;
	size = 1U;
	EXPECT(cdk2_smmstore_read(&store, 0, 0, &size, output) ==
	       EFI_DEVICE_ERROR);
	info.com_buffer_size = BLOCK_SIZE - 1U;
	EXPECT(cdk2_smmstore_initialize(&store, &info, invoke, &fixture) ==
	       EFI_INVALID_PARAMETER);
	info.com_buffer_size = sizeof(fixture.communication);
	info.mmio_address = 0;
	EXPECT(cdk2_smmstore_initialize(&store, &info, invoke, &fixture) ==
		       EFI_SUCCESS &&
	       store.info.mmio_address ==
		       0x100000000ULL - BLOCKS * BLOCK_SIZE);
	info.com_buffer = MAX_UINT64 - 4U;
	EXPECT(cdk2_smmstore_initialize(&store, &info, invoke, &fixture) ==
	       EFI_INVALID_PARAMETER);
	if (failures == 0)
		puts("SMMSTORE transport tests: PASS");
	return failures != 0;
}
