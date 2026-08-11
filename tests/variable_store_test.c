/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

#include <stdio.h>
#include <string.h>

#define BLOCKS 8U
#define BLOCK_SIZE 256U

struct fixture {
	UINT8 flash[BLOCKS][BLOCK_SIZE];
	UINT8 communication[BLOCK_SIZE];
	BOOLEAN fail_erase;
};

static void write16(UINT8 *bytes, UINT16 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
}

static void write32(UINT8 *bytes, UINT32 value)
{
	write16(bytes, (UINT16)value);
	write16(bytes + 2, (UINT16)(value >> 16));
}

static UINT32 invoke(void *context, UINT8 command, void *request_buffer)
{
	struct fixture *fixture = context;
	struct cdk2_smmstore_request *request = request_buffer;
	UINTN index;

	if (request->block >= BLOCKS || request->offset >= BLOCK_SIZE ||
	    request->size > BLOCK_SIZE - request->offset)
		return 1U;
	if (command == CDK2_SMMSTORE_RAW_CLEAR) {
		if (fixture->fail_erase)
			return 1U;
		memset(fixture->flash[request->block], 0xff, BLOCK_SIZE);
		return 0;
	}
	if (command == CDK2_SMMSTORE_RAW_READ) {
		memcpy(fixture->communication + request->offset,
		       fixture->flash[request->block] + request->offset,
		       request->size);
		return 0;
	}
	if (command != CDK2_SMMSTORE_RAW_WRITE)
		return 1U;
	for (index = 0; index < request->size; index++)
		fixture->flash[request->block][request->offset + index] &=
			fixture->communication[request->offset + index];
	return 0;
}

static EFI_STATUS initialize(struct fixture *fixture,
			     struct cdk2_smmstore *store)
{
	SMMSTORE_INFO info = {
		.com_buffer = (UINTN)fixture->communication,
		.com_buffer_size = sizeof(fixture->communication),
		.num_blocks = BLOCKS,
		.block_size = BLOCK_SIZE,
		.mmio_address = 0x200000U,
		.apm_cmd = 0xedU,
	};

	return cdk2_smmstore_initialize(store, &info, invoke, fixture);
}

static EFI_STATUS add_variable(struct cdk2_smmstore *store)
{
	UINT8 variable[68];
	UINTN size = sizeof(variable);

	memset(variable, 0, sizeof(variable));
	write16(variable, 0x55aaU);
	variable[2] = 0x3fU;
	write32(variable + 4, 7U);
	write32(variable + 36, 4U);
	write32(variable + 40, 3U);
	variable[44] = 1U;
	variable[60] = 'X';
	variable[62] = 0;
	variable[64] = 1U;
	variable[65] = 2U;
	variable[66] = 3U;
	return cdk2_smmstore_write(store, 0, 100U, &size, variable);
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
	struct cdk2_smmstore reopened;
	UINTN count;
	int failures = 0;

	memset(&fixture, 0, sizeof(fixture));
	EXPECT(initialize(&fixture, &store) == EFI_SUCCESS);
	EXPECT(cdk2_variable_store_format(&store) == EFI_SUCCESS);
	EXPECT(cdk2_variable_store_validate(&store, &count) == EFI_SUCCESS &&
	       count == 0);
	EXPECT(add_variable(&store) == EFI_SUCCESS);
	EXPECT(cdk2_variable_store_validate(&store, &count) == EFI_SUCCESS &&
	       count == 1U);
	EXPECT(initialize(&fixture, &reopened) == EFI_SUCCESS);
	EXPECT(cdk2_variable_store_validate(&reopened, &count) == EFI_SUCCESS &&
	       count == 1U);

	EXPECT(cdk2_variable_store_format(&store) == EFI_SUCCESS);
	fixture.flash[0][40] ^= 1U;
	EXPECT(cdk2_variable_store_validate(&store, &count) ==
	       EFI_COMPROMISED_DATA);
	EXPECT(cdk2_variable_store_format(&store) == EFI_SUCCESS);
	fixture.flash[0][50] ^= 1U;
	EXPECT(cdk2_variable_store_validate(&store, &count) == EFI_CRC_ERROR);
	EXPECT(cdk2_variable_store_format(&store) == EFI_SUCCESS);
	fixture.flash[0][72] ^= 1U;
	EXPECT(cdk2_variable_store_validate(&store, &count) ==
	       EFI_COMPROMISED_DATA);
	EXPECT(cdk2_variable_store_format(&store) == EFI_SUCCESS);
	EXPECT(add_variable(&store) == EFI_SUCCESS);
	write32(fixture.flash[0] + 100U + 36U, 3U);
	EXPECT(cdk2_variable_store_validate(&store, &count) ==
	       EFI_COMPROMISED_DATA);
	EXPECT(cdk2_variable_store_format(&store) == EFI_SUCCESS);
	EXPECT(add_variable(&store) == EFI_SUCCESS);
	write32(fixture.flash[0] + 100U + 40U, MAX_UINT32);
	EXPECT(cdk2_variable_store_validate(&store, &count) ==
	       EFI_COMPROMISED_DATA);
	EXPECT(cdk2_variable_store_format(&store) == EFI_SUCCESS);
	EXPECT(add_variable(&store) == EFI_SUCCESS);
	fixture.flash[0][163] = 1U;
	EXPECT(cdk2_variable_store_validate(&store, &count) ==
	       EFI_COMPROMISED_DATA);
	fixture.fail_erase = TRUE;
	EXPECT(cdk2_variable_store_format(&store) == EFI_DEVICE_ERROR);
	if (failures == 0)
		puts("authenticated variable-store tests: PASS");
	return failures != 0;
}
