/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_transport.h>
#include <stdio.h>
#include <string.h>

#define TEST_BASE 0xfed40000U

struct mock_io {
	enum cdk2_tpm2_interface interface;
	UINT8 command[64];
	UINT32 command_size;
	UINT8 response[64];
	UINT32 response_index;
	UINT32 stalls;
	UINT32 cancel_writes;
	int started;
	int locality;
	int ready;
	int force_start_timeout;
};

static UINT8 mock_read8(void *context, UINT64 address)
{
	struct mock_io *mock = context;
	UINT64 offset = address - TEST_BASE;

	if (offset == 0)
		return 0;
	if ((mock->interface == CDK2_TPM2_INTERFACE_FIFO ||
	     mock->interface == CDK2_TPM2_INTERFACE_TIS) && offset == 0x24U)
		return mock->response[mock->response_index++];
	if (mock->interface == CDK2_TPM2_INTERFACE_CRB && offset >= 0x80U)
		return mock->response[offset - 0x80U];
	return 0;
}

static UINT32 mock_read32(void *context, UINT64 address)
{
	struct mock_io *mock = context;
	UINT64 offset = address - TEST_BASE;

	if (offset == 0)
		return mock->locality ? 0xa0U : 0;
	if (offset == 0x18U) {
		UINT32 value = 0x80U | 0x4000U;
		if (mock->ready)
			value |= 0x40U;
		if (mock->command_size < 12U && !mock->started)
			value |= 0x08U;
		if (mock->started)
			value |= 0x10U;
		return value;
	}
	if (offset == 0x0cU)
		return mock->locality ? 1U : 0;
	if (offset == 0x40U)
		return 0;
	if (offset == 0x44U)
		return 2U;
	if (offset == 0x4cU)
		return mock->force_start_timeout ? 1U : 0;
	return 0;
}

static UINT64 mock_read64(void *context, UINT64 address)
{
	(void)context; (void)address; return 0;
}

static void mock_write8(void *context, UINT64 address, UINT8 value)
{
	struct mock_io *mock = context;
	UINT64 offset = address - TEST_BASE;

	if (offset == 0 && value == 2U)
		mock->locality = 1;
	if (offset == 0x18U && value == 0x40U)
		mock->ready = 1;
	if (offset == 0x18U && value == 0x20U)
		mock->started = 1;
	if (offset == 0x24U)
		mock->command[mock->command_size++] = value;
	if (offset >= 0x80U && mock->interface == CDK2_TPM2_INTERFACE_CRB) {
		mock->command[offset - 0x80U] = value;
		if (mock->command_size <= offset - 0x80U)
			mock->command_size = offset - 0x80U + 1U;
	}
}

static void mock_write32(void *context, UINT64 address, UINT32 value)
{
	struct mock_io *mock = context;
	UINT64 offset = address - TEST_BASE;

	if (offset == 0x08U && value == 1U)
		mock->locality = 1;
	if (offset == 0x48U)
		mock->cancel_writes++;
}

static void mock_write64(void *context, UINT64 address, UINT64 value)
{
	(void)context; (void)address; (void)value;
}

static void mock_stall(void *context, UINT32 microseconds)
{
	struct mock_io *mock = context;
	(void)microseconds; mock->stalls++;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "tcg2-transport test: %s\n", message);
	return !condition;
}

int main(void)
{
	UINT8 command[] = { 0x80, 0x01, 0, 0, 0, 12, 0, 0, 1, 0x44, 0, 0 };
	UINT8 response[] = { 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0 };
	struct cdk2_tpm2_response header;
	struct mock_io mock;
	struct cdk2_tpm2_io io;
	struct cdk2_tpm2_transport transport;
	UINT8 output[64];
	UINT32 output_size;
	int failures = 0;

	failures += expect(cdk2_tpm2_detect_interface(0x00002100U, 0x30000697U) ==
		CDK2_TPM2_INTERFACE_FIFO, "QEMU FIFO interface not detected");
	failures += expect(cdk2_tpm2_detect_interface(0x00025811U, 0) ==
		CDK2_TPM2_INTERFACE_CRB, "QEMU CRB interface not detected");
	failures += expect(cdk2_tpm2_detect_interface(0x0000000fU, 0) ==
		CDK2_TPM2_INTERFACE_TIS, "legacy TIS interface not detected");
	failures += expect(cdk2_tpm2_detect_interface(0xffffffffU, 0xffffffffU) ==
		CDK2_TPM2_INTERFACE_INVALID, "absent TPM was accepted");
	failures += expect(cdk2_tpm2_validate_command(command, sizeof(command)) ==
		EFI_SUCCESS, "valid command rejected");
	command[5] = 10;
	failures += expect(cdk2_tpm2_validate_command(command, sizeof(command)) ==
		EFI_COMPROMISED_DATA, "mismatched command size accepted");
	failures += expect(cdk2_tpm2_parse_response(response, sizeof(response), &header) ==
		EFI_SUCCESS && header.size == 10U && header.code == 0,
		"valid response rejected");
	response[5] = 11;
	failures += expect(cdk2_tpm2_parse_response(response, sizeof(response), &header) ==
		EFI_BUFFER_TOO_SMALL, "oversized response accepted");
	response[0] = 0;
	failures += expect(cdk2_tpm2_parse_response(response, sizeof(response), &header) ==
		EFI_COMPROMISED_DATA, "invalid response tag accepted");

	memset(&mock, 0, sizeof(mock));
	memcpy(mock.response, (UINT8[]){ 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0 }, 10);
	io = (struct cdk2_tpm2_io){
		.context = &mock, .read8 = mock_read8, .read32 = mock_read32,
		.read64 = mock_read64, .write8 = mock_write8,
		.write32 = mock_write32, .write64 = mock_write64, .stall = mock_stall,
	};
	transport = (struct cdk2_tpm2_transport){
		.interface = CDK2_TPM2_INTERFACE_FIFO, .base = TEST_BASE,
		.timeout_us = 120, .io = &io,
	};
	failures += expect(cdk2_tpm2_request_locality(&transport) == EFI_SUCCESS,
		"FIFO locality request failed");
	command[5] = 12; output_size = sizeof(output);
	failures += expect(cdk2_tpm2_submit(&transport, command, sizeof(command), output,
		&output_size) == EFI_SUCCESS && output_size == 10U &&
		memcmp(command, mock.command, sizeof(command)) == 0,
		"FIFO trace did not complete");

	memset(&mock, 0, sizeof(mock));
	mock.interface = CDK2_TPM2_INTERFACE_CRB;
	memcpy(mock.response, (UINT8[]){ 0x80, 0x01, 0, 0, 0, 10, 0, 0, 1, 0x43 }, 10);
	io.context = &mock;
	transport.interface = CDK2_TPM2_INTERFACE_CRB;
	failures += expect(cdk2_tpm2_request_locality(&transport) == EFI_SUCCESS,
		"CRB locality request failed");
	output_size = sizeof(output);
	failures += expect(cdk2_tpm2_submit(&transport, command, sizeof(command), output,
		&output_size) == EFI_SUCCESS && output_size == 10U &&
		memcmp(command, mock.command, sizeof(command)) == 0,
		"CRB trace did not complete");
	mock.force_start_timeout = 1; output_size = sizeof(output);
	failures += expect(cdk2_tpm2_submit(&transport, command, sizeof(command), output,
		&output_size) == EFI_DEVICE_ERROR && mock.cancel_writes == 2U,
		"CRB timeout did not cancel and recover");
	return failures == 0 ? 0 : 1;
}
