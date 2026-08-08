/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_commands.h>
#include <stdio.h>
#include <string.h>

#define BASE 0xfed40000U

struct command_mock { UINT8 data[256]; UINT32 response_code; };

static UINT32 be32(const UINT8 *bytes)
{
	return (UINT32)bytes[0] << 24 | (UINT32)bytes[1] << 16 |
		(UINT32)bytes[2] << 8 | bytes[3];
}

static void put32(UINT8 *bytes, UINT32 value)
{
	bytes[0] = (UINT8)(value >> 24); bytes[1] = (UINT8)(value >> 16);
	bytes[2] = (UINT8)(value >> 8); bytes[3] = (UINT8)value;
}

static UINT8 read8(void *context, UINT64 address)
{
	struct command_mock *mock = context;
	if (address == BASE) return 0;
	return mock->data[address - BASE - 0x80U];
}

static UINT32 read32(void *context, UINT64 address)
{
	(void)context;
	if (address - BASE == 0x44U) return 2U;
	return 0;
}

static UINT64 read64(void *context, UINT64 address)
{
	(void)context; (void)address; return 0;
}

static void write8(void *context, UINT64 address, UINT8 value)
{
	struct command_mock *mock = context;
	mock->data[address - BASE - 0x80U] = value;
}

static void make_header(struct command_mock *mock, UINT32 size)
{
	memset(mock->data, 0, 256); mock->data[0] = 0x80; mock->data[1] = 0x01;
	put32(mock->data + 2, size); put32(mock->data + 6, mock->response_code);
}

static void write32(void *context, UINT64 address, UINT32 value)
{
	struct command_mock *mock = context;
	UINT32 code;
	UINT32 property;

	if (address - BASE != 0x4cU || value != 1U) return;
	code = be32(mock->data + 6);
	if (code == CDK2_TPM2_CC_STARTUP) { make_header(mock, 10); return; }
	property = be32(mock->data + 14);
	if (property != 0) {
		make_header(mock, 27); mock->data[10] = 0;
		put32(mock->data + 11, CDK2_TPM2_CAP_PROPERTIES);
		put32(mock->data + 15, 1); put32(mock->data + 19, property);
		put32(mock->data + 23, 0x53575450U); return;
	}
	make_header(mock, 27); mock->data[10] = 0;
	put32(mock->data + 11, CDK2_TPM2_CAP_PCRS); put32(mock->data + 15, 2);
	mock->data[19] = 0; mock->data[20] = 4; mock->data[21] = 3;
	mock->data[22] = 0xff; mock->data[23] = 0; mock->data[24] = 0;
	mock->data[25] = 0; mock->data[26] = 0x0b; mock->data[27] = 3;
	mock->data[28] = 0xff; mock->data[29] = 0xff; mock->data[30] = 0xff;
	put32(mock->data + 2, 31);
}

static void write64(void *context, UINT64 address, UINT64 value)
{
	(void)context; (void)address; (void)value;
}

static void stall(void *context, UINT32 microseconds)
{
	(void)context; (void)microseconds;
}

static int expect(int condition, const char *message)
{
	if (!condition) fprintf(stderr, "tcg2-commands test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct command_mock mock = {0};
	struct cdk2_tpm2_io io = { &mock, read8, read32, read64, write8,
		write32, write64, stall };
	struct cdk2_tpm2_transport transport = {
		CDK2_TPM2_INTERFACE_CRB, BASE, 120, &io };
	UINT32 code, value, supported, active, banks;
	int failures = 0;

	failures += expect(cdk2_tpm2_startup(&transport, CDK2_TPM2_SU_CLEAR, &code) ==
		EFI_SUCCESS && code == 0, "Startup failed");
	mock.response_code = CDK2_TPM2_RC_INITIALIZE;
	failures += expect(cdk2_tpm2_startup(&transport, CDK2_TPM2_SU_CLEAR, &code) ==
		EFI_SUCCESS && code == CDK2_TPM2_RC_INITIALIZE,
		"already-started TPM was rejected");
	mock.response_code = 0;
	failures += expect(cdk2_tpm2_get_property(&transport, 0x105U, &value, &code) ==
		EFI_SUCCESS && value == 0x53575450U, "manufacturer property failed");
	failures += expect(cdk2_tpm2_get_pcr_banks(&transport, &supported, &active,
		&banks, &code) == EFI_SUCCESS && banks == 2U && supported == 3U &&
		active == 3U, "PCR bank capability failed");
	mock.response_code = 0x143U;
	failures += expect(cdk2_tpm2_get_property(&transport, 0x105U, &value, &code) ==
		EFI_DEVICE_ERROR && code == 0x143U, "TPM error code was lost");
	return failures == 0 ? 0 : 1;
}
