/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_commands.h>
#include <stdio.h>
#include <string.h>

#define BASE 0xfed40000U

struct command_mock {
	UINT8 data[256];
	UINT32 response_code;
	BOOLEAN fail_sequence_update;
	UINT32 flushes;
};

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
	if (address == BASE)
		return 0;
	return mock->data[address - BASE - 0x80U];
}

static UINT32 read32(void *context, UINT64 address)
{
	(void)context;
	if (address - BASE == 0x44U)
		return 2U;
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

	if (address - BASE != 0x4cU || value != 1U)
		return;
	code = be32(mock->data + 6);
	if (code == CDK2_TPM2_CC_STARTUP) {
		make_header(mock, 10);
		return;
	}
	if (code == CDK2_TPM2_CC_HASH_SEQUENCE_START) {
		make_header(mock, 14);
		put32(mock->data + 10, 0x80000001U);
		return;
	}
	if (code == CDK2_TPM2_CC_SEQUENCE_COMPLETE) {
		make_header(mock, 48);
		mock->data[0] = 0x80;
		mock->data[1] = 0x02;
		put32(mock->data + 10, 34);
		mock->data[14] = 0;
		mock->data[15] = SHA256_DIGEST_SIZE;
		memset(mock->data + 16, 0xa5, SHA256_DIGEST_SIZE);
		return;
	}
	if (code == CDK2_TPM2_CC_SEQUENCE_UPDATE ||
	    code == CDK2_TPM2_CC_PCR_EXTEND) {
		make_header(mock, 10);
		if (code == CDK2_TPM2_CC_SEQUENCE_UPDATE && mock->fail_sequence_update)
			put32(mock->data + 6, 1U);
		return;
	}
	if (code == CDK2_TPM2_CC_FLUSH_CONTEXT) {
		mock->flushes++;
		make_header(mock, 10);
		return;
	}
	if (code == CDK2_TPM2_CC_PCR_ALLOCATE) {
		make_header(mock, 27);
		mock->data[0] = 0x80;
		mock->data[1] = 0x02;
		put32(mock->data + 10, 13);
		mock->data[14] = 1;
		return;
	}
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
	if (!condition)
		fprintf(stderr, "tcg2-commands test: %s\n", message);
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
	UINT32 handle;
	UINT16 digest_size;
	BOOLEAN allocation_success;
	UINT8 digest[SHA256_DIGEST_SIZE];
	struct cdk2_tcg2_digest extend_digest = {
		.algorithm = TPM_ALG_SHA256,
		.size = SHA256_DIGEST_SIZE,
	};
	struct cdk2_tcg2_span hash_spans[2] = {
		{ (const UINT8 *)"abc", 3 },
		{ (const UINT8 *)"def", 3 },
	};
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
	failures += expect(cdk2_tpm2_hash_sequence_start(&transport, TPM_ALG_SHA256,
		&handle, &code) == EFI_SUCCESS && handle == 0x80000001U && code == 0,
		"HashSequenceStart failed");
	failures += expect(cdk2_tpm2_sequence_update(&transport, handle, "abc", 3,
		&code) == EFI_SUCCESS && code == 0,
		"SequenceUpdate failed");
	failures += expect(cdk2_tpm2_sequence_complete(&transport, handle, NULL, 0,
		digest, sizeof(digest), &digest_size, &code) == EFI_SUCCESS &&
		digest_size == sizeof(digest) && digest[0] == 0xa5,
		"SequenceComplete failed");
	memset(extend_digest.bytes, 0xa5, extend_digest.size);
	failures += expect(cdk2_tpm2_pcr_extend(&transport, 7, &extend_digest, 1,
		&code) == EFI_SUCCESS && code == 0, "PCR_Extend failed");
	failures += expect(cdk2_tpm2_hash_spans(&transport, TPM_ALG_SHA256,
		hash_spans, 2, digest, sizeof(digest)) == EFI_SUCCESS &&
		digest[0] == 0xa5, "native TPM hashing failed");
	mock.fail_sequence_update = TRUE;
	failures += expect(cdk2_tpm2_hash_spans(&transport, TPM_ALG_SHA256,
		hash_spans, 2, digest, sizeof(digest)) == EFI_DEVICE_ERROR &&
		mock.flushes == 1U, "failed sequence was not flushed");
	mock.fail_sequence_update = FALSE;
	failures += expect(cdk2_tpm2_extend_digests(&transport, 7, &extend_digest, 1,
		&code) == EFI_SUCCESS && code == 0, "native TPM extension failed");
	failures += expect(cdk2_tpm2_pcr_allocate(&transport, 3, 2,
		&allocation_success, &code) == EFI_SUCCESS && allocation_success &&
		code == 0, "PCR_Allocate failed");
	mock.response_code = 0x143U;
	failures += expect(cdk2_tpm2_get_property(&transport, 0x105U, &value, &code) ==
		EFI_DEVICE_ERROR && code == 0x143U, "TPM error code was lost");
	return failures == 0 ? 0 : 1;
}
