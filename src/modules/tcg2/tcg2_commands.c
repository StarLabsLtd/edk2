/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_commands.h>
#include <industry_standard/tpm20.h>

static UINT16 read_be16(const UINT8 *bytes)
{
	return (UINT16)((UINT16)bytes[0] << 8) | bytes[1];
}

static UINT32 read_be32(const UINT8 *bytes)
{
	return (UINT32)bytes[0] << 24 | (UINT32)bytes[1] << 16 |
		(UINT32)bytes[2] << 8 | bytes[3];
}

static void write_be16(UINT8 *bytes, UINT16 value)
{
	bytes[0] = (UINT8)(value >> 8); bytes[1] = (UINT8)value;
}

static void write_be32(UINT8 *bytes, UINT32 value)
{
	bytes[0] = (UINT8)(value >> 24); bytes[1] = (UINT8)(value >> 16);
	bytes[2] = (UINT8)(value >> 8); bytes[3] = (UINT8)value;
}

static void command_header(UINT8 *command, UINT32 size, UINT32 code)
{
	write_be16(command, CDK2_TPM2_ST_NO_SESSIONS);
	write_be32(command + 2, size);
	write_be32(command + 6, code);
}

EFI_STATUS cdk2_tpm2_execute(const struct cdk2_tpm2_transport *transport,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size, struct cdk2_tpm2_result *result)
{
	struct cdk2_tpm2_response header;
	EFI_STATUS status;

	if (result == NULL)
		return EFI_INVALID_PARAMETER;
	result->response_code = 0;
	result->response_size = 0;
	status = cdk2_tpm2_submit(transport, command, command_size, response,
		response_size);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_tpm2_parse_response(response, *response_size, &header);
	if (EFI_ERROR(status))
		return status;
	result->response_code = header.code;
	result->response_size = header.size;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_startup(const struct cdk2_tpm2_transport *transport,
	UINT16 startup_type, UINT32 *response_code)
{
	UINT8 command[12];
	UINT8 response[CDK2_TPM2_HEADER_SIZE];
	UINT32 response_size = sizeof(response);
	struct cdk2_tpm2_result result;
	EFI_STATUS status;

	if (response_code == NULL ||
	    (startup_type != CDK2_TPM2_SU_CLEAR && startup_type != CDK2_TPM2_SU_STATE))
		return EFI_INVALID_PARAMETER;
	command_header(command, sizeof(command), CDK2_TPM2_CC_STARTUP);
	write_be16(command + CDK2_TPM2_HEADER_SIZE, startup_type);
	status = cdk2_tpm2_execute(transport, command, sizeof(command), response,
		&response_size, &result);
	if (EFI_ERROR(status))
		return status;
	*response_code = result.response_code;
	if (result.response_code == CDK2_TPM2_RC_SUCCESS ||
	    result.response_code == CDK2_TPM2_RC_INITIALIZE)
		return EFI_SUCCESS;
	return EFI_DEVICE_ERROR;
}

static EFI_STATUS get_capability(const struct cdk2_tpm2_transport *transport,
	UINT32 capability, UINT32 property, UINT32 count, UINT8 *response,
	UINT32 *response_size, struct cdk2_tpm2_result *result)
{
	UINT8 command[22];

	command_header(command, sizeof(command), CDK2_TPM2_CC_GET_CAPABILITY);
	write_be32(command + 10, capability);
	write_be32(command + 14, property);
	write_be32(command + 18, count);
	return cdk2_tpm2_execute(transport, command, sizeof(command), response,
		response_size, result);
}

EFI_STATUS cdk2_tpm2_get_property(const struct cdk2_tpm2_transport *transport,
	UINT32 property, UINT32 *value, UINT32 *response_code)
{
	UINT8 response[27];
	UINT32 size = sizeof(response);
	struct cdk2_tpm2_result result;
	EFI_STATUS status;

	if (value == NULL || response_code == NULL)
		return EFI_INVALID_PARAMETER;
	status = get_capability(transport, CDK2_TPM2_CAP_PROPERTIES, property, 1,
		response, &size, &result);
	if (EFI_ERROR(status))
		return status;
	*response_code = result.response_code;
	if (result.response_code != CDK2_TPM2_RC_SUCCESS)
		return EFI_DEVICE_ERROR;
	if (size < sizeof(response) || read_be32(response + 11) !=
	    CDK2_TPM2_CAP_PROPERTIES || read_be32(response + 15) != 1U ||
	    read_be32(response + 19) != property)
		return EFI_COMPROMISED_DATA;
	*value = read_be32(response + 23);
	return EFI_SUCCESS;
}

static UINT32 hash_bit(UINT16 algorithm)
{
	switch (algorithm) {
	case TPM_ALG_SHA1: return CDK2_TPM2_HASH_SHA1;
	case TPM_ALG_SHA256: return CDK2_TPM2_HASH_SHA256;
	case TPM_ALG_SHA384: return CDK2_TPM2_HASH_SHA384;
	case TPM_ALG_SHA512: return CDK2_TPM2_HASH_SHA512;
	case TPM_ALG_SM3_256: return CDK2_TPM2_HASH_SM3_256;
	default: return 0;
	}
}

EFI_STATUS cdk2_tpm2_get_pcr_banks(const struct cdk2_tpm2_transport *transport,
	UINT32 *supported, UINT32 *active, UINT32 *bank_count,
	UINT32 *response_code)
{
	UINT8 response[256];
	UINT32 size = sizeof(response);
	struct cdk2_tpm2_result result;
	UINT32 count;
	UINT32 index;
	UINT32 offset;
	UINT32 bit;
	UINT8 select_size;
	EFI_STATUS status;

	if (supported == NULL || active == NULL || bank_count == NULL ||
	    response_code == NULL)
		return EFI_INVALID_PARAMETER;
	status = get_capability(transport, CDK2_TPM2_CAP_PCRS, 0, 1, response,
		&size, &result);
	if (EFI_ERROR(status))
		return status;
	*response_code = result.response_code;
	if (result.response_code != CDK2_TPM2_RC_SUCCESS)
		return EFI_DEVICE_ERROR;
	if (size < 19U || read_be32(response + 11) != CDK2_TPM2_CAP_PCRS)
		return EFI_COMPROMISED_DATA;
	count = read_be32(response + 15);
	if (count == 0 || count > CDK2_TPM2_MAX_PCR_BANKS)
		return EFI_COMPROMISED_DATA;
	*supported = 0; *active = 0; *bank_count = count; offset = 19;
	for (index = 0; index < count; index++) {
		if (offset + 3U > size)
			return EFI_COMPROMISED_DATA;
		bit = hash_bit(read_be16(response + offset));
		select_size = response[offset + 2]; offset += 3;
		if (select_size == 0 || offset + select_size > size)
			return EFI_COMPROMISED_DATA;
		*supported |= bit;
		while (select_size-- != 0)
			if (response[offset++] != 0) *active |= bit;
	}
	return EFI_SUCCESS;
}
