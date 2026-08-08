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

static void copy_bytes(UINT8 *destination, const UINT8 *source, UINT32 size)
{
	UINT32 index;

	for (index = 0; index < size; index++)
		destination[index] = source[index];
}

static void command_header(UINT8 *command, UINT32 size, UINT32 code)
{
	write_be16(command, CDK2_TPM2_ST_NO_SESSIONS);
	write_be32(command + 2, size);
	write_be32(command + 6, code);
}

static UINT32 password_session(UINT8 *command)
{
	write_be32(command, 9);
	write_be32(command + 4, CDK2_TPM2_RS_PW);
	write_be16(command + 8, 0);
	command[10] = 0;
	write_be16(command + 11, 0);
	return 13;
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

EFI_STATUS cdk2_tpm2_hash_sequence_start(
	const struct cdk2_tpm2_transport *transport, TPMI_ALG_HASH algorithm,
	UINT32 *handle, UINT32 *response_code)
{
	UINT8 command[14];
	UINT8 response[14];
	UINT32 size = sizeof(response);
	struct cdk2_tpm2_result result;
	EFI_STATUS status;

	if (handle == NULL || response_code == NULL)
		return EFI_INVALID_PARAMETER;
	command_header(command, sizeof(command), CDK2_TPM2_CC_HASH_SEQUENCE_START);
	write_be16(command + 10, 0);
	write_be16(command + 12, algorithm);
	status = cdk2_tpm2_execute(transport, command, sizeof(command), response,
		&size, &result);
	if (EFI_ERROR(status))
		return status;
	*response_code = result.response_code;
	if (result.response_code != 0)
		return EFI_DEVICE_ERROR;
	if (size != sizeof(response))
		return EFI_COMPROMISED_DATA;
	*handle = read_be32(response + 10);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_sequence_update(
	const struct cdk2_tpm2_transport *transport, UINT32 handle,
	const void *data_buffer, UINT16 data_size, UINT32 *response_code)
{
	const UINT8 *data = data_buffer;
	UINT8 command[10 + 4 + 13 + 2 + CDK2_TPM2_SEQUENCE_CHUNK];
	UINT8 response[10];
	UINT32 size = sizeof(response);
	UINT32 offset;
	struct cdk2_tpm2_result result;
	EFI_STATUS status;

	if (response_code == NULL || data_size > CDK2_TPM2_SEQUENCE_CHUNK ||
	    (data_size != 0 && data == NULL))
		return EFI_INVALID_PARAMETER;
	offset = 10;
	write_be32(command + offset, handle);
	offset += 4;
	offset += password_session(command + offset);
	write_be16(command + offset, data_size);
	offset += 2;
	copy_bytes(command + offset, data, data_size);
	offset += data_size;
	command_header(command, offset, CDK2_TPM2_CC_SEQUENCE_UPDATE);
	command[0] = 0x80;
	command[1] = 0x02;
	status = cdk2_tpm2_execute(transport, command, offset, response, &size, &result);
	if (EFI_ERROR(status))
		return status;
	*response_code = result.response_code;
	return result.response_code == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS cdk2_tpm2_sequence_complete(
	const struct cdk2_tpm2_transport *transport, UINT32 handle,
	const void *data_buffer, UINT16 data_size, UINT8 *digest,
	UINT16 digest_capacity, UINT16 *digest_size, UINT32 *response_code)
{
	const UINT8 *data = data_buffer;
	UINT8 command[10 + 4 + 13 + 2 + CDK2_TPM2_SEQUENCE_CHUNK + 4];
	UINT8 response[14 + SHA512_DIGEST_SIZE];
	UINT32 size = sizeof(response);
	UINT32 offset = 10;
	UINT16 returned;
	struct cdk2_tpm2_result result;
	EFI_STATUS status;

	if (digest == NULL || digest_size == NULL || response_code == NULL ||
	    data_size > CDK2_TPM2_SEQUENCE_CHUNK ||
	    (data_size != 0 && data == NULL))
		return EFI_INVALID_PARAMETER;
	write_be32(command + offset, handle);
	offset += 4;
	offset += password_session(command + offset);
	write_be16(command + offset, data_size);
	offset += 2;
	copy_bytes(command + offset, data, data_size);
	offset += data_size;
	write_be32(command + offset, CDK2_TPM2_RH_NULL);
	offset += 4;
	command_header(command, offset, CDK2_TPM2_CC_SEQUENCE_COMPLETE);
	command[0] = 0x80;
	command[1] = 0x02;
	status = cdk2_tpm2_execute(transport, command, offset, response, &size, &result);
	if (EFI_ERROR(status))
		return status;
	*response_code = result.response_code;
	if (result.response_code != 0)
		return EFI_DEVICE_ERROR;
	if (size < 16 || read_be32(response + 10) > size - 14)
		return EFI_COMPROMISED_DATA;
	returned = read_be16(response + 14);
	*digest_size = returned;
	if (returned > digest_capacity)
		return EFI_BUFFER_TOO_SMALL;
	if (returned > size - 16)
		return EFI_COMPROMISED_DATA;
	copy_bytes(digest, response + 16, returned);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_pcr_extend(const struct cdk2_tpm2_transport *transport,
	TPM_PCRINDEX pcr_index, const struct cdk2_tcg2_digest *digests,
	UINT32 digest_count, UINT32 *response_code)
{
	UINT8 command[10 + 4 + 13 + 4 +
		CDK2_TCG2_MAX_DIGESTS * (2 + SHA512_DIGEST_SIZE)];
	UINT8 response[10];
	UINT32 size = sizeof(response);
	UINT32 offset = 10;
	UINT32 index;
	struct cdk2_tpm2_result result;
	EFI_STATUS status;

	if (response_code == NULL || digests == NULL || digest_count == 0 ||
	    digest_count > CDK2_TCG2_MAX_DIGESTS || pcr_index > 23)
		return EFI_INVALID_PARAMETER;
	write_be32(command + offset, pcr_index);
	offset += 4;
	offset += password_session(command + offset);
	write_be32(command + offset, digest_count);
	offset += 4;
	for (index = 0; index < digest_count; index++) {
		if (digests[index].size == 0 ||
		    digests[index].size > sizeof(digests[index].bytes))
			return EFI_INVALID_PARAMETER;
		write_be16(command + offset, digests[index].algorithm);
		offset += 2;
		copy_bytes(command + offset, digests[index].bytes, digests[index].size);
		offset += digests[index].size;
	}
	command_header(command, offset, CDK2_TPM2_CC_PCR_EXTEND);
	command[0] = 0x80;
	command[1] = 0x02;
	status = cdk2_tpm2_execute(transport, command, offset, response, &size, &result);
	if (EFI_ERROR(status))
		return status;
	*response_code = result.response_code;
	return result.response_code == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}
