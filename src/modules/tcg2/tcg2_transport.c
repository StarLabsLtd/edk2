/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_transport.h>

#define PTP_INTERFACE_TYPE_MASK 0x0fU
#define PTP_INTERFACE_VERSION_SHIFT 4U
#define PTP_INTERFACE_VERSION_MASK 0x0fU
#define PTP_CAP_FIFO (1U << 13)
#define PTP_CAP_CRB (1U << 14)
#define PTP_FIFO_CAP_VERSION_SHIFT 28U
#define PTP_FIFO_CAP_VERSION_MASK 0x07U

static UINT16 read_be16(const UINT8 *bytes)
{
	return (UINT16)((UINT16)bytes[0] << 8) | bytes[1];
}

static UINT32 read_be32(const UINT8 *bytes)
{
	return (UINT32)bytes[0] << 24 | (UINT32)bytes[1] << 16 |
		(UINT32)bytes[2] << 8 | bytes[3];
}

enum cdk2_tpm2_interface cdk2_tpm2_detect_interface(UINT32 interface_id,
	UINT32 interface_capability)
{
	UINT32 type = interface_id & PTP_INTERFACE_TYPE_MASK;
	UINT32 version = interface_id >> PTP_INTERFACE_VERSION_SHIFT &
		PTP_INTERFACE_VERSION_MASK;

	if (interface_id == MAX_UINT32)
		return CDK2_TPM2_INTERFACE_INVALID;
	if (type == 1U && (version == 1U || version == 2U) &&
	    (interface_id & PTP_CAP_CRB) != 0U)
		return CDK2_TPM2_INTERFACE_CRB;
	if (type == 0U && version == 0U && (interface_id & PTP_CAP_FIFO) != 0U &&
	    (interface_capability >> PTP_FIFO_CAP_VERSION_SHIFT &
	     PTP_FIFO_CAP_VERSION_MASK) == 3U)
		return CDK2_TPM2_INTERFACE_FIFO;
	if (type == 0x0fU)
		return CDK2_TPM2_INTERFACE_TIS;
	return CDK2_TPM2_INTERFACE_INVALID;
}

EFI_STATUS cdk2_tpm2_validate_command(const UINT8 *command, UINT32 command_size)
{
	UINT16 tag;

	if (command == NULL || command_size < CDK2_TPM2_HEADER_SIZE)
		return EFI_INVALID_PARAMETER;
	tag = read_be16(command);
	if (tag != CDK2_TPM2_ST_NO_SESSIONS && tag != CDK2_TPM2_ST_SESSIONS)
		return EFI_COMPROMISED_DATA;
	if (read_be32(command + 2) != command_size)
		return EFI_COMPROMISED_DATA;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_parse_response(const UINT8 *response, UINT32 available,
	struct cdk2_tpm2_response *header)
{
	if (response == NULL || header == NULL || available < CDK2_TPM2_HEADER_SIZE)
		return EFI_INVALID_PARAMETER;
	header->tag = read_be16(response);
	header->size = read_be32(response + 2);
	header->code = read_be32(response + 6);
	if (header->tag != CDK2_TPM2_ST_NO_SESSIONS &&
	    header->tag != CDK2_TPM2_ST_SESSIONS)
		return EFI_COMPROMISED_DATA;
	if (header->size < CDK2_TPM2_HEADER_SIZE)
		return EFI_COMPROMISED_DATA;
	if (header->size > available)
		return EFI_BUFFER_TOO_SMALL;
	return EFI_SUCCESS;
}
