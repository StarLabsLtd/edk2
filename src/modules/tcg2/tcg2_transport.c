/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_transport.h>

#define PTP_INTERFACE_TYPE_MASK 0x0fU
#define PTP_INTERFACE_VERSION_SHIFT 4U
#define PTP_INTERFACE_VERSION_MASK 0x0fU
#define PTP_CAP_FIFO (1U << 13)
#define PTP_CAP_CRB (1U << 14)
#define PTP_FIFO_CAP_VERSION_SHIFT 28U
#define PTP_FIFO_CAP_VERSION_MASK 0x07U

#define TPM_POLL_US 30U

#define FIFO_ACCESS 0x0000U
#define FIFO_STS 0x0018U
#define FIFO_DATA 0x0024U
#define FIFO_ACCESS_VALID (1U << 7)
#define FIFO_ACCESS_ACTIVE (1U << 5)
#define FIFO_ACCESS_REQUEST (1U << 1)
#define FIFO_STS_VALID (1U << 7)
#define FIFO_STS_COMMAND_READY (1U << 6)
#define FIFO_STS_GO (1U << 5)
#define FIFO_STS_DATA_AVAILABLE (1U << 4)
#define FIFO_STS_EXPECT (1U << 3)
#define FIFO_STS_BURST_SHIFT 8U

#define CRB_LOCALITY_CONTROL 0x0008U
#define CRB_LOCALITY_STATUS 0x000cU
#define CRB_CONTROL_REQUEST 0x0040U
#define CRB_CONTROL_STATUS 0x0044U
#define CRB_CONTROL_CANCEL 0x0048U
#define CRB_CONTROL_START 0x004cU
#define CRB_COMMAND_SIZE 0x0058U
#define CRB_COMMAND_ADDRESS 0x005cU
#define CRB_RESPONSE_SIZE 0x0064U
#define CRB_RESPONSE_ADDRESS 0x0068U
#define CRB_DATA_BUFFER 0x0080U
#define CRB_DATA_BUFFER_SIZE 0x0f80U
#define CRB_LOCALITY_REQUEST 1U
#define CRB_LOCALITY_GRANTED 1U
#define CRB_REQUEST_COMMAND_READY 1U
#define CRB_REQUEST_GO_IDLE 2U
#define CRB_STATUS_IDLE 2U

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

static EFI_STATUS validate_transport(const struct cdk2_tpm2_transport *transport)
{
	const struct cdk2_tpm2_io *io;

	if (transport == NULL || transport->io == NULL || transport->timeout_us == 0)
		return EFI_INVALID_PARAMETER;
	io = transport->io;
	if (io->read8 == NULL || io->read32 == NULL || io->write8 == NULL ||
	    io->write32 == NULL || io->stall == NULL)
		return EFI_INVALID_PARAMETER;
	if (transport->interface == CDK2_TPM2_INTERFACE_CRB &&
	    (io->read64 == NULL || io->write64 == NULL))
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}

static EFI_STATUS wait32(const struct cdk2_tpm2_transport *transport,
	UINT64 offset, UINT32 set, UINT32 clear)
{
	UINT32 elapsed;
	UINT32 value;

	for (elapsed = 0; elapsed < transport->timeout_us; elapsed += TPM_POLL_US) {
		value = transport->io->read32(transport->io->context,
			transport->base + offset);
		if ((value & set) == set && (value & clear) == 0)
			return EFI_SUCCESS;
		transport->io->stall(transport->io->context, TPM_POLL_US);
	}
	return EFI_TIMEOUT;
}

static EFI_STATUS wait8(const struct cdk2_tpm2_transport *transport,
	UINT64 offset, UINT8 set, UINT8 clear)
{
	UINT32 elapsed;
	UINT8 value;

	for (elapsed = 0; elapsed < transport->timeout_us; elapsed += TPM_POLL_US) {
		value = transport->io->read8(transport->io->context,
			transport->base + offset);
		if ((value & set) == set && (value & clear) == 0)
			return EFI_SUCCESS;
		transport->io->stall(transport->io->context, TPM_POLL_US);
	}
	return EFI_TIMEOUT;
}

EFI_STATUS cdk2_tpm2_request_locality(const struct cdk2_tpm2_transport *transport)
{
	EFI_STATUS status = validate_transport(transport);
	UINT8 access;

	if (EFI_ERROR(status))
		return status;
	access = transport->io->read8(transport->io->context, transport->base);
	if (access == MAX_UINT8)
		return EFI_NOT_FOUND;
	if (transport->interface == CDK2_TPM2_INTERFACE_CRB) {
		transport->io->write32(transport->io->context,
			transport->base + CRB_LOCALITY_CONTROL, CRB_LOCALITY_REQUEST);
		return wait32(transport, CRB_LOCALITY_STATUS, CRB_LOCALITY_GRANTED, 0);
	}
	if (transport->interface != CDK2_TPM2_INTERFACE_FIFO &&
	    transport->interface != CDK2_TPM2_INTERFACE_TIS)
		return EFI_UNSUPPORTED;
	if ((access & (FIFO_ACCESS_VALID | FIFO_ACCESS_ACTIVE)) ==
	    (FIFO_ACCESS_VALID | FIFO_ACCESS_ACTIVE))
		return EFI_SUCCESS;
	transport->io->write8(transport->io->context,
		transport->base + FIFO_ACCESS, FIFO_ACCESS_REQUEST);
	return wait8(transport, FIFO_ACCESS,
		FIFO_ACCESS_VALID | FIFO_ACCESS_ACTIVE, 0);
}

static UINT32 fifo_burst(const struct cdk2_tpm2_transport *transport)
{
	return transport->io->read32(transport->io->context,
		transport->base + FIFO_STS) >> FIFO_STS_BURST_SHIFT & 0xffffU;
}

static EFI_STATUS fifo_wait_burst(const struct cdk2_tpm2_transport *transport,
	UINT32 *burst)
{
	UINT32 elapsed;

	for (elapsed = 0; elapsed < transport->timeout_us; elapsed += TPM_POLL_US) {
		*burst = fifo_burst(transport);
		if (*burst != 0)
			return EFI_SUCCESS;
		transport->io->stall(transport->io->context, TPM_POLL_US);
	}
	return EFI_TIMEOUT;
}

static EFI_STATUS fifo_read_bytes(const struct cdk2_tpm2_transport *transport,
	UINT8 *response, UINT32 start, UINT32 end)
{
	UINT32 burst;
	EFI_STATUS status;

	while (start < end) {
		status = wait32(transport, FIFO_STS,
			FIFO_STS_VALID | FIFO_STS_DATA_AVAILABLE, 0);
		if (EFI_ERROR(status))
			return status;
		status = fifo_wait_burst(transport, &burst);
		if (EFI_ERROR(status))
			return status;
		while (burst-- != 0 && start < end)
			response[start++] = transport->io->read8(transport->io->context,
				transport->base + FIFO_DATA);
	}
	return EFI_SUCCESS;
}

static EFI_STATUS fifo_submit(const struct cdk2_tpm2_transport *transport,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size)
{
	UINT32 index = 0;
	UINT32 burst;
	UINT32 available;
	struct cdk2_tpm2_response header;
	EFI_STATUS status;

	transport->io->write8(transport->io->context, transport->base + FIFO_STS,
		FIFO_STS_COMMAND_READY);
	status = wait32(transport, FIFO_STS,
		FIFO_STS_VALID | FIFO_STS_COMMAND_READY, 0);
	if (EFI_ERROR(status))
		return status;
	while (index < command_size) {
		status = fifo_wait_burst(transport, &burst);
		if (EFI_ERROR(status))
			goto cleanup;
		while (burst-- != 0 && index < command_size)
			transport->io->write8(transport->io->context,
				transport->base + FIFO_DATA, command[index++]);
	}
	status = wait32(transport, FIFO_STS, FIFO_STS_VALID, FIFO_STS_EXPECT);
	if (EFI_ERROR(status))
		goto cleanup;
	transport->io->write8(transport->io->context, transport->base + FIFO_STS,
		FIFO_STS_GO);
	status = wait32(transport, FIFO_STS,
		FIFO_STS_VALID | FIFO_STS_DATA_AVAILABLE, 0);
	if (EFI_ERROR(status))
		goto cleanup;
	available = *response_size;
	status = fifo_read_bytes(transport, response, 0, CDK2_TPM2_HEADER_SIZE);
	if (EFI_ERROR(status))
		goto cleanup;
	status = cdk2_tpm2_parse_response(response, available, &header);
	if (EFI_ERROR(status)) {
		if (status == EFI_BUFFER_TOO_SMALL)
			*response_size = header.size;
		goto cleanup;
	}
	status = fifo_read_bytes(transport, response, CDK2_TPM2_HEADER_SIZE,
		header.size);
	if (EFI_ERROR(status))
		goto cleanup;
	*response_size = header.size;
cleanup:
	transport->io->write8(transport->io->context, transport->base + FIFO_STS,
		FIFO_STS_COMMAND_READY);
	return status;
}

static EFI_STATUS crb_submit(const struct cdk2_tpm2_transport *transport,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size)
{
	UINT64 data = transport->base + CRB_DATA_BUFFER;
	struct cdk2_tpm2_response header;
	EFI_STATUS status;
	UINT32 index;

	if (command_size > CRB_DATA_BUFFER_SIZE ||
	    *response_size > CRB_DATA_BUFFER_SIZE)
		return EFI_BAD_BUFFER_SIZE;

	if ((transport->io->read32(transport->io->context,
	     transport->base + CRB_CONTROL_STATUS) & CRB_STATUS_IDLE) == 0) {
		transport->io->write32(transport->io->context,
			transport->base + CRB_CONTROL_REQUEST, CRB_REQUEST_GO_IDLE);
		status = wait32(transport, CRB_CONTROL_STATUS, CRB_STATUS_IDLE, 0);
		if (EFI_ERROR(status))
			return EFI_DEVICE_ERROR;
	}
	transport->io->write32(transport->io->context,
		transport->base + CRB_CONTROL_REQUEST, CRB_REQUEST_COMMAND_READY);
	status = wait32(transport, CRB_CONTROL_REQUEST, 0, CRB_REQUEST_COMMAND_READY);
	if (EFI_ERROR(status))
		return EFI_DEVICE_ERROR;
	for (index = 0; index < command_size; index++)
		transport->io->write8(transport->io->context, data + index, command[index]);
	transport->io->write32(transport->io->context,
		transport->base + CRB_COMMAND_SIZE, command_size);
	transport->io->write64(transport->io->context,
		transport->base + CRB_COMMAND_ADDRESS, data);
	transport->io->write32(transport->io->context,
		transport->base + CRB_RESPONSE_SIZE, *response_size);
	transport->io->write64(transport->io->context,
		transport->base + CRB_RESPONSE_ADDRESS, data);
	transport->io->write32(transport->io->context,
		transport->base + CRB_CONTROL_START, 1);
	status = wait32(transport, CRB_CONTROL_START, 0, 1);
	if (EFI_ERROR(status)) {
		transport->io->write32(transport->io->context,
			transport->base + CRB_CONTROL_CANCEL, 1);
		status = wait32(transport, CRB_CONTROL_START, 0, 1);
		transport->io->write32(transport->io->context,
			transport->base + CRB_CONTROL_CANCEL, 0);
		if (EFI_ERROR(status))
			return EFI_DEVICE_ERROR;
	}
	for (index = 0; index < CDK2_TPM2_HEADER_SIZE; index++)
		response[index] = transport->io->read8(transport->io->context, data + index);
	status = cdk2_tpm2_parse_response(response, *response_size, &header);
	if (EFI_ERROR(status)) {
		if (status == EFI_BUFFER_TOO_SMALL)
			*response_size = header.size;
	} else {
		for (; index < header.size; index++)
			response[index] = transport->io->read8(transport->io->context,
				data + index);
		*response_size = header.size;
	}
	transport->io->write32(transport->io->context,
		transport->base + CRB_CONTROL_REQUEST, CRB_REQUEST_GO_IDLE);
	return status;
}

EFI_STATUS cdk2_tpm2_submit(const struct cdk2_tpm2_transport *transport,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size)
{
	EFI_STATUS status = validate_transport(transport);

	if (EFI_ERROR(status) || response == NULL || response_size == NULL ||
	    *response_size < CDK2_TPM2_HEADER_SIZE)
		return EFI_INVALID_PARAMETER;
	status = cdk2_tpm2_validate_command(command, command_size);
	if (EFI_ERROR(status))
		return status;
	if (transport->interface == CDK2_TPM2_INTERFACE_CRB)
		return crb_submit(transport, command, command_size, response, response_size);
	if (transport->interface == CDK2_TPM2_INTERFACE_FIFO ||
	    transport->interface == CDK2_TPM2_INTERFACE_TIS)
		return fifo_submit(transport, command, command_size, response, response_size);
	return EFI_UNSUPPORTED;
}
