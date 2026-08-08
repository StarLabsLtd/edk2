/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TCG2_TRANSPORT_H_
#define CDK2_TCG2_TRANSPORT_H_

#include <uefi.h>

#define CDK2_TPM2_HEADER_SIZE 10U
#define CDK2_TPM2_ST_NO_SESSIONS 0x8001U
#define CDK2_TPM2_ST_SESSIONS 0x8002U

enum cdk2_tpm2_interface {
	CDK2_TPM2_INTERFACE_FIFO,
	CDK2_TPM2_INTERFACE_CRB,
	CDK2_TPM2_INTERFACE_TIS,
	CDK2_TPM2_INTERFACE_INVALID,
};

struct cdk2_tpm2_response {
	UINT16 tag;
	UINT32 size;
	UINT32 code;
};

typedef UINT8 cdk2_tpm2_read8_fn(void *context, UINT64 address);
typedef UINT32 cdk2_tpm2_read32_fn(void *context, UINT64 address);
typedef UINT64 cdk2_tpm2_read64_fn(void *context, UINT64 address);
typedef void cdk2_tpm2_write8_fn(void *context, UINT64 address, UINT8 value);
typedef void cdk2_tpm2_write32_fn(void *context, UINT64 address, UINT32 value);
typedef void cdk2_tpm2_write64_fn(void *context, UINT64 address, UINT64 value);
typedef void cdk2_tpm2_stall_fn(void *context, UINT32 microseconds);

struct cdk2_tpm2_io {
	void *context;
	cdk2_tpm2_read8_fn *read8;
	cdk2_tpm2_read32_fn *read32;
	cdk2_tpm2_read64_fn *read64;
	cdk2_tpm2_write8_fn *write8;
	cdk2_tpm2_write32_fn *write32;
	cdk2_tpm2_write64_fn *write64;
	cdk2_tpm2_stall_fn *stall;
};

struct cdk2_tpm2_transport {
	enum cdk2_tpm2_interface interface;
	UINT64 base;
	UINT32 timeout_us;
	const struct cdk2_tpm2_io *io;
};

enum cdk2_tpm2_interface cdk2_tpm2_detect_interface(UINT32 interface_id,
	UINT32 interface_capability);
EFI_STATUS cdk2_tpm2_validate_command(const UINT8 *command, UINT32 command_size);
EFI_STATUS cdk2_tpm2_parse_response(const UINT8 *response, UINT32 available,
	struct cdk2_tpm2_response *header);
EFI_STATUS cdk2_tpm2_request_locality(const struct cdk2_tpm2_transport *transport);
EFI_STATUS cdk2_tpm2_submit(const struct cdk2_tpm2_transport *transport,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size);

#endif
