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

enum cdk2_tpm2_interface cdk2_tpm2_detect_interface(UINT32 interface_id,
	UINT32 interface_capability);
EFI_STATUS cdk2_tpm2_validate_command(const UINT8 *command, UINT32 command_size);
EFI_STATUS cdk2_tpm2_parse_response(const UINT8 *response, UINT32 available,
	struct cdk2_tpm2_response *header);

#endif
