/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TCG2_COMMANDS_H_
#define CDK2_TCG2_COMMANDS_H_

#include <cdk2/tcg2_measure.h>
#include <cdk2/tcg2_transport.h>

#define CDK2_TPM2_RC_SUCCESS 0U
#define CDK2_TPM2_RC_INITIALIZE 0x100U
#define CDK2_TPM2_SU_CLEAR 0U
#define CDK2_TPM2_SU_STATE 1U
#define CDK2_TPM2_CAP_PCRS 5U
#define CDK2_TPM2_CAP_PROPERTIES 6U
#define CDK2_TPM2_CC_STARTUP 0x00000144U
#define CDK2_TPM2_CC_GET_CAPABILITY 0x0000017aU
#define CDK2_TPM2_CC_HASH_SEQUENCE_START 0x00000186U
#define CDK2_TPM2_CC_SEQUENCE_UPDATE 0x0000015cU
#define CDK2_TPM2_CC_SEQUENCE_COMPLETE 0x0000013eU
#define CDK2_TPM2_CC_PCR_EXTEND 0x00000182U
#define CDK2_TPM2_RS_PW 0x40000009U
#define CDK2_TPM2_RH_NULL 0x40000007U
#define CDK2_TPM2_MAX_PCR_BANKS 16U
#define CDK2_TPM2_SEQUENCE_CHUNK 1024U

#define CDK2_TPM2_HASH_SHA1 (1U << 0)
#define CDK2_TPM2_HASH_SHA256 (1U << 1)
#define CDK2_TPM2_HASH_SHA384 (1U << 2)
#define CDK2_TPM2_HASH_SHA512 (1U << 3)
#define CDK2_TPM2_HASH_SM3_256 (1U << 4)

struct cdk2_tpm2_result {
	UINT32 response_code;
	UINT32 response_size;
};

EFI_STATUS cdk2_tpm2_execute(const struct cdk2_tpm2_transport *transport,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size, struct cdk2_tpm2_result *result);
EFI_STATUS cdk2_tpm2_startup(const struct cdk2_tpm2_transport *transport,
	UINT16 startup_type, UINT32 *response_code);
EFI_STATUS cdk2_tpm2_get_property(const struct cdk2_tpm2_transport *transport,
	UINT32 property, UINT32 *value, UINT32 *response_code);
EFI_STATUS cdk2_tpm2_get_pcr_banks(const struct cdk2_tpm2_transport *transport,
	UINT32 *supported, UINT32 *active, UINT32 *bank_count,
	UINT32 *response_code);
EFI_STATUS cdk2_tpm2_hash_sequence_start(
	const struct cdk2_tpm2_transport *transport, TPMI_ALG_HASH algorithm,
	UINT32 *handle, UINT32 *response_code);
EFI_STATUS cdk2_tpm2_sequence_update(
	const struct cdk2_tpm2_transport *transport, UINT32 handle,
	const void *data, UINT16 size, UINT32 *response_code);
EFI_STATUS cdk2_tpm2_sequence_complete(
	const struct cdk2_tpm2_transport *transport, UINT32 handle,
	const void *data, UINT16 size, UINT8 *digest, UINT16 digest_capacity,
	UINT16 *digest_size, UINT32 *response_code);
EFI_STATUS cdk2_tpm2_pcr_extend(const struct cdk2_tpm2_transport *transport,
	TPM_PCRINDEX pcr_index, const struct cdk2_tcg2_digest *digests,
	UINT32 digest_count, UINT32 *response_code);
EFI_STATUS cdk2_tpm2_hash_spans(void *context, TPMI_ALG_HASH algorithm,
	const struct cdk2_tcg2_span *spans, UINT32 span_count, UINT8 *digest,
	UINT16 digest_size);
EFI_STATUS cdk2_tpm2_extend_digests(void *context, TPM_PCRINDEX pcr_index,
	const struct cdk2_tcg2_digest *digests, UINT32 digest_count,
	UINT32 *response_code);

#endif
