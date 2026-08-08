/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TCG2_MEASURE_H_
#define CDK2_TCG2_MEASURE_H_

#include <cdk2/tcg2_event_log.h>

#define CDK2_TCG2_MAX_SPANS 100U

struct cdk2_tcg2_span {
	const UINT8 *data;
	UINT32 size;
};

typedef EFI_STATUS cdk2_tcg2_hash_fn(void *context, TPMI_ALG_HASH algorithm,
	const struct cdk2_tcg2_span *spans, UINT32 span_count, UINT8 *digest,
	UINT16 digest_size);
typedef EFI_STATUS cdk2_tcg2_extend_fn(void *context, TPM_PCRINDEX pcr_index,
	const struct cdk2_tcg2_digest *digests, UINT32 digest_count,
	UINT32 *response_code);

struct cdk2_tcg2_measurement {
	struct cdk2_tcg2_logs *logs;
	void *context;
	cdk2_tcg2_hash_fn *hash;
	cdk2_tcg2_extend_fn *extend;
	TPMI_ALG_HASH algorithms[CDK2_TCG2_MAX_DIGESTS];
	UINT32 algorithm_count;
};

EFI_STATUS cdk2_tcg2_measure_spans(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type,
	const struct cdk2_tcg2_span *spans, UINT32 span_count,
	const void *event, UINT32 event_size, UINT32 *response_code);
EFI_STATUS cdk2_tcg2_extend_spans(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, const struct cdk2_tcg2_span *spans,
	UINT32 span_count, UINT32 *response_code);
EFI_STATUS cdk2_tcg2_measure_pe(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const void *image,
	UINT32 image_size, const void *event, UINT32 event_size,
	UINT32 *response_code);
EFI_STATUS cdk2_tcg2_extend_pe(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, const void *image, UINT32 image_size,
	UINT32 *response_code);
EFI_STATUS cdk2_tcg2_measure_variable(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const EFI_GUID *vendor,
	const CHAR16 *name, UINT32 name_bytes, const void *data, UINT32 data_size,
	UINT32 *response_code);
EFI_STATUS cdk2_tcg2_measure_action(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const char *action,
	UINT32 *response_code);
EFI_STATUS cdk2_tcg2_measure_separator(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, UINT32 value,
	UINT32 *response_code);

#endif
