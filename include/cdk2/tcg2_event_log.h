/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TCG2_EVENT_LOG_H_
#define CDK2_TCG2_EVENT_LOG_H_

#include <industry_standard/tpm20.h>
#include <pi/hob.h>

#define CDK2_TCG2_MAX_DIGEST_SIZE 64U
#define CDK2_TCG2_MAX_DIGESTS HASH_COUNT
#define CDK2_TCG2_EV_NO_ACTION 3U

struct cdk2_tcg2_digest {
	TPMI_ALG_HASH algorithm;
	UINT16 size;
	UINT8 bytes[CDK2_TCG2_MAX_DIGEST_SIZE];
};

struct cdk2_tcg2_event {
	TPM_PCRINDEX pcr_index;
	UINT32 event_type;
	UINT32 digest_count;
	const struct cdk2_tcg2_digest *digests;
	UINT32 event_size;
	const UINT8 *event;
};

struct cdk2_tcg2_data_span { const UINT8 *data; UINT32 size; };

struct cdk2_tcg2_log {
	UINT8 *buffer;
	UINT32 capacity;
	UINT32 used;
	UINT32 last_entry_offset;
	BOOLEAN truncated;
};

struct cdk2_tcg2_logs {
	struct cdk2_tcg2_log main;
	struct cdk2_tcg2_log final;
	BOOLEAN final_active;
	UINT64 event_count;
	UINT64 final_event_count;
	UINT64 *final_count_export;
};

extern const EFI_GUID cdk2_tcg_event2_entry_hob_guid;

EFI_STATUS cdk2_tcg2_log_init(struct cdk2_tcg2_log *log, void *buffer,
	UINT32 capacity);
EFI_STATUS cdk2_tcg2_write_specid(struct cdk2_tcg2_logs *logs,
	const TPMI_ALG_HASH *algorithms, UINT32 algorithm_count, UINT8 uintn_size);
EFI_STATUS cdk2_tcg2_append_event(struct cdk2_tcg2_logs *logs,
	const struct cdk2_tcg2_event *event);
EFI_STATUS cdk2_tcg2_append_event_spans(struct cdk2_tcg2_logs *logs,
	const struct cdk2_tcg2_event *event,
	const struct cdk2_tcg2_data_span *spans, UINT32 span_count);
EFI_STATUS cdk2_tcg2_import_event2_hobs(struct cdk2_tcg2_logs *logs,
	const void *hob_list, const void *hob_end);
void cdk2_tcg2_activate_final_log(struct cdk2_tcg2_logs *logs);

#endif
