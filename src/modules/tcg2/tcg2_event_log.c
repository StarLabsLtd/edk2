/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_event_log.h>

const EFI_GUID cdk2_tcg_event2_entry_hob_guid = {
	0xd26c221e, 0x2430, 0x4c8a,
	{0x91, 0x70, 0x3f, 0xcb, 0x45, 0x00, 0x41, 0x3f}
};

static UINT16 digest_size(TPMI_ALG_HASH algorithm)
{
	switch (algorithm) {
	case TPM_ALG_SHA1: return SHA1_DIGEST_SIZE;
	case TPM_ALG_SHA256: return SHA256_DIGEST_SIZE;
	case TPM_ALG_SHA384: return SHA384_DIGEST_SIZE;
	case TPM_ALG_SHA512: return SHA512_DIGEST_SIZE;
	case TPM_ALG_SM3_256: return SM3_256_DIGEST_SIZE;
	default: return 0;
	}
}

static void put16(UINT8 *buffer, UINT16 value)
{
	buffer[0] = (UINT8)value; buffer[1] = (UINT8)(value >> 8);
}

static void put32(UINT8 *buffer, UINT32 value)
{
	buffer[0] = (UINT8)value; buffer[1] = (UINT8)(value >> 8);
	buffer[2] = (UINT8)(value >> 16); buffer[3] = (UINT8)(value >> 24);
}

static UINT16 get16(const UINT8 *buffer)
{
	return (UINT16)buffer[0] | (UINT16)buffer[1] << 8;
}

static UINT32 get32(const UINT8 *buffer)
{
	return (UINT32)buffer[0] | (UINT32)buffer[1] << 8 |
		(UINT32)buffer[2] << 16 | (UINT32)buffer[3] << 24;
}

static void copy_bytes(UINT8 *out, const UINT8 *in, UINT32 size)
{
	UINT32 index;
	for (index = 0; index < size; index++) out[index] = in[index];
}

static int guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left;
	const UINT8 *b = (const UINT8 *)right;
	UINTN index;
	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index]) return 0;
	return 1;
}

EFI_STATUS cdk2_tcg2_log_init(struct cdk2_tcg2_log *log, void *buffer,
	UINT32 capacity)
{
	if (log == NULL || buffer == NULL || capacity == 0)
		return EFI_INVALID_PARAMETER;
	log->buffer = buffer; log->capacity = capacity; log->used = 0;
	log->truncated = FALSE;
	return EFI_SUCCESS;
}

static EFI_STATUS append_raw(struct cdk2_tcg2_log *log, const UINT8 *record,
	UINT32 size)
{
	if (size > log->capacity - log->used) {
		log->truncated = TRUE;
		return EFI_VOLUME_FULL;
	}
	copy_bytes(log->buffer + log->used, record, size); log->used += size;
	return EFI_SUCCESS;
}

static EFI_STATUS event_size(const struct cdk2_tcg2_event *event, UINT32 *size)
{
	UINT32 total = 16U;
	UINT32 index;
	UINT32 prior;

	if (event == NULL || size == NULL || event->digests == NULL ||
	    event->digest_count == 0 || event->digest_count > CDK2_TCG2_MAX_DIGESTS ||
	    (event->event_size != 0 && event->event == NULL))
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < event->digest_count; index++) {
		if (event->digests[index].size != digest_size(event->digests[index].algorithm))
			return EFI_COMPROMISED_DATA;
		for (prior = 0; prior < index; prior++)
			if (event->digests[prior].algorithm ==
			    event->digests[index].algorithm)
				return EFI_COMPROMISED_DATA;
		if (total > MAX_UINT32 - 2U - event->digests[index].size)
			return EFI_BAD_BUFFER_SIZE;
		total += 2U + event->digests[index].size;
	}
	if (event->event_size > MAX_UINT32 - total)
		return EFI_BAD_BUFFER_SIZE;
	*size = total + event->event_size;
	return EFI_SUCCESS;
}

static EFI_STATUS encode_event(const struct cdk2_tcg2_event *event,
	const struct cdk2_tcg2_data_span *spans, UINT32 span_count,
	UINT8 *buffer, UINT32 capacity, UINT32 *written)
{
	UINT32 size;
	UINT32 offset = 0;
	UINT32 index;
	EFI_STATUS status = event_size(event, &size);

	if (EFI_ERROR(status)) return status;
	if (size > capacity) return EFI_BUFFER_TOO_SMALL;
	put32(buffer + offset, event->pcr_index); offset += 4;
	put32(buffer + offset, event->event_type); offset += 4;
	put32(buffer + offset, event->digest_count); offset += 4;
	for (index = 0; index < event->digest_count; index++) {
		put16(buffer + offset, event->digests[index].algorithm); offset += 2;
		copy_bytes(buffer + offset, event->digests[index].bytes,
			event->digests[index].size);
		offset += event->digests[index].size;
	}
	put32(buffer + offset, event->event_size); offset += 4;
	for (index = 0; index < span_count; index++) {
		copy_bytes(buffer + offset, spans[index].data, spans[index].size);
		offset += spans[index].size;
	}
	*written = size;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_append_event(struct cdk2_tcg2_logs *logs,
	const struct cdk2_tcg2_event *event)
{
	struct cdk2_tcg2_data_span span;

	if (event == NULL) return EFI_INVALID_PARAMETER;
	span = (struct cdk2_tcg2_data_span){ event->event, event->event_size };
	return cdk2_tcg2_append_event_spans(logs, event, &span, 1);
}

EFI_STATUS cdk2_tcg2_append_event_spans(struct cdk2_tcg2_logs *logs,
	const struct cdk2_tcg2_event *event,
	const struct cdk2_tcg2_data_span *spans, UINT32 span_count)
{
	UINT32 size;
	UINT32 written;
	UINT32 total_event_size = 0;
	UINT32 index;
	EFI_STATUS status;

	if (logs == NULL || event == NULL || spans == NULL || span_count == 0)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < span_count; index++) {
		if (spans[index].size != 0 && spans[index].data == NULL)
			return EFI_INVALID_PARAMETER;
		if (spans[index].size > MAX_UINT32 - total_event_size)
			return EFI_BAD_BUFFER_SIZE;
		total_event_size += spans[index].size;
	}
	if (total_event_size != event->event_size) return EFI_COMPROMISED_DATA;
	status = event_size(event, &size);
	if (EFI_ERROR(status)) return status;
	if (size > logs->main.capacity - logs->main.used) {
		logs->main.truncated = TRUE;
		return EFI_VOLUME_FULL;
	}
	status = encode_event(event, spans, span_count,
		logs->main.buffer + logs->main.used,
		logs->main.capacity - logs->main.used, &written);
	if (EFI_ERROR(status) || written != size) return EFI_COMPROMISED_DATA;
	logs->main.used += size;
	logs->event_count++;
	if (logs->final_active) {
		if (size > logs->final.capacity - logs->final.used) {
			logs->final.truncated = TRUE;
			status = EFI_VOLUME_FULL;
		} else {
			EFI_STATUS final_status = encode_event(event, spans, span_count,
				logs->final.buffer + logs->final.used,
				logs->final.capacity - logs->final.used, &written);
			if (EFI_ERROR(final_status) || written != size)
				return EFI_COMPROMISED_DATA;
			logs->final.used += size;
		}
	}
	return status;
}

static EFI_STATUS raw_event_size(const UINT8 *record, UINT32 available,
	UINT32 *record_size)
{
	UINT32 count;
	UINT32 index;
	UINT32 offset = 12;
	UINT16 size;

	if (available < 16U) return EFI_COMPROMISED_DATA;
	count = get32(record + 8);
	if (count == 0 || count > CDK2_TCG2_MAX_DIGESTS)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < count; index++) {
		if (offset + 2U > available) return EFI_COMPROMISED_DATA;
		size = digest_size(get16(record + offset)); offset += 2;
		if (size == 0 || offset + size > available) return EFI_COMPROMISED_DATA;
		offset += size;
	}
	if (offset + 4U > available) return EFI_COMPROMISED_DATA;
	count = get32(record + offset); offset += 4;
	if (count > available - offset) return EFI_COMPROMISED_DATA;
	*record_size = offset + count;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_import_event2_hobs(struct cdk2_tcg2_logs *logs,
	const void *hob_list, const void *hob_end)
{
	const UINT8 *current = hob_list;
	const UINT8 *end = hob_end;
	const EFI_HOB_GENERIC_HEADER *header;
	const EFI_HOB_GUID_TYPE *guid;
	UINT32 payload_size;
	UINT32 size;
	UINT32 advance;
	EFI_STATUS status;

	if (logs == NULL || current == NULL || end == NULL || current >= end)
		return EFI_INVALID_PARAMETER;
	while ((UINTN)(end - current) >= sizeof(*header)) {
		header = (const EFI_HOB_GENERIC_HEADER *)current;
		if (header->hob_length < sizeof(*header) || header->hob_length > end - current)
			return EFI_COMPROMISED_DATA;
		if (header->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST) return EFI_SUCCESS;
		if (header->hob_type == EFI_HOB_TYPE_GUID_EXTENSION &&
		    header->hob_length >= sizeof(*guid)) {
			guid = (const EFI_HOB_GUID_TYPE *)current;
			if (guid_equal(&guid->name, &cdk2_tcg_event2_entry_hob_guid)) {
				payload_size = header->hob_length - sizeof(*guid);
				status = raw_event_size(current + sizeof(*guid), payload_size, &size);
				if (EFI_ERROR(status) || size != payload_size) return EFI_COMPROMISED_DATA;
				status = append_raw(&logs->main, current + sizeof(*guid), size);
				if (EFI_ERROR(status)) return status;
				logs->event_count++;
			}
		}
		advance = (header->hob_length + 7U) & ~7U;
		if (advance < header->hob_length || advance > end - current)
			return EFI_COMPROMISED_DATA;
		current += advance;
	}
	return EFI_COMPROMISED_DATA;
}

void cdk2_tcg2_activate_final_log(struct cdk2_tcg2_logs *logs)
{
	if (logs != NULL) logs->final_active = TRUE;
}
