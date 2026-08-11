/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/ftw_pi.h>

static const EFI_GUID signature = { 0x9e58292b, 0x7c68, 0x497d,
	{ 0xa0, 0xce, 0x65, 0x00, 0xfd, 0x9f, 0x1b, 0x95 }
};
static void bytes(void *d0, const void *s0, UINTN n)
{
	UINT8 *d = d0;
	const UINT8 *s = s0;
	while (n--)
		*d++ =  *s++;
}
static void fill(void *d0, UINT8 v, UINTN n)
{
	UINT8 *d = d0;
	while (n--)
		*d++ = v;
}
static BOOLEAN equal(const void *a0, const void *b0, UINTN n)
{
	const UINT8 *a = a0, *b = b0;
	while (n--)
		if (*a++ != *b++)
			return FALSE;
	return TRUE;
}
static EFI_STATUS program(void *d0, const void *s0, UINTN n)
{
	UINT8 *d = d0;
	const UINT8 *s = s0;
	UINTN i;
	for (i = 0; i < n; i++)
		if ((d[i] & s[i]) != s[i])
			return EFI_WRITE_PROTECTED;
	for (i = 0; i < n; i++)
		d[i] = s[i];
	return EFI_SUCCESS;
}
static UINTN stride(const struct cdk2_ftw_pi_write_header *h)
{
	return sizeof(struct cdk2_ftw_pi_write_header) + (UINTN)h->number_of_writes *
	       (sizeof(struct cdk2_ftw_pi_record) + (UINTN)h->private_data_size);
}
static UINT32 header_crc(UINTN size)
{
	struct cdk2_ftw_pi_work_header h;
	fill(&h, 0xff, sizeof(h));
	h.signature = signature;
	h.write_queue_size = size - sizeof(h);
	h.crc32 = 0xffffffffU;
	return cdk2_ftw_crc32(&h, sizeof(h));
}
static UINT32 logical_crc(struct cdk2_ftw_journal *j)
{
	UINT32 saved = j->crc32, result;
	j->crc32 = 0;
	result = cdk2_ftw_crc32(j, sizeof(*j));
	j->crc32 = saved;
	return result;
}
EFI_STATUS cdk2_ftw_pi_initialize(UINT8 *w, UINTN size)
{
	struct cdk2_ftw_pi_work_header *h;
	if (!w || size < sizeof(*h) + sizeof(struct cdk2_ftw_pi_write_header) +
	    sizeof(struct cdk2_ftw_pi_record))
		return EFI_INVALID_PARAMETER;
	fill(w, 0xff, size);
	h = (void *)w;
	h->signature = signature;
	h->write_queue_size = size - sizeof(*h);
	h->crc32 = header_crc(size);
	h->state = 0xfe;
	return EFI_SUCCESS;
}
static EFI_STATUS header_valid(const UINT8 *w, UINTN size)
{
	const struct cdk2_ftw_pi_work_header *h = (const void *)w;
	if (size < sizeof(*h) || !equal(&h->signature, &signature, sizeof(signature)) ||
	    h->write_queue_size != size - sizeof(*h) || h->crc32 != header_crc(size) ||
	    (h->state & 3U) != 2U)
		return EFI_VOLUME_CORRUPTED;
	return EFI_SUCCESS;
}
EFI_STATUS cdk2_ftw_pi_decode(const UINT8 *w, UINTN size, struct cdk2_ftw_journal *j)
{
	UINTN off = sizeof(struct cdk2_ftw_pi_work_header), i;
	const struct cdk2_ftw_pi_write_header *h;
	if (!w || !j)
		return EFI_INVALID_PARAMETER;
	if (EFI_ERROR(header_valid(w, size)))
		return EFI_VOLUME_CORRUPTED;
	fill(j, 0, sizeof(*j));
	j->magic = CDK2_FTW_MAGIC;
	j->phase = CDK2_FTW_EMPTY;
	while (off + sizeof(*h) <= size) {
		h = (const void *)(w + off);
		if (h->state == 0xff)
			break;
		if (h->state & 1U)
			return EFI_VOLUME_CORRUPTED;
		if (h->number_of_writes == 0 || h->number_of_writes > CDK2_FTW_MAX_WRITES ||
		    h->private_data_size > CDK2_FTW_MAX_PRIVATE || stride(h) > size - off)
			return EFI_VOLUME_CORRUPTED;
		if (!(h->state & 4U)) {
			off += stride(h);
			continue;
		}
		if (h->state & 2U) {
			j->crc32 = logical_crc(j);
			return EFI_SUCCESS;
		}
		j->caller_id = h->caller_id;
		j->write_count = (UINT32)h->number_of_writes;
		j->private_size = (UINT32)h->private_data_size;
		j->phase = CDK2_FTW_ALLOCATED;
		for (i = 0; i < j->write_count; i++) {
			const UINT8 *p = (const UINT8 *)(h + 1) + i * (sizeof(struct cdk2_ftw_pi_record) + j->private_size);
			const struct cdk2_ftw_pi_record *r = (const void *)p;
			struct cdk2_ftw_record *o =  &j->records[i];
			if (r->state == 0xff)
				break;
			o->lba = r->lba;
			o->offset = r->offset;
			o->length = r->length;
			o->relative_offset = r->relative_offset;
			o->private_size = j->private_size;
			bytes(o->private_data, r + 1, j->private_size);
			if (!(r->state & 4U) && (r->state & 2U))
				return EFI_VOLUME_CORRUPTED;
			o->phase =  !(r->state & 4U) ? CDK2_FTW_DESTINATION_COMPLETE :
				    (!(r->state & 2U) ? CDK2_FTW_SPARE_COMPLETE : CDK2_FTW_EMPTY);
			if (o->phase == CDK2_FTW_DESTINATION_COMPLETE)
				j->next_write++;
		}
		if (j->next_write < j->write_count && j->records[j->next_write].phase == CDK2_FTW_SPARE_COMPLETE)
			j->phase = CDK2_FTW_SPARE_COMPLETE;
		else if (j->next_write == j->write_count)
			j->phase = CDK2_FTW_BATCH_COMPLETE;
		j->crc32 = logical_crc(j);
		return EFI_SUCCESS;
	}
	j->crc32 = logical_crc(j);
	return EFI_SUCCESS;
}
EFI_STATUS cdk2_ftw_pi_encode(UINT8 *w, UINTN size, const struct cdk2_ftw_journal *j)
{
	UINTN off = sizeof(struct cdk2_ftw_pi_work_header), i, need;
	struct cdk2_ftw_pi_write_header *h, desired_h;
	EFI_STATUS status;
	if (!w || !j || EFI_ERROR(header_valid(w, size)))
		return EFI_INVALID_PARAMETER;
	if (j->phase == CDK2_FTW_EMPTY && !j->write_count)
		return EFI_SUCCESS;
	while (off + sizeof(*h) <= size) {
		h = (void *)(w + off);
		if (h->state == 0xff)
			break;
		if ((h->state & 4U) && h->number_of_writes == j->write_count &&
		   h->private_data_size == j->private_size && equal(&h->caller_id, &j->caller_id, sizeof(EFI_GUID)))
			goto update;
		off += stride(h);
	}
	need = sizeof(*h) + j->write_count * (sizeof(struct cdk2_ftw_pi_record) + j->private_size);
	if (off + need > size) {
		EFI_STATUS s = cdk2_ftw_pi_initialize(w, size);
		if (EFI_ERROR(s))
			return s;
		off = sizeof(struct cdk2_ftw_pi_work_header);
	}
	h = (void *)(w + off);
update:
	fill(&desired_h, 0xff, sizeof(desired_h));
	desired_h.state = 0xfc;
	desired_h.caller_id = j->caller_id;
	desired_h.number_of_writes = j->write_count;
	desired_h.private_data_size = j->private_size;
	status = program(h, &desired_h, sizeof(desired_h));
	if (EFI_ERROR(status))
		return status;
	for (i = 0; i < j->write_count; i++) {
		UINT8 *p = (UINT8 *)(h + 1) + i * (sizeof(struct cdk2_ftw_pi_record) + j->private_size);
		struct cdk2_ftw_pi_record desired_r;
		UINT8 desired_state;
		const struct cdk2_ftw_record *in =  &j->records[i];
		if (in->length == 0 && in->phase == CDK2_FTW_EMPTY)
			continue;
		fill(&desired_r, 0xff, sizeof(desired_r));
		desired_r.lba = in->lba;
		desired_r.offset = in->offset;
		desired_r.length = in->length;
		desired_r.relative_offset = in->relative_offset;
		desired_state = desired_r.state;
		if (in->phase >= CDK2_FTW_SPARE_COMPLETE)
			desired_state &=  ~2U;
		if (in->phase >= CDK2_FTW_DESTINATION_COMPLETE)
			desired_state &=  ~4U;
		status = program(p + 1, (UINT8 *)&desired_r + 1, sizeof(desired_r) - 1);
		if (EFI_ERROR(status))
			return status;
		status = program(p + sizeof(desired_r), in->private_data, j->private_size);
		if (EFI_ERROR(status))
			return status;
		status = program(p, &desired_state, sizeof(desired_state));
		if (EFI_ERROR(status))
			return status;
	}
	if (j->phase == CDK2_FTW_BATCH_COMPLETE || j->phase == CDK2_FTW_ABORTED) {
		UINT8 complete = h->state & ~4U;
		status = program(&h->state, &complete, sizeof(complete));
		if (EFI_ERROR(status))
			return status;
	}
	return EFI_SUCCESS;
}
