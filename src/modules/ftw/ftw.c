/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/ftw.h>

static void copy(void *out, const void *in, UINTN n)
{ UINT8 *d = out; const UINT8 *s = in; while (n--) *d++ = *s++; }
static void zero(void *out, UINTN n)
{ UINT8 *d = out; while (n--) *d++ = 0; }

UINT32 cdk2_ftw_crc32(const void *data, UINTN bytes)
{
	const UINT8 *p = data; UINT32 crc = ~0U; UINTN i; unsigned bit;
	for (i = 0; i < bytes; i++) { crc ^= p[i]; for (bit = 0; bit < 8; bit++)
		crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U))); }
	return ~crc;
}
static UINT32 journal_crc(const struct cdk2_ftw_journal *journal)
{
	struct cdk2_ftw_journal copy_journal = *journal;
	copy_journal.crc32 = 0;
	return cdk2_ftw_crc32(&copy_journal, sizeof(copy_journal));
}
static EFI_STATUS persist(struct cdk2_ftw *ftw)
{
	ftw->journal.crc32 = journal_crc(&ftw->journal);
	return ftw->ops->journal_write(ftw->context, &ftw->journal);
}
static EFI_STATUS valid_context(struct cdk2_ftw *ftw)
{
	if (!ftw || !ftw->ops || !ftw->scratch || !ftw->block_size ||
	    !ftw->ops->journal_read || !ftw->ops->journal_write ||
	    !ftw->ops->target_read || !ftw->ops->target_write || !ftw->ops->target_erase ||
	    !ftw->ops->spare_read || !ftw->ops->spare_write || !ftw->ops->spare_erase)
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}
EFI_STATUS cdk2_ftw_initialize(struct cdk2_ftw *ftw)
{
	EFI_STATUS status = valid_context(ftw);
	if (EFI_ERROR(status)) return status;
	status = ftw->ops->journal_read(ftw->context, &ftw->journal);
	if (status == EFI_NOT_FOUND) { zero(&ftw->journal, sizeof(ftw->journal));
		ftw->journal.magic = CDK2_FTW_MAGIC; ftw->journal.phase = CDK2_FTW_EMPTY;
		return persist(ftw); }
	if (EFI_ERROR(status)) return status;
	if (ftw->journal.magic != CDK2_FTW_MAGIC ||
	    ftw->journal.crc32 != journal_crc(&ftw->journal) ||
	    ftw->journal.write_count > CDK2_FTW_MAX_WRITES ||
	    ftw->journal.next_write > ftw->journal.write_count)
		return EFI_VOLUME_CORRUPTED;
	if (ftw->journal.next_write < ftw->journal.write_count &&
	    ftw->journal.records[ftw->journal.next_write].phase == CDK2_FTW_SPARE_COMPLETE)
		return cdk2_ftw_restart(ftw);
	return EFI_SUCCESS;
}
EFI_STATUS cdk2_ftw_allocate(struct cdk2_ftw *ftw, const EFI_GUID *caller,
	UINTN private_size, UINTN writes)
{
	if (EFI_ERROR(valid_context(ftw)) || !caller || !writes) return EFI_INVALID_PARAMETER;
	if (private_size > CDK2_FTW_MAX_PRIVATE || writes > CDK2_FTW_MAX_WRITES)
		return EFI_BUFFER_TOO_SMALL;
	if (ftw->journal.phase == CDK2_FTW_ALLOCATED ||
	    ftw->journal.phase == CDK2_FTW_SPARE_COMPLETE) return EFI_ACCESS_DENIED;
	zero(&ftw->journal, sizeof(ftw->journal)); ftw->journal.magic = CDK2_FTW_MAGIC;
	ftw->journal.caller_id = *caller; ftw->journal.private_size = private_size;
	ftw->journal.write_count = writes; ftw->journal.phase = CDK2_FTW_ALLOCATED;
	return persist(ftw);
}
void cdk2_ftw_set_relative_offset(struct cdk2_ftw *ftw, INT64 relative_offset)
{
	if (ftw) ftw->relative_offset = relative_offset;
}
static EFI_STATUS finish_from_spare(struct cdk2_ftw *ftw, struct cdk2_ftw_record *record)
{
	EFI_STATUS status = ftw->ops->spare_read(ftw->context, 0, ftw->scratch, ftw->block_size);
	if (EFI_ERROR(status)) return EFI_ABORTED;
	status = ftw->ops->target_erase(ftw->context, record->lba);
	if (EFI_ERROR(status)) return EFI_ABORTED;
	status = ftw->ops->target_write(ftw->context, record->lba, ftw->scratch, ftw->block_size);
	if (EFI_ERROR(status)) return EFI_ABORTED;
	record->phase = CDK2_FTW_DESTINATION_COMPLETE;
	ftw->journal.next_write++;
	ftw->journal.phase = ftw->journal.next_write == ftw->journal.write_count ?
		CDK2_FTW_BATCH_COMPLETE : CDK2_FTW_ALLOCATED;
	return persist(ftw);
}
EFI_STATUS cdk2_ftw_write(struct cdk2_ftw *ftw, UINT64 lba, UINTN offset,
	UINTN length, const void *private_data, const void *buffer)
{
	struct cdk2_ftw_record *record; EFI_STATUS status;
	if (EFI_ERROR(valid_context(ftw)) || (!buffer && length) ||
	    (!private_data && ftw->journal.private_size)) return EFI_INVALID_PARAMETER;
	if (offset > ftw->block_size || length > ftw->block_size - offset)
		return EFI_BAD_BUFFER_SIZE;
	if (ftw->journal.phase != CDK2_FTW_ALLOCATED ||
	    ftw->journal.next_write >= ftw->journal.write_count) return EFI_ACCESS_DENIED;
	record = &ftw->journal.records[ftw->journal.next_write]; zero(record, sizeof(*record));
	record->lba = lba; record->offset = offset; record->length = length;
	record->relative_offset = ftw->relative_offset;
	record->private_size = ftw->journal.private_size;
	copy(record->private_data, private_data, record->private_size);
	status = persist(ftw); if (EFI_ERROR(status)) return EFI_ABORTED;
	status = ftw->ops->target_read(ftw->context, lba, ftw->scratch, ftw->block_size);
	if (EFI_ERROR(status)) return EFI_ABORTED;
	copy(ftw->scratch + offset, buffer, length);
	status = ftw->ops->spare_erase(ftw->context, 0); if (EFI_ERROR(status)) return EFI_ABORTED;
	status = ftw->ops->spare_write(ftw->context, 0, ftw->scratch, ftw->block_size);
	if (EFI_ERROR(status)) return EFI_ABORTED;
	record->phase = CDK2_FTW_SPARE_COMPLETE; ftw->journal.phase = CDK2_FTW_SPARE_COMPLETE;
	status = persist(ftw); if (EFI_ERROR(status)) return EFI_ABORTED;
	return finish_from_spare(ftw, record);
}
EFI_STATUS cdk2_ftw_restart(struct cdk2_ftw *ftw)
{
	struct cdk2_ftw_record *record;
	if (EFI_ERROR(valid_context(ftw))) return EFI_INVALID_PARAMETER;
	if (ftw->journal.next_write >= ftw->journal.write_count) return EFI_ACCESS_DENIED;
	record = &ftw->journal.records[ftw->journal.next_write];
	if (record->phase != CDK2_FTW_SPARE_COMPLETE) return EFI_ACCESS_DENIED;
	return finish_from_spare(ftw, record);
}
EFI_STATUS cdk2_ftw_abort(struct cdk2_ftw *ftw)
{
	if (EFI_ERROR(valid_context(ftw))) return EFI_INVALID_PARAMETER;
	if (ftw->journal.phase != CDK2_FTW_ALLOCATED) return EFI_NOT_FOUND;
	ftw->journal.phase = CDK2_FTW_ABORTED; return persist(ftw);
}
EFI_STATUS cdk2_ftw_get_last_write(struct cdk2_ftw *ftw, EFI_GUID *caller,
	UINT64 *lba, UINTN *offset, UINTN *length, UINTN *private_size,
	void *private_data, BOOLEAN *complete)
{
	struct cdk2_ftw_record *record; UINTN index;
	if (!ftw || !caller || !lba || !offset || !length || !private_size || !complete)
		return EFI_INVALID_PARAMETER;
	if (!ftw->journal.write_count || ftw->journal.phase == CDK2_FTW_EMPTY) return EFI_NOT_FOUND;
	index = ftw->journal.next_write < ftw->journal.write_count ? ftw->journal.next_write :
		ftw->journal.write_count - 1; record = &ftw->journal.records[index];
	if (record->phase == CDK2_FTW_EMPTY && index > 0)
		record = &ftw->journal.records[--index];
	if (*private_size < record->private_size) { *private_size = record->private_size;
		return EFI_BUFFER_TOO_SMALL; }
	if (record->private_size && !private_data) return EFI_INVALID_PARAMETER;
	*caller = ftw->journal.caller_id; *lba = record->lba; *offset = record->offset;
	*length = record->length; *private_size = record->private_size;
	copy(private_data, record->private_data, record->private_size);
	*complete = record->phase == CDK2_FTW_DESTINATION_COMPLETE;
	return EFI_SUCCESS;
}
