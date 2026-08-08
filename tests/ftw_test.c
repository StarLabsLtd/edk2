/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <string.h>
#include <cdk2/ftw.h>

#define BLOCK 32
struct media {
	struct cdk2_ftw_journal journal;
	UINT8 target[2][BLOCK], spare[BLOCK];
	BOOLEAN journal_exists;
	unsigned operation, fail_at;
};
static EFI_STATUS fault(struct media *m)
{ m->operation++; return m->fail_at == m->operation ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS journal_read(void *p, struct cdk2_ftw_journal *j)
{ struct media *m = p; if (!m->journal_exists) return EFI_NOT_FOUND; *j = m->journal; return 0; }
static EFI_STATUS journal_write(void *p, const struct cdk2_ftw_journal *j)
{ struct media *m = p; EFI_STATUS s = fault(m); if (EFI_ERROR(s)) return s;
	m->journal = *j; m->journal_exists = TRUE; return 0; }
static EFI_STATUS target_read(void *p, UINT64 lba, void *b, UINTN n)
{ struct media *m = p; EFI_STATUS s = fault(m); if (EFI_ERROR(s)) return s;
	if (lba > 1 || n != BLOCK) return EFI_INVALID_PARAMETER;
	memcpy(b, m->target[lba], n); return 0; }
static EFI_STATUS target_write(void *p, UINT64 lba, const void *b, UINTN n)
{ struct media *m = p; EFI_STATUS s = fault(m); if (EFI_ERROR(s)) return s;
	if (lba > 1 || n != BLOCK) return EFI_INVALID_PARAMETER;
	memcpy(m->target[lba], b, n); return 0; }
static EFI_STATUS target_erase(void *p, UINT64 lba)
{ struct media *m = p; EFI_STATUS s = fault(m); if (EFI_ERROR(s)) return s;
	if (lba > 1) return EFI_INVALID_PARAMETER;
	memset(m->target[lba], 0xff, BLOCK); return 0; }
static EFI_STATUS spare_read(void *p, UINT64 lba, void *b, UINTN n)
{ struct media *m = p; EFI_STATUS s = fault(m); (void)lba; if (EFI_ERROR(s)) return s;
	memcpy(b, m->spare, n); return 0; }
static EFI_STATUS spare_write(void *p, UINT64 lba, const void *b, UINTN n)
{ struct media *m = p; EFI_STATUS s = fault(m); (void)lba; if (EFI_ERROR(s)) return s;
	memcpy(m->spare, b, n); return 0; }
static EFI_STATUS spare_erase(void *p, UINT64 lba)
{ struct media *m = p; EFI_STATUS s = fault(m); (void)lba; if (EFI_ERROR(s)) return s;
	memset(m->spare, 0xff, BLOCK); return 0; }
static const struct cdk2_ftw_ops ops = { journal_read, journal_write, target_read,
	target_write, target_erase, spare_read, spare_write, spare_erase };
static struct cdk2_ftw make_ftw(struct media *m, UINT8 *scratch)
{ return (struct cdk2_ftw){ &ops, m, BLOCK, scratch, { 0 } }; }

static void crash_matrix(void)
{
	unsigned cut;
	for (cut = 1; cut <= 9; cut++) {
		struct media m = { 0 }; UINT8 scratch[BLOCK], update[5] = { 3,4,5,6,7 };
		EFI_GUID id = { .data1 = cut }; struct cdk2_ftw ftw = make_ftw(&m, scratch);
		memset(m.target[0], 0x11, BLOCK);
		assert(cdk2_ftw_initialize(&ftw) == EFI_SUCCESS);
		assert(cdk2_ftw_allocate(&ftw, &id, 0, 1) == EFI_SUCCESS);
		m.operation = 0; m.fail_at = cut;
		assert(EFI_ERROR(cdk2_ftw_write(&ftw, 0, 7, sizeof(update), NULL, update)));
		/* A cut must expose either the complete old block or complete new block. */
		assert((m.target[0][7] == 0x11) ||
			!memcmp(m.target[0] + 7, update, sizeof(update)) ||
			(m.journal.records[0].phase == CDK2_FTW_SPARE_COMPLETE &&
			 !memcmp(m.spare + 7, update, sizeof(update))));
		m.operation = 0; m.fail_at = 0; ftw = make_ftw(&m, scratch);
		assert(cdk2_ftw_initialize(&ftw) == EFI_SUCCESS);
		if (memcmp(m.target[0] + 7, update, sizeof(update)))
			assert(cdk2_ftw_write(&ftw, 0, 7, sizeof(update), NULL, update) == EFI_SUCCESS);
		assert(!memcmp(m.target[0] + 7, update, sizeof(update)));
	}
}

int main(void)
{
	struct media m = { 0 }; UINT8 scratch[BLOCK], update[5] = { 9,8,7,6,5 };
	EFI_GUID id = { .data1 = 7 }, got; struct cdk2_ftw ftw = make_ftw(&m, scratch);
	UINT64 lba; UINTN offset, length, private_size; BOOLEAN complete; UINT8 private = 0xaa;
	memset(m.target[0], 1, BLOCK); memset(m.target[1], 2, BLOCK);
	assert(cdk2_ftw_initialize(&ftw) == EFI_SUCCESS);
	assert(cdk2_ftw_allocate(&ftw, &id, 1, 2) == EFI_SUCCESS);
	assert(cdk2_ftw_allocate(&ftw, &id, 1, 1) == EFI_ACCESS_DENIED);
	assert(cdk2_ftw_write(&ftw, 0, 4, 5, &private, update) == EFI_SUCCESS);
	assert(!memcmp(m.target[0] + 4, update, 5));
	private_size = 0;
	assert(cdk2_ftw_get_last_write(&ftw, &got, &lba, &offset, &length,
		&private_size, NULL, &complete) == EFI_BUFFER_TOO_SMALL && private_size == 1);
	private_size = 1;
	assert(cdk2_ftw_get_last_write(&ftw, &got, &lba, &offset, &length,
		&private_size, &private, &complete) == EFI_SUCCESS && complete && lba == 0);
	/* Persist spare-complete, then lose power before destination erase. */
	m.operation = 0; m.fail_at = 6;
	assert(cdk2_ftw_write(&ftw, 1, 10, 5, &private, update) == EFI_ABORTED);
	assert(m.journal.records[1].phase == CDK2_FTW_SPARE_COMPLETE);
	m.fail_at = 0; m.operation = 0; ftw = make_ftw(&m, scratch);
	assert(cdk2_ftw_initialize(&ftw) == EFI_SUCCESS);
	assert(!memcmp(m.target[1] + 10, update, 5) &&
		m.journal.phase == CDK2_FTW_BATCH_COMPLETE);
	assert(cdk2_ftw_abort(&ftw) == EFI_NOT_FOUND);
	/* CRC detects torn/corrupt journal rather than trusting its state bits. */
	m.journal.records[0].lba ^= 1; ftw = make_ftw(&m, scratch);
	assert(cdk2_ftw_initialize(&ftw) == EFI_VOLUME_CORRUPTED);
	crash_matrix();
	return 0;
}
