/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <string.h>
#include <cdk2/ftw_fvb.h>

#define BS 16
struct volume { UINT8 data[2][BS]; BOOLEAN boot; };
struct fixture { struct cdk2_ftw_journal journal; BOOLEAN exists; unsigned swaps; };
static EFI_STATUS size(void *c, void *v, UINT64 lba, UINTN *out)
{ (void)c; (void)v; if (lba > 1) return EFI_INVALID_PARAMETER; *out = BS; return 0; }
static EFI_STATUS read(void *c, void *v, UINT64 lba, void *data, UINTN bytes)
{ (void)c; if (lba > 1 || bytes != BS) return EFI_INVALID_PARAMETER;
	memcpy(data, ((struct volume *)v)->data[lba], bytes); return 0; }
static EFI_STATUS write(void *c, void *v, UINT64 lba, const void *data, UINTN bytes)
{ (void)c; if (lba > 1 || bytes != BS) return EFI_INVALID_PARAMETER;
	memcpy(((struct volume *)v)->data[lba], data, bytes); return 0; }
static EFI_STATUS erase(void *c, void *v, UINT64 lba, UINTN count)
{ (void)c; if (lba + count > 2) return EFI_INVALID_PARAMETER;
	while (count--)
		memset(((struct volume *)v)->data[lba++], 0xff, BS);
	return 0; }
static EFI_STATUS swap(void *c, void *spare, UINT64 slba, void *target, UINT64 tlba, UINTN count)
{ struct fixture *f = c; f->swaps++;
	while (count--)
		memcpy(((struct volume *)target)->data[tlba++],
			((struct volume *)spare)->data[slba++], BS);
	return 0; }
static BOOLEAN is_boot(void *c, void *v) { (void)c; return ((struct volume *)v)->boot; }
static EFI_STATUS jr(void *c, struct cdk2_ftw_journal *j)
{ struct fixture *f = c; if (!f->exists) return EFI_NOT_FOUND; *j = f->journal; return 0; }
static EFI_STATUS jw(void *c, const struct cdk2_ftw_journal *j)
{ struct fixture *f = c; f->journal = *j; f->exists = TRUE; return 0; }
static const struct cdk2_ftw_fvb_ops ops = { size, read, write, erase, swap,
	is_boot, jr, jw };
int main(void)
{
	struct fixture f = { 0 }; struct volume work = { 0 }, spare = { 0 };
	struct volume normal = { 0 }, boot = { .boot = TRUE }; UINT8 scratch[BS * 2];
	UINT8 update[4] = { 1,2,3,4 }; EFI_GUID id = { .data1 = 1 };
	struct cdk2_ftw_fvb a = { .ops = &ops, .context = &f, .working_volume = &work,
		.spare_volume = &spare, .working_lba = 0, .spare_lba = 0, .block_count = 2 };
	memset(normal.data, 0x33, sizeof(normal.data)); memset(boot.data, 0x44, sizeof(boot.data));
	assert(cdk2_ftw_fvb_initialize(&a, scratch) == EFI_SUCCESS && a.core.block_size == 32);
	assert(cdk2_ftw_allocate(&a.core, &id, 0, 1) == EFI_SUCCESS);
	assert(cdk2_ftw_fvb_select_target(&a, &normal, 0) == EFI_SUCCESS);
	assert(cdk2_ftw_fvb_write(&a, 0, 14, 4, NULL, update) == EFI_SUCCESS);
	assert(!memcmp(normal.data[0] + 14, update, 2) && !memcmp(normal.data[1], update + 2, 2));
	assert(cdk2_ftw_allocate(&a.core, &id, 0, 1) == EFI_SUCCESS);
	assert(cdk2_ftw_fvb_select_target(&a, &boot, 0) == EFI_SUCCESS);
	assert(cdk2_ftw_fvb_write(&a, 0, 5, 4, NULL, update) == EFI_SUCCESS);
	assert(f.swaps == 1 && !memcmp(boot.data[0] + 5, update, 4));
	return 0;
}
