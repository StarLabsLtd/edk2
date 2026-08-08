/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/ftw_fvb.h>

static EFI_STATUS journal_read(void *context, struct cdk2_ftw_journal *journal)
{ struct cdk2_ftw_fvb *a = context; return a->ops->journal_read(a->context, journal); }
static EFI_STATUS journal_write(void *context, const struct cdk2_ftw_journal *journal)
{ struct cdk2_ftw_fvb *a = context; return a->ops->journal_write(a->context, journal); }
static EFI_STATUS target_read(void *context, UINT64 lba, void *data, UINTN bytes)
{ struct cdk2_ftw_fvb *a = context; UINTN i, block = bytes / a->block_count;
	for (i = 0; i < a->block_count; i++) { EFI_STATUS s = a->ops->read(a->context,
		a->target_volume, lba + i, (UINT8 *)data + i * block, block);
		if (EFI_ERROR(s)) return s; } return EFI_SUCCESS; }
static EFI_STATUS target_erase(void *context, UINT64 lba)
{ struct cdk2_ftw_fvb *a = context;
	if (a->target_is_boot) return EFI_SUCCESS;
	return a->ops->erase(a->context, a->target_volume, lba, 1); }
static EFI_STATUS target_write(void *context, UINT64 lba, const void *data, UINTN bytes)
{
	struct cdk2_ftw_fvb *a = context;
	if (a->target_is_boot) {
		if (!a->ops->swap) return EFI_UNSUPPORTED;
		return a->ops->swap(a->context, a->spare_volume, a->spare_lba,
			a->target_volume, lba, 1);
	}
	UINTN i, block = bytes / a->block_count;
	for (i = 0; i < a->block_count; i++) { EFI_STATUS s = a->ops->write(a->context,
		a->target_volume, lba + i, (const UINT8 *)data + i * block, block);
		if (EFI_ERROR(s)) return s; }
	return EFI_SUCCESS;
}
static EFI_STATUS spare_read(void *context, UINT64 lba, void *data, UINTN bytes)
{ struct cdk2_ftw_fvb *a = context; UINTN i, block = bytes / a->block_count; (void)lba;
	for (i = 0; i < a->block_count; i++) { EFI_STATUS s = a->ops->read(a->context,
		a->spare_volume, a->spare_lba + i, (UINT8 *)data + i * block, block);
		if (EFI_ERROR(s)) return s; } return EFI_SUCCESS; }
static EFI_STATUS spare_write(void *context, UINT64 lba, const void *data, UINTN bytes)
{ struct cdk2_ftw_fvb *a = context; UINTN i, block = bytes / a->block_count; (void)lba;
	for (i = 0; i < a->block_count; i++) { EFI_STATUS s = a->ops->write(a->context,
		a->spare_volume, a->spare_lba + i, (const UINT8 *)data + i * block, block);
		if (EFI_ERROR(s)) return s; } return EFI_SUCCESS; }
static EFI_STATUS spare_erase(void *context, UINT64 lba)
{ struct cdk2_ftw_fvb *a = context; (void)lba;
	return a->ops->erase(a->context, a->spare_volume, a->spare_lba, a->block_count); }
static const struct cdk2_ftw_ops core_ops = { journal_read, journal_write,
	target_read, target_write, target_erase, spare_read, spare_write, spare_erase };

EFI_STATUS cdk2_ftw_fvb_initialize(struct cdk2_ftw_fvb *a, UINT8 *scratch)
{
	UINTN work_size, spare_size;
	if (!a || !a->ops || !a->ops->get_block_size || !a->ops->read ||
	    !a->ops->write || !a->ops->erase || !a->ops->journal_read ||
	    !a->ops->journal_write || !a->working_volume || !a->spare_volume || !scratch)
		return EFI_INVALID_PARAMETER;
	EFI_STATUS status = a->ops->get_block_size(a->context, a->working_volume,
		a->working_lba, &work_size);
	if (EFI_ERROR(status)) return status;
	status = a->ops->get_block_size(a->context, a->spare_volume, a->spare_lba, &spare_size);
	if (EFI_ERROR(status)) return status;
	if (!work_size || work_size != spare_size || !a->block_count)
		return EFI_VOLUME_CORRUPTED;
	a->core = (struct cdk2_ftw){ &core_ops, a, work_size * a->block_count, scratch, { 0 }, 0 };
	return cdk2_ftw_initialize(&a->core);
}
EFI_STATUS cdk2_ftw_fvb_select_target(struct cdk2_ftw_fvb *a, void *volume, UINT64 lba)
{
	UINTN size; EFI_STATUS status;
	if (!a || !volume) return EFI_INVALID_PARAMETER;
	status = a->ops->get_block_size(a->context, volume, lba, &size);
	if (EFI_ERROR(status)) return status;
	if (size * a->block_count != a->core.block_size) return EFI_BAD_BUFFER_SIZE;
	a->target_volume = volume;
	a->target_is_boot = a->ops->is_boot ? a->ops->is_boot(a->context, volume) : FALSE;
	return EFI_SUCCESS;
}
EFI_STATUS cdk2_ftw_fvb_write(struct cdk2_ftw_fvb *a, UINT64 lba,
	UINTN offset, UINTN length, const void *private_data, const void *buffer)
{
	if (!a || !a->target_volume) return EFI_NOT_READY;
	return cdk2_ftw_write(&a->core, lba, offset, length, private_data, buffer);
}
