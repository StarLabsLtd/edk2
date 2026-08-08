/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_FTW_FVB_H
#define CDK2_FTW_FVB_H
#include <cdk2/ftw.h>

typedef EFI_STATUS cdk2_fvb_get_block_size_fn(void *, void *, UINT64, UINTN *);
typedef EFI_STATUS cdk2_fvb_read_fn(void *, void *, UINT64, void *, UINTN);
typedef EFI_STATUS cdk2_fvb_write_fn(void *, void *, UINT64, const void *, UINTN);
typedef EFI_STATUS cdk2_fvb_erase_fn(void *, void *, UINT64, UINTN);
typedef EFI_STATUS cdk2_fvb_swap_fn(void *, void *, UINT64, void *, UINT64, UINTN);
typedef BOOLEAN cdk2_fvb_is_boot_fn(void *, void *);
typedef EFI_STATUS cdk2_fvb_journal_read_fn(void *, struct cdk2_ftw_journal *);
typedef EFI_STATUS cdk2_fvb_journal_write_fn(void *, const struct cdk2_ftw_journal *);

struct cdk2_ftw_fvb_ops {
	cdk2_fvb_get_block_size_fn *get_block_size;
	cdk2_fvb_read_fn *read;
	cdk2_fvb_write_fn *write;
	cdk2_fvb_erase_fn *erase;
	cdk2_fvb_swap_fn *swap;
	cdk2_fvb_is_boot_fn *is_boot;
	cdk2_fvb_journal_read_fn *journal_read;
	cdk2_fvb_journal_write_fn *journal_write;
};
struct cdk2_ftw_fvb {
	struct cdk2_ftw core;
	const struct cdk2_ftw_fvb_ops *ops;
	void *context;
	void *working_volume, *spare_volume, *target_volume;
	UINT64 working_lba, spare_lba;
	UINTN block_count;
	BOOLEAN target_is_boot;
};

EFI_STATUS cdk2_ftw_fvb_initialize(struct cdk2_ftw_fvb *adapter, UINT8 *scratch);
EFI_STATUS cdk2_ftw_fvb_select_target(struct cdk2_ftw_fvb *adapter,
	void *volume, UINT64 lba);
EFI_STATUS cdk2_ftw_fvb_write(struct cdk2_ftw_fvb *adapter, UINT64 lba,
	UINTN offset, UINTN length, const void *private_data, const void *buffer);
#endif
