/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_FTW_ENTRY_H
#define CDK2_FTW_ENTRY_H

#include <cdk2/capsule_runtime_entry.h>
#include <cdk2/ftw.h>

struct cdk2_config_table_view {
	EFI_GUID guid;
	void *table;
};

struct cdk2_ftw_system_table_view {
	struct cdk2_table_header header;
	CHAR16 *vendor;
	UINT32 revision;
	UINT32 padding;
	void *console_fields[6];
	struct cdk2_runtime_services_view *runtime;
	struct cdk2_boot_services_view *boot;
	UINTN table_count;
	struct cdk2_config_table_view *tables;
};

struct cdk2_fvb_protocol_view {
	EFI_STATUS (CDK2_MS_ABI *get_attributes)(void *, UINT64 *);
	EFI_STATUS (CDK2_MS_ABI *set_attributes)(void *, UINT64 *);
	EFI_STATUS (CDK2_MS_ABI *get_physical_address)(void *, UINT64 *);
	EFI_STATUS (CDK2_MS_ABI *get_block_size)(void *, UINT64, UINTN *, UINTN *);
	EFI_STATUS (CDK2_MS_ABI *read)(void *, UINT64, UINTN, UINTN *, void *);
	EFI_STATUS (CDK2_MS_ABI *write)(void *, UINT64, UINTN, UINTN *, const void *);
	EFI_STATUS (CDK2_MS_ABI *erase_blocks)(void *, ...);
};

struct cdk2_ftw_protocol_view {
	EFI_STATUS (CDK2_MS_ABI *get_max_block_size)(void *, UINTN *);
	EFI_STATUS (CDK2_MS_ABI *allocate)(void *, EFI_GUID *, UINTN, UINTN);
	EFI_STATUS (CDK2_MS_ABI *write)(void *, UINT64, UINTN, UINTN, void *, void *, void *);
	EFI_STATUS (CDK2_MS_ABI *restart)(void *, void *);
	EFI_STATUS (CDK2_MS_ABI *abort)(void *);
	EFI_STATUS (CDK2_MS_ABI *get_last_write)(void *, EFI_GUID *, UINT64 *, UINTN *,
		UINTN *, UINTN *, void *, BOOLEAN *);
};

typedef char cdk2_ftw_system_boot_abi[
	(offsetof(struct cdk2_ftw_system_table_view, boot) == 96U) ? 1 : -1];
typedef char cdk2_ftw_system_tables_abi[
	(offsetof(struct cdk2_ftw_system_table_view, tables) == 112U) ? 1 : -1];
typedef char cdk2_fvb_protocol_abi[
	(sizeof(struct cdk2_fvb_protocol_view) == 56U) ? 1 : -1];
typedef char cdk2_ftw_protocol_abi[
	(sizeof(struct cdk2_ftw_protocol_view) == 48U) ? 1 : -1];

EFI_STATUS CDK2_MS_ABI cdk2_ftw_entry(void *, struct cdk2_ftw_system_table_view *);
void cdk2_ftw_entry_reset_for_test(void);

#endif
