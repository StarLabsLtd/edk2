/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_FAT_BINDING_H_
#define CDK2_FAT_BINDING_H_

#include <cdk2/disk_io.h>
#include <cdk2/fat.h>

struct cdk2_fat_binding_ops {
	EFI_STATUS (*open)(void *, void *, const EFI_GUID *, void **);
	EFI_STATUS (*close)(void *, void *, const EFI_GUID *);
	EFI_STATUS (*publish)(void *, void *, const EFI_GUID *, void *);
	EFI_STATUS (*unpublish)(void *, void *, const EFI_GUID *, void *);
	EFI_STATUS (*allocate)(void *, UINTN, void **);
	void (*release)(void *, void *);
	EFI_STATUS (*signal)(void *, void *);
};
struct cdk2_fat_io_token { void *event; EFI_STATUS transaction_status; };
struct cdk2_fat_binding;
EFI_STATUS cdk2_fat_complete_io(const struct cdk2_fat_binding *binding,
	struct cdk2_fat_io_token *token, EFI_STATUS status);

struct cdk2_fat_mount {
	struct cdk2_fat_mount *next;
	struct cdk2_fat_volume volume;
	struct cdk2_block_io *block;
	struct cdk2_disk_io *disk;
	void *controller;
	UINT32 media_id;
	UINTN open_handles;
	BOOLEAN published;
};

struct cdk2_fat_binding {
	const struct cdk2_fat_binding_ops *ops;
	void *context;
	struct cdk2_fat_mount *mounts;
};

extern const EFI_GUID cdk2_fat_block_io_guid;
extern const EFI_GUID cdk2_fat_disk_io_guid;
extern const EFI_GUID cdk2_fat_simple_fs_guid;

EFI_STATUS cdk2_fat_binding_start(struct cdk2_fat_binding *binding,
	void *controller);
EFI_STATUS cdk2_fat_binding_stop(struct cdk2_fat_binding *binding,
	void *controller);
EFI_STATUS cdk2_fat_binding_refresh(struct cdk2_fat_mount *mount);
EFI_STATUS cdk2_fat_binding_open_handle(struct cdk2_fat_mount *mount);
void cdk2_fat_binding_close_handle(struct cdk2_fat_mount *mount);

#endif
