/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_FAT_BINDING_H_
#define CDK2_FAT_BINDING_H_

#include <cdk2/disk_io.h>
#include <cdk2/fat.h>
#include <cdk2/english.h>

struct cdk2_fat_binding_ops {
	EFI_STATUS (*open)(void *, void *, const EFI_GUID *, void **);
	EFI_STATUS (*close)(void *, void *, const EFI_GUID *);
	EFI_STATUS (*publish)(void *, void *, const EFI_GUID *, void *);
	EFI_STATUS (*unpublish)(void *, void *, const EFI_GUID *, void *);
	EFI_STATUS (*allocate)(void *, UINTN, void **);
	void (*release)(void *, void *);
	EFI_STATUS (*signal)(void *, void *);
	EFI_STATUS (*queue)(void *, void (*)(void *), void *, void **);
	void (*drain)(void *, void *);
	EFI_STATUS (*create_event)(void *, void (CDK2_MS_ABI *)(void *, void *),
		void *, void **);
	EFI_STATUS (*close_event)(void *, void *);
	EFI_STATUS (*wait_event)(void *, void *);
};
struct cdk2_fat_io_token { void *event; EFI_STATUS transaction_status; };
struct cdk2_fat_binding;
struct cdk2_fat_protocol_volume;
EFI_STATUS cdk2_fat_complete_io(const struct cdk2_fat_binding *binding,
	struct cdk2_fat_io_token *token, EFI_STATUS status);

struct cdk2_fat_mount {
	struct cdk2_fat_mount *next;
	struct cdk2_fat_volume volume;
	struct cdk2_block_io *block;
	struct cdk2_disk_io *disk;
	struct cdk2_disk_io2 *disk2;
	void *controller;
	struct cdk2_fat_protocol_volume *simple_fs;
	UINT32 media_id;
	UINTN open_handles;
	BOOLEAN published, block_open, disk_open, disk2_open;
};

struct cdk2_fat_binding {
	const struct cdk2_fat_binding_ops *ops;
	void *context;
	struct cdk2_fat_mount *mounts;
	struct cdk2_unicode_collation *collation;
};

extern const EFI_GUID cdk2_fat_block_io_guid;
extern const EFI_GUID cdk2_fat_disk_io_guid;
extern const EFI_GUID cdk2_fat_disk_io2_guid;
extern const EFI_GUID cdk2_fat_simple_fs_guid;

EFI_STATUS cdk2_fat_binding_start(struct cdk2_fat_binding *binding,
	void *controller);
EFI_STATUS cdk2_fat_binding_stop(struct cdk2_fat_binding *binding,
	void *controller);
EFI_STATUS cdk2_fat_binding_refresh(struct cdk2_fat_mount *mount);
EFI_STATUS cdk2_fat_binding_open_handle(struct cdk2_fat_mount *mount);
void cdk2_fat_binding_close_handle(struct cdk2_fat_mount *mount);

struct cdk2_fat_file_protocol;
struct cdk2_fat_file_io_token {
	void *event;
	EFI_STATUS status;
	UINTN buffer_size;
	void *buffer;
};
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_open_fn(
	struct cdk2_fat_file_protocol *, struct cdk2_fat_file_protocol **,
	CHAR16 *, UINT64, UINT64);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_close_fn(struct cdk2_fat_file_protocol *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_delete_fn(struct cdk2_fat_file_protocol *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_rw_fn(
	struct cdk2_fat_file_protocol *, UINTN *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_position_get_fn(
	struct cdk2_fat_file_protocol *, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_position_set_fn(
	struct cdk2_fat_file_protocol *, UINT64);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_info_get_fn(
	struct cdk2_fat_file_protocol *, EFI_GUID *, UINTN *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_info_set_fn(
	struct cdk2_fat_file_protocol *, EFI_GUID *, UINTN, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_flush_fn(struct cdk2_fat_file_protocol *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_open_ex_fn(
	struct cdk2_fat_file_protocol *, struct cdk2_fat_file_protocol **,
	CHAR16 *, UINT64, UINT64, struct cdk2_fat_file_io_token *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_rw_ex_fn(
	struct cdk2_fat_file_protocol *, struct cdk2_fat_file_io_token *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fat_file_flush_ex_fn(
	struct cdk2_fat_file_protocol *, struct cdk2_fat_file_io_token *);

struct cdk2_fat_file_protocol {
	UINT64 revision;
	cdk2_fat_file_open_fn *open;
	cdk2_fat_file_close_fn *close;
	cdk2_fat_file_delete_fn *delete;
	cdk2_fat_file_rw_fn *read;
	cdk2_fat_file_rw_fn *write;
	cdk2_fat_file_position_get_fn *get_position;
	cdk2_fat_file_position_set_fn *set_position;
	cdk2_fat_file_info_get_fn *get_info;
	cdk2_fat_file_info_set_fn *set_info;
	cdk2_fat_file_flush_fn *flush;
	cdk2_fat_file_open_ex_fn *open_ex;
	cdk2_fat_file_rw_ex_fn *read_ex;
	cdk2_fat_file_rw_ex_fn *write_ex;
	cdk2_fat_file_flush_ex_fn *flush_ex;
};

struct cdk2_fat_simple_fs_protocol {
	UINT64 revision;
	EFI_STATUS CDK2_MS_ABI (*open_volume)(struct cdk2_fat_simple_fs_protocol *,
		struct cdk2_fat_file_protocol **);
};

struct cdk2_fat_protocol_volume {
	struct cdk2_fat_simple_fs_protocol protocol;
	struct cdk2_fat_binding *binding;
	struct cdk2_fat_mount *mount;
};

extern const EFI_GUID cdk2_fat_file_info_guid;
extern const EFI_GUID cdk2_fat_fs_info_guid;
extern const EFI_GUID cdk2_fat_volume_label_info_guid;
void cdk2_fat_protocol_init(struct cdk2_fat_protocol_volume *volume,
	struct cdk2_fat_binding *binding, struct cdk2_fat_mount *mount);
EFI_STATUS CDK2_MS_ABI cdk2_fat_entry(void *image, void *system_table);
EFI_STATUS cdk2_fat_driver_name(BOOLEAN component_name2, CHAR8 *language,
	CHAR16 **name);

#endif
