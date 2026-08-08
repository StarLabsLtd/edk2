/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_HII_DATABASE_H_
#define CDK2_HII_DATABASE_H_

#include <uefi.h>

#define CDK2_HII_MAX_LISTS 64U
#define CDK2_HII_MAX_NOTIFIES 32U
#define CDK2_HII_PACKAGE_END 0xdfU

struct cdk2_hii_package_list_header {
	EFI_GUID guid;
	UINT32 length;
};
struct cdk2_hii_package_header {
	UINT32 length_and_type;
};
typedef EFI_STATUS cdk2_hii_allocate_fn(void *context, UINTN size, void **buffer);
typedef void cdk2_hii_release_fn(void *context, void *buffer);
typedef EFI_STATUS cdk2_hii_notify_fn(void *context, UINT8 package_type,
	const EFI_GUID *package_guid, const void *package_list, void *handle,
	UINTN notify_type);
struct cdk2_hii_database_ops {
	cdk2_hii_allocate_fn *allocate;
	cdk2_hii_release_fn *release;
};
struct cdk2_hii_list {
	void *data, *driver_handle;
	UINT32 size;
	BOOLEAN active;
};
struct cdk2_hii_notify {
	UINT8 package_type;
	EFI_GUID package_guid;
	cdk2_hii_notify_fn *callback;
	void *context;
	UINTN notify_mask;
	BOOLEAN use_guid, active;
};
struct cdk2_hii_database {
	const struct cdk2_hii_database_ops *ops;
	void *context;
	struct cdk2_hii_list lists[CDK2_HII_MAX_LISTS];
	struct cdk2_hii_notify notifies[CDK2_HII_MAX_NOTIFIES];
};

EFI_STATUS cdk2_hii_database_init(struct cdk2_hii_database *database,
	const struct cdk2_hii_database_ops *ops, void *context);
EFI_STATUS cdk2_hii_new_package_list(struct cdk2_hii_database *database,
	const void *package_list, void *driver_handle, void **handle);
EFI_STATUS cdk2_hii_remove_package_list(struct cdk2_hii_database *database,
	void *handle);
EFI_STATUS cdk2_hii_update_package_list(struct cdk2_hii_database *database,
	void *handle, const void *package_list);
EFI_STATUS cdk2_hii_export_package_lists(struct cdk2_hii_database *database,
	void *handle, UINTN *size, void *buffer);
EFI_STATUS cdk2_hii_list_package_lists(struct cdk2_hii_database *database,
	UINT8 package_type, const EFI_GUID *package_guid, UINTN *count,
	void **handles);
EFI_STATUS cdk2_hii_register_package_notify(struct cdk2_hii_database *database,
	UINT8 package_type, const EFI_GUID *package_guid, cdk2_hii_notify_fn *callback,
	void *context, UINTN notify_mask, void **notify_handle);
EFI_STATUS cdk2_hii_unregister_package_notify(struct cdk2_hii_database *database,
	void *notify_handle);

#endif
