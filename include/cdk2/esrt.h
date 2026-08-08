/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_ESRT_H
#define CDK2_ESRT_H

#include <uefi.h>

#define CDK2_ESRT_TYPE_SYSTEM 1U
#define CDK2_ESRT_TYPE_DEVICE 2U
#define CDK2_ESRT_TYPE_UEFI_DRIVER 3U
#define CDK2_ESRT_IMAGE_IN_USE BIT3
#define CDK2_ESRT_IMAGE_RESET_REQUIRED BIT1
#define CDK2_ESRT_LAST_ATTEMPT_SUCCESS 0U
#ifndef EFI_WRITE_PROTECTED
#define EFI_WRITE_PROTECTED EFIERR(8)
#endif

enum cdk2_esrt_store { CDK2_ESRT_FMP, CDK2_ESRT_NON_FMP };

struct cdk2_esrt_entry {
	EFI_GUID firmware_class;
	UINT32 firmware_type;
	UINT32 firmware_version;
	UINT32 lowest_supported_version;
	UINT32 capsule_flags;
	UINT32 last_attempt_version;
	UINT32 last_attempt_status;
};

struct cdk2_esrt_table {
	UINT32 resource_count;
	UINT32 resource_count_max;
	UINT64 resource_version;
	struct cdk2_esrt_entry entries[];
};

struct cdk2_esrt_fmp_image {
	EFI_GUID image_type_id;
	UINT32 version;
	UINT64 attributes_supported;
	UINT64 attributes_setting;
	UINT32 lowest_supported_version;
	UINT32 last_attempt_version;
	UINT32 last_attempt_status;
	UINT32 descriptor_version;
};

typedef EFI_STATUS cdk2_esrt_read_fn(void *, enum cdk2_esrt_store,
	struct cdk2_esrt_entry *, UINTN, UINTN *);
typedef EFI_STATUS cdk2_esrt_write_fn(void *, enum cdk2_esrt_store,
	const struct cdk2_esrt_entry *, UINTN);
typedef EFI_STATUS cdk2_esrt_lock_fn(void *, enum cdk2_esrt_store);
typedef EFI_STATUS cdk2_esrt_publish_fn(void *, const struct cdk2_esrt_table *, UINTN);
typedef EFI_STATUS cdk2_esrt_install_fn(void *, void *);
typedef EFI_STATUS cdk2_esrt_uninstall_fn(void *, void *);
typedef EFI_STATUS cdk2_esrt_event_fn(void *, void *, void **);
typedef EFI_STATUS cdk2_esrt_close_event_fn(void *, void *);

struct cdk2_esrt_ops {
	cdk2_esrt_read_fn *read;
	cdk2_esrt_write_fn *write;
	cdk2_esrt_lock_fn *lock;
	cdk2_esrt_publish_fn *publish;
	cdk2_esrt_install_fn *install_management;
	cdk2_esrt_uninstall_fn *uninstall_management;
	cdk2_esrt_event_fn *create_ready_to_boot;
	cdk2_esrt_close_event_fn *close_event;
};

struct cdk2_esrt {
	const struct cdk2_esrt_ops *ops;
	void *context;
	UINTN max_fmp;
	UINTN max_non_fmp;
	UINT32 reboot_capsule_flags;
	const EFI_GUID *system_classes;
	UINTN system_class_count;
	BOOLEAN locked;
	BOOLEAN management_installed;
	void *ready_event;
};

EFI_STATUS cdk2_esrt_get(struct cdk2_esrt *esrt, const EFI_GUID *firmware_class,
	struct cdk2_esrt_entry *entry);
EFI_STATUS cdk2_esrt_register(struct cdk2_esrt *esrt,
	const struct cdk2_esrt_entry *entry);
EFI_STATUS cdk2_esrt_unregister(struct cdk2_esrt *esrt,
	const EFI_GUID *firmware_class);
EFI_STATUS cdk2_esrt_update(struct cdk2_esrt *esrt,
	const struct cdk2_esrt_entry *entry);
EFI_STATUS cdk2_esrt_sync_fmp(struct cdk2_esrt *esrt,
	const struct cdk2_esrt_fmp_image *images, UINTN image_count,
	const struct cdk2_esrt_table *published);
EFI_STATUS cdk2_esrt_lock(struct cdk2_esrt *esrt);
EFI_STATUS cdk2_esrt_ready_to_boot(struct cdk2_esrt *esrt);
EFI_STATUS cdk2_esrt_activate(struct cdk2_esrt *esrt);

#endif
