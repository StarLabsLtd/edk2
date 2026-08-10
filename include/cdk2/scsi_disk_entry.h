/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_SCSI_DISK_ENTRY_H_
#define CDK2_SCSI_DISK_ENTRY_H_

#include <cdk2/scsi_disk.h>

struct cdk2_scsi_disk_driver_binding;
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_supported_fn(
	struct cdk2_scsi_disk_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_start_fn(
	struct cdk2_scsi_disk_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_stop_fn(
	struct cdk2_scsi_disk_driver_binding *, void *, UINTN, void **);

struct cdk2_scsi_disk_driver_binding {
	cdk2_scsi_disk_supported_fn *supported;
	cdk2_scsi_disk_start_fn *start;
	cdk2_scsi_disk_stop_fn *stop;
	UINT32 version;
	void *image_handle;
	void *driver_binding_handle;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_unload_fn(void *image);

struct cdk2_scsi_disk_loaded_image {
	UINT32 revision;
	void *parent_handle, *system_table, *device_handle, *file_path;
	void *reserved;
	UINT32 load_options_size;
	void *load_options, *image_base;
	UINT64 image_size;
	UINT32 image_code_type, image_data_type;
	cdk2_scsi_disk_unload_fn *unload;
};

struct cdk2_scsi_disk_entry {
	void *image;
	void *system;
	void *boot;
	struct cdk2_scsi_disk_loaded_image *loaded;
	cdk2_scsi_disk_unload_fn *original_unload;
	struct cdk2_scsi_disk_driver_binding driver;
	struct cdk2_scsi_disk_binding binding;
	BOOLEAN published;
};

EFI_STATUS cdk2_scsi_disk_entry_publish(struct cdk2_scsi_disk_entry *entry,
	void *image, void *system);
EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_entry_unload(void *image);
EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_entry(void *image, void *system);

#endif
