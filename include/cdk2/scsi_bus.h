/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_SCSI_BUS_H_
#define CDK2_SCSI_BUS_H_
#include <stdint.h>
#include <uefi.h>
#define CDK2_SCSI_TARGET_MAX 16U
#define CDK2_SCSI_HOST_ADAPTER_STATUS_OK 0U
#define CDK2_SCSI_ALREADY_STARTED ((1ULL << 63) | 20ULL)
struct cdk2_scsi_target { UINT8 id[CDK2_SCSI_TARGET_MAX]; UINT64 lun; };
struct cdk2_scsi_request {
	UINT64 timeout;
	void *in_data;
	void *out_data;
	void *sense_data;
	void *cdb;
	UINT32 in_length;
	UINT32 out_length;
	UINT8 sense_length;
	UINT8 cdb_length;
	UINT8 data_direction;
	UINT8 host_status;
	UINT8 target_status;
};
typedef EFI_STATUS cdk2_scsi_pass_fn(void *, const UINT8 *, UINT64,
	struct cdk2_scsi_request *, void *);
typedef EFI_STATUS cdk2_scsi_reset_bus_fn(void *);
typedef EFI_STATUS cdk2_scsi_reset_target_fn(void *, const UINT8 *, UINT64);
typedef EFI_STATUS cdk2_scsi_next_fn(void *, UINT8 **, UINT64 *);
typedef EFI_STATUS cdk2_scsi_build_path_fn(void *, const UINT8 *, UINT64, void **);
typedef void cdk2_scsi_release_path_fn(void *, void *);
struct cdk2_scsi_backend {
	void *interface;
	UINT32 io_align;
	UINT32 attributes;
	cdk2_scsi_pass_fn *pass;
	cdk2_scsi_reset_bus_fn *reset_bus;
	cdk2_scsi_reset_target_fn *reset_target;
	cdk2_scsi_next_fn *next;
	cdk2_scsi_build_path_fn *build_path;
	cdk2_scsi_release_path_fn *release_path;
};
struct cdk2_scsi_device {
	struct cdk2_scsi_backend backend;
	struct cdk2_scsi_target location;
	UINT8 device_type;
};
EFI_STATUS cdk2_scsi_device_init(struct cdk2_scsi_device *device,
	const struct cdk2_scsi_backend *backend,
	const struct cdk2_scsi_target *target, UINT8 device_type);
EFI_STATUS cdk2_scsi_get_location(const struct cdk2_scsi_device *device,
	UINT8 **target, UINT64 *lun);
EFI_STATUS cdk2_scsi_reset_bus(struct cdk2_scsi_device *device);
EFI_STATUS cdk2_scsi_reset_device(struct cdk2_scsi_device *device);
EFI_STATUS cdk2_scsi_execute(struct cdk2_scsi_device *device,
	struct cdk2_scsi_request *request, void *event);
BOOLEAN cdk2_scsi_target_equal(const struct cdk2_scsi_target *left,
	const struct cdk2_scsi_target *right);
typedef EFI_STATUS cdk2_scsi_publish_fn(void *, struct cdk2_scsi_device *, void *);
typedef EFI_STATUS cdk2_scsi_unpublish_fn(void *, struct cdk2_scsi_device *, void *);
struct cdk2_scsi_bus {
	struct cdk2_scsi_backend backend;
	struct cdk2_scsi_device *devices;
	void **paths;
	UINTN capacity;
	UINTN count;
	void *context;
	cdk2_scsi_publish_fn *publish;
	cdk2_scsi_unpublish_fn *unpublish;
};
EFI_STATUS cdk2_scsi_enumerate(struct cdk2_scsi_bus *bus,
	const struct cdk2_scsi_target *only);
EFI_STATUS cdk2_scsi_remove_all(struct cdk2_scsi_bus *bus);
#endif
