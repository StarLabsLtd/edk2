/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SCSI_BUS_BINDING_H_
#define CDK2_SCSI_BUS_BINDING_H_

#include <cdk2/scsi_bus.h>

#define CDK2_OPEN_GET_PROTOCOL 0x02U
#define CDK2_OPEN_BY_DRIVER 0x10U
#define CDK2_OPEN_BY_CHILD_CONTROLLER 0x08U
#define CDK2_EXT_SCSI_NONBLOCKIO 0x04U

struct cdk2_device_path {
	UINT8 type;
	UINT8 subtype;
	UINT8 length[2];
};

struct cdk2_ext_scsi_mode {
	UINT32 adapter_id;
	UINT32 attributes;
	UINT32 io_align;
};

struct cdk2_ext_scsi;
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_pass_fn(struct cdk2_ext_scsi *, UINT8 *,
	UINT64, struct cdk2_scsi_request *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_next_fn(struct cdk2_ext_scsi *, UINT8 **,
	UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_build_fn(struct cdk2_ext_scsi *, UINT8 *,
	UINT64, struct cdk2_device_path **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_get_fn(struct cdk2_ext_scsi *,
	struct cdk2_device_path *, UINT8 **, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_reset_fn(struct cdk2_ext_scsi *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_reset_target_fn(struct cdk2_ext_scsi *,
	UINT8 *, UINT64);

struct cdk2_ext_scsi {
	cdk2_ext_pass_fn *pass_thru;
	cdk2_ext_next_fn *get_next_target_lun;
	cdk2_ext_build_fn *build_device_path;
	cdk2_ext_get_fn *get_target_lun;
	cdk2_ext_reset_fn *reset_channel;
	cdk2_ext_reset_target_fn *reset_target_lun;
	void *get_next_target;
	struct cdk2_ext_scsi_mode *mode;
};

struct cdk2_scsi_io;
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_type_fn(struct cdk2_scsi_io *, UINT8 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_location_fn(struct cdk2_scsi_io *, UINT8 **,
	UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_io_reset_fn(struct cdk2_scsi_io *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_io_execute_fn(struct cdk2_scsi_io *,
	struct cdk2_scsi_request *, void *);

struct cdk2_scsi_io {
	cdk2_scsi_type_fn *get_device_type;
	cdk2_scsi_location_fn *get_device_location;
	cdk2_scsi_io_reset_fn *reset_bus;
	cdk2_scsi_io_reset_fn *reset_device;
	cdk2_scsi_io_execute_fn *execute_scsi_command;
	UINT32 io_align;
};

struct cdk2_scsi_binding;
struct cdk2_scsi_child;
struct cdk2_scsi_driver_binding;
struct cdk2_scsi_component_name;
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_supported_fn(
	struct cdk2_scsi_driver_binding *, void *, struct cdk2_device_path *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_start_fn(
	struct cdk2_scsi_driver_binding *, void *, struct cdk2_device_path *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_stop_fn(
	struct cdk2_scsi_driver_binding *, void *, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_name_fn(struct cdk2_scsi_component_name *,
	CHAR8 *, CHAR16 **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_controller_name_fn(
	struct cdk2_scsi_component_name *, void *, void *, CHAR8 *, CHAR16 **);

struct cdk2_scsi_driver_binding {
	cdk2_scsi_supported_fn *supported;
	cdk2_scsi_start_fn *start;
	cdk2_scsi_stop_fn *stop;
	UINT32 version;
	void *image_handle;
	void *driver_binding_handle;
};

struct cdk2_scsi_component_name {
	cdk2_scsi_name_fn *get_driver_name;
	cdk2_scsi_controller_name_fn *get_controller_name;
	CHAR8 *supported_languages;
};

typedef EFI_STATUS cdk2_scsi_open_fn(void *, void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS cdk2_scsi_close_fn(void *, void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS cdk2_scsi_install_fn(void *, void **, const EFI_GUID *, void *,
	const EFI_GUID *, void *);
typedef EFI_STATUS cdk2_scsi_uninstall_fn(void *, void *, const EFI_GUID *, void *,
	const EFI_GUID *, void *);
typedef EFI_STATUS cdk2_scsi_locate_path_fn(void *, const EFI_GUID *,
	struct cdk2_device_path **, void **);
typedef EFI_STATUS cdk2_scsi_allocate_fn(void *, UINTN, void **);
typedef void cdk2_scsi_free_fn(void *, void *);
typedef EFI_STATUS cdk2_scsi_signal_fn(void *, void *);

struct cdk2_scsi_binding_ops {
	cdk2_scsi_open_fn *open;
	cdk2_scsi_close_fn *close;
	cdk2_scsi_install_fn *install;
	cdk2_scsi_uninstall_fn *uninstall;
	cdk2_scsi_locate_path_fn *locate_device_path;
	cdk2_scsi_allocate_fn *allocate;
	cdk2_scsi_free_fn *free;
	cdk2_scsi_signal_fn *signal;
};

struct cdk2_scsi_child {
	struct cdk2_scsi_child *next;
	struct cdk2_scsi_binding *owner;
	void *handle;
	struct cdk2_scsi_io io;
	struct cdk2_scsi_target target;
	struct cdk2_device_path *path;
	UINT8 device_type;
	BOOLEAN installed;
	BOOLEAN by_child;
};

struct cdk2_scsi_binding {
	const struct cdk2_scsi_binding_ops *ops;
	void *context;
	void *image;
	void *controller;
	struct cdk2_ext_scsi *pass_thru;
	struct cdk2_device_path *parent_path;
	struct cdk2_scsi_child *children;
	struct cdk2_scsi_driver_binding driver;
	struct cdk2_scsi_component_name component_name;
	struct cdk2_scsi_component_name component_name2;
	BOOLEAN path_open;
	BOOLEAN pass_open;
};

extern const EFI_GUID cdk2_ext_scsi_pass_thru_guid;
extern const EFI_GUID cdk2_scsi_io_guid;
extern const EFI_GUID cdk2_device_path_guid;

void cdk2_scsi_binding_init(struct cdk2_scsi_binding *binding,
	const struct cdk2_scsi_binding_ops *ops, void *context, void *image);
EFI_STATUS cdk2_scsi_binding_supported(struct cdk2_scsi_binding *binding,
	void *controller, struct cdk2_device_path *remaining);
EFI_STATUS cdk2_scsi_binding_start(struct cdk2_scsi_binding *binding,
	void *controller, struct cdk2_device_path *remaining);
EFI_STATUS cdk2_scsi_binding_stop(struct cdk2_scsi_binding *binding,
	void *controller, UINTN number_of_children, void **children);

#endif
