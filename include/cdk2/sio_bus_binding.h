/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SIO_BUS_BINDING_H_
#define CDK2_SIO_BUS_BINDING_H_

#include <cdk2/sio_bus.h>

#define CDK2_SIO_PCI_IO 0x100U
#define CDK2_SIO_PCI_MEMORY 0x200U
#define CDK2_SIO_PCI_BUS_MASTER 0x400U
#define CDK2_SIO_PCI_ISA_IO 0x2U
#define CDK2_SIO_PCI_ISA_IO_16 0x10000U
#define CDK2_SIO_PCI_MOTHERBOARD_IO 0x1U
#define CDK2_SIO_NOT_STARTED ((1ULL << 63) | 19ULL)

struct cdk2_sio_pci_info {
	UINT16 vendor_id;
	UINT16 command;
	UINT8 base_class;
	UINT8 sub_class;
	UINT8 function;
};
struct cdk2_sio_child {
	struct cdk2_sio protocol;
	void *handle;
	void *device_path;
	BOOLEAN installed;
	BOOLEAN related;
};
typedef EFI_STATUS cdk2_sio_parent_fn(void *, void *);
typedef EFI_STATUS cdk2_sio_info_fn(void *, void *, struct cdk2_sio_pci_info *);
typedef EFI_STATUS cdk2_sio_attr_fn(void *, void *, UINT64, UINT64 *);
typedef EFI_STATUS cdk2_sio_child_fn(void *, void *, struct cdk2_sio_child *, UINTN);
struct cdk2_sio_binding_ops {
	cdk2_sio_parent_fn *open_pci;
	cdk2_sio_parent_fn *close_pci;
	cdk2_sio_parent_fn *open_device_path;
	cdk2_sio_parent_fn *close_device_path;
	cdk2_sio_info_fn *get_info;
	cdk2_sio_attr_fn *get_attributes;
	cdk2_sio_attr_fn *supported_attributes;
	cdk2_sio_attr_fn *enable_attributes;
	cdk2_sio_attr_fn *set_attributes;
	cdk2_sio_child_fn *install_child;
	cdk2_sio_child_fn *uninstall_child;
	cdk2_sio_child_fn *open_child;
	cdk2_sio_child_fn *close_child;
};
struct cdk2_sio_binding {
	const struct cdk2_sio_binding_ops *ops;
	void *context;
	void *controller;
	struct cdk2_sio_child children[3];
	UINT64 original_attributes;
	UINTN child_count;
	BOOLEAN pci_open;
	BOOLEAN path_open;
	BOOLEAN attributes_enabled;
};

EFI_STATUS cdk2_sio_binding_supported(struct cdk2_sio_binding *binding,
	void *controller);
EFI_STATUS cdk2_sio_binding_start(struct cdk2_sio_binding *binding,
	void *controller);
EFI_STATUS cdk2_sio_binding_stop(struct cdk2_sio_binding *binding,
	UINTN number_of_children, void **child_handles);

#endif
