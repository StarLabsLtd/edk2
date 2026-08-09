/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CDK2_PCI_BUS_ADAPTER_H
#define CDK2_PCI_BUS_ADAPTER_H

#include <cdk2/pci_io_model.h>
#include <uefi.h>

typedef EFI_STATUS cdk2_boot_access_fn(void *, enum cdk2_pci_io_space, int,
	unsigned int, uint64_t, size_t, void *);
typedef EFI_STATUS cdk2_boot_delay_fn(void *, uint64_t);
typedef EFI_STATUS cdk2_boot_map_fn(void *, unsigned int, void *, size_t *,
	uint64_t *, void **);
typedef EFI_STATUS cdk2_boot_unmap_fn(void *, void *);
typedef EFI_STATUS cdk2_boot_allocate_pages_fn(void *, size_t, int, void **);
typedef EFI_STATUS cdk2_boot_free_pages_fn(void *, size_t, void *);
typedef EFI_STATUS cdk2_boot_flush_fn(void *);
typedef EFI_STATUS cdk2_boot_allocate_pool_fn(void *, size_t, void **);
typedef EFI_STATUS cdk2_boot_gcd_fn(void *, unsigned int, uint64_t, uint64_t,
	uint64_t);

struct cdk2_pci_io_boot_adapter {
	void *context;
	cdk2_boot_access_fn *access;
	cdk2_boot_delay_fn *delay;
	cdk2_boot_map_fn *iommu_map;
	cdk2_boot_unmap_fn *iommu_unmap;
	cdk2_boot_map_fn *root_map;
	cdk2_boot_unmap_fn *root_unmap;
	cdk2_boot_allocate_pages_fn *allocate_pages;
	cdk2_boot_free_pages_fn *free_pages;
	cdk2_boot_flush_fn *flush;
	cdk2_boot_allocate_pool_fn *allocate_pool;
	cdk2_boot_gcd_fn *gcd_set_attributes;
	EFI_STATUS last_status;
};

void cdk2_pci_io_attach_boot_adapter(struct cdk2_pci_io_model *io,
	struct cdk2_pci_io_boot_adapter *adapter);
EFI_STATUS cdk2_pci_io_adapter_status(const struct cdk2_pci_io_boot_adapter *adapter);

#endif
