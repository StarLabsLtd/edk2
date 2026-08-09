/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_ATA_ATAPI_BACKEND_H_
#define CDK2_ATA_ATAPI_BACKEND_H_

#include <cdk2/ata_atapi_pci_adapter.h>

typedef EFI_STATUS cdk2_ata_backend_allocate_fn(void *, size_t, void **);
typedef void cdk2_ata_backend_release_fn(void *, void *, size_t);
struct cdk2_ata_backend_pool {
	void *context;
	cdk2_ata_backend_allocate_fn *allocate;
	cdk2_ata_backend_release_fn *release;
};
struct cdk2_ata_controller_backend {
	struct cdk2_ata_pci_adapter adapter;
	struct cdk2_ahci_engine ahci;
	struct cdk2_ide_engine ide;
	struct cdk2_ata_backend_pool pool;
	UINT8 identify[512] __aligned(8);
	UINT8 ahci_initialized, ide_initialized;
};

EFI_STATUS cdk2_ata_backend_prepare(struct cdk2_ata_backend_pool *pool,
	struct cdk2_ata_controller *controller);
void cdk2_ata_backend_release(struct cdk2_ata_controller *controller);
EFI_STATUS cdk2_ata_backend_discover_ahci(struct cdk2_ata_controller *controller,
	struct cdk2_ata_topology *topology);
EFI_STATUS cdk2_ata_backend_discover_ide(struct cdk2_ata_controller *controller,
	struct cdk2_ata_topology *topology);

#endif
