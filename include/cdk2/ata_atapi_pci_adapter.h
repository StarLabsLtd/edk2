/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_ATA_ATAPI_PCI_ADAPTER_H_
#define CDK2_ATA_ATAPI_PCI_ADAPTER_H_

#include <cdk2/ata_atapi_pass_thru.h>
#include <cdk2/pci_io_abi.h>

#define CDK2_ATA_ADAPTER_ALLOCATIONS 40U
struct cdk2_ide_init_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_ide_channel_fn(
	struct cdk2_ide_init_protocol *, UINT8, BOOLEAN *, UINT8 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ide_notify_fn(
	struct cdk2_ide_init_protocol *, UINTN, UINT8);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ide_submit_fn(
	struct cdk2_ide_init_protocol *, UINT8, UINT8, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ide_calculate_fn(
	struct cdk2_ide_init_protocol *, UINT8, UINT8, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ide_timing_fn(
	struct cdk2_ide_init_protocol *, UINT8, UINT8, void *);
struct cdk2_ide_init_protocol {
	cdk2_ide_channel_fn *get_channel;
	cdk2_ide_notify_fn *notify;
	cdk2_ide_submit_fn *submit;
	void *disqualify;
	cdk2_ide_calculate_fn *calculate;
	cdk2_ide_timing_fn *timing;
	BOOLEAN enum_all; UINT8 channel_count;
};
struct cdk2_ata_adapter_allocation {
	void *host, *mapping;
	UINTN pages;
};
struct cdk2_ata_pci_adapter {
	struct cdk2_efi_pci_io_protocol *pci;
	struct cdk2_ide_init_protocol *ide;
	struct cdk2_ata_adapter_allocation allocations[CDK2_ATA_ADAPTER_ALLOCATIONS];
	UINT8 ahci_bar;
	UINT8 timing_ready;
	UINT8 ahci_mode_owned;
	UINT32 original_ghc;
	UINT64 ticks;
};

EFI_STATUS cdk2_ata_pci_adapter_init(struct cdk2_ata_pci_adapter *adapter,
	struct cdk2_efi_pci_io_protocol *pci, struct cdk2_ide_init_protocol *ide,
	UINT8 ahci_bar);
void cdk2_ata_pci_ahci_services(struct cdk2_ata_pci_adapter *adapter,
	struct cdk2_ahci_dma_services *services);
void cdk2_ata_pci_ide_services(struct cdk2_ata_pci_adapter *adapter,
	struct cdk2_ide_services *services);
EFI_STATUS cdk2_ata_pci_adapter_release(struct cdk2_ata_pci_adapter *adapter);
EFI_STATUS cdk2_ata_pci_enable_ahci(struct cdk2_ata_pci_adapter *adapter);
void cdk2_ata_pci_adapter_enable_timing(struct cdk2_ata_pci_adapter *adapter,
	UINT8 channel, UINT8 device);
EFI_STATUS cdk2_ata_pci_read_class(struct cdk2_efi_pci_io_protocol *pci,
	UINT8 class_code[3]);
EFI_STATUS cdk2_ata_pci_get_attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINT64 *current, UINT64 *supported);
EFI_STATUS cdk2_ata_pci_enable_attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINT64 attributes);
EFI_STATUS cdk2_ata_pci_restore_attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINT64 attributes);
EFI_STATUS cdk2_ata_pci_read_ahci_capability(
	struct cdk2_efi_pci_io_protocol *pci, UINT8 bar, UINT32 *capability,
	UINT32 *ports_implemented);

#endif
