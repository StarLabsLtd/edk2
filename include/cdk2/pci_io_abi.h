/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CDK2_PCI_IO_ABI_H
#define CDK2_PCI_IO_ABI_H

#include <cdk2/pci_io_model.h>
#include <uefi.h>

struct cdk2_efi_pci_io_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_poll_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, UINT8, UINT64, UINT64, UINT64,
	UINT64, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_access_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, UINT8, UINT64, UINTN, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_config_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, UINT32, UINTN, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_copy_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, UINT8, UINT64, UINT8, UINT64, UINTN);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_map_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, void *, UINTN *, UINT64 *, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_unmap_fn(
	struct cdk2_efi_pci_io_protocol *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_allocate_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, UINTN, UINTN, void **, UINT64);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_free_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_flush_fn(
	struct cdk2_efi_pci_io_protocol *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_location_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN *, UINTN *, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_attributes_fn(
	struct cdk2_efi_pci_io_protocol *, UINTN, UINT64, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_get_bar_fn(
	struct cdk2_efi_pci_io_protocol *, UINT8, UINT64 *, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_pci_io_set_bar_fn(
	struct cdk2_efi_pci_io_protocol *, UINT64, UINT8, UINT64 *, UINT64 *);

struct cdk2_pci_io_access_pair {
	cdk2_pci_io_access_fn *read;
	cdk2_pci_io_access_fn *write;
};
struct cdk2_pci_io_config_pair {
	cdk2_pci_io_config_fn *read;
	cdk2_pci_io_config_fn *write;
};
struct cdk2_efi_pci_io_protocol {
	cdk2_pci_io_poll_fn *poll_mem, *poll_io;
	struct cdk2_pci_io_access_pair mem, io;
	struct cdk2_pci_io_config_pair pci;
	cdk2_pci_io_copy_fn *copy_mem;
	cdk2_pci_io_map_fn *map;
	cdk2_pci_io_unmap_fn *unmap;
	cdk2_pci_io_allocate_fn *allocate_buffer;
	cdk2_pci_io_free_fn *free_buffer;
	cdk2_pci_io_flush_fn *flush;
	cdk2_pci_io_location_fn *get_location;
	cdk2_pci_io_attributes_fn *attributes;
	cdk2_pci_io_get_bar_fn *get_bar_attributes;
	cdk2_pci_io_set_bar_fn *set_bar_attributes;
	UINT64 rom_size;
	void *rom_image;
};

struct cdk2_pci_io_instance {
	struct cdk2_efi_pci_io_protocol protocol;
	struct cdk2_pci_io_model owned_model;
};

void cdk2_pci_io_initialize_protocol(struct cdk2_pci_io_instance *instance,
	struct cdk2_pci_io_model *model);

#endif
