/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/xhci.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { UINT64 attributes; UINTN maps, unmaps, allocs, frees, delays; };
static struct fixture *active;

static EFI_STATUS CDK2_MS_ABI access(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{
	(void)pci; (void)width; (void)bar; (void)offset; (void)count;
	memset(buffer, 0, count * 4U); return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI config(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT32 offset, UINTN count, void *buffer)
{
	UINT8 value[3] = { 0x30U, 0x03U, 0x0cU };
	(void)pci; (void)width; (void)offset; memcpy(buffer, value, count);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINTN operation, UINT64 value, UINT64 * result)
{
	(void)pci;
	if (operation == 0U)
		*result = active->attributes;
	else if (operation == 1U)
		*result = 0x700U;
	else if (operation == 2U)
		active->attributes |= value;
	else if (operation == 4U)
		active->attributes = value;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI allocate_buffer(struct cdk2_efi_pci_io_protocol *pci,
	UINTN type, UINTN memory, UINTN pages, void **host, UINT64 attributes_value)
{
	(void)pci; (void)type; (void)memory; (void)attributes_value;
	*host = aligned_alloc(4096U, pages * 4096U); active->allocs++;
	return *host == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI free_buffer(struct cdk2_efi_pci_io_protocol *pci,
	UINTN pages, void *host)
{ (void)pci; (void)pages; active->frees++; free(host); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI map(struct cdk2_efi_pci_io_protocol *pci,
	UINTN operation, void *host, UINTN * bytes, UINT64 * device, void **mapping)
{ (void)pci; (void)operation; (void)bytes; *device = (UINTN)host;
	*mapping = host; active->maps++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI unmap(struct cdk2_efi_pci_io_protocol *pci,
	void *mapping)
{ (void)pci; (void)mapping; active->unmaps++; return EFI_SUCCESS; }
static void delay(void *opaque, UINTN microseconds)
{ ((struct fixture *)opaque)->delays += microseconds; }

int main(void)
{
	struct fixture fixture = { .attributes = 0x200U };
	struct cdk2_efi_pci_io_protocol pci = { .mem = { access, access },
		.pci = { config, config }, .map = map, .unmap = unmap,
		.allocate_buffer = allocate_buffer, .free_buffer = free_buffer,
		.attributes = attributes };
	struct cdk2_xhci_pci_adapter adapter;
	struct cdk2_xhci_controller_services services;
	struct cdk2_xhci_dma dma;

	active = &fixture;
	CHECK(cdk2_xhci_pci_adapter_init(&adapter, &pci, 0U, &fixture, delay) ==
		EFI_SUCCESS && fixture.attributes == 0x700U);
	cdk2_xhci_pci_controller_services(&adapter, &services);
	CHECK(services.allocate_dma(services.context, 72U, 64U, &dma) == EFI_SUCCESS &&
		((UINTN)dma.host & 63U) == 0U && fixture.maps == 1U);
	services.release_dma(services.context, &dma);
	CHECK(cdk2_xhci_pci_adapter_release(&adapter) == EFI_SUCCESS &&
		fixture.attributes == 0x200U && fixture.unmaps == 1U &&
		fixture.allocs == fixture.frees);
	puts("xhci PCI adapter tests: PASS");
	return 0;
}
