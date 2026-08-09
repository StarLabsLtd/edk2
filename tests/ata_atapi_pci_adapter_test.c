/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pci_adapter.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)
typedef UINTN native_uintn_t;
typedef UINT64 native_uint64_t;
struct fixture { unsigned int allocs, frees, maps, unmaps, flushes, mem, io, timings; };
static struct fixture fixture;
static EFI_STATUS CDK2_MS_ABI access(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{ (void)pci; (void)count; CHECK(bar < 6); CHECK(offset < 0x1000);
	fixture.mem++; memset(buffer, 0, (size_t)1U << width); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI io_access(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{ (void)pci; (void)count; CHECK(bar < 6); CHECK(offset < 0x1000);
	fixture.io++; memset(buffer, 0, (size_t)1U << width); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI pci_map(struct cdk2_efi_pci_io_protocol *pci,
	UINTN operation, void *host, native_uintn_t *size, native_uint64_t *device,
	void **mapping)
{ (void)pci; (void)operation; fixture.maps++; *device = (UINT64)(uintptr_t)host;
	*mapping = host; CHECK(*size != 0); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI unmap(struct cdk2_efi_pci_io_protocol *pci, void *mapping)
{ (void)pci; (void)mapping; fixture.unmaps++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI allocate(struct cdk2_efi_pci_io_protocol *pci,
	UINTN type, UINTN memory, UINTN pages, void **host, UINT64 attributes)
{ (void)pci; (void)type; (void)memory; (void)attributes; fixture.allocs++;
	*host = aligned_alloc(4096, pages * 4096); return *host == NULL ?
		EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI release(struct cdk2_efi_pci_io_protocol *pci,
	UINTN pages, void *host)
{ (void)pci; (void)pages; fixture.frees++; free(host); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI flush(struct cdk2_efi_pci_io_protocol *pci)
{ (void)pci; fixture.flushes++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI pci_attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINTN operation, UINT64 value, native_uint64_t *result)
{ (void)pci; (void)operation; (void)value; if (result != NULL) *result = 7;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI calculate(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, UINT8 device, void **mode)
{ (void)ide; CHECK(channel < 2 && device < 2); *mode = &fixture; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI timing(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, UINT8 device, void *mode)
{ (void)ide; (void)channel; (void)device; CHECK(mode == &fixture); fixture.timings++;
	return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_efi_pci_io_protocol pci = { .mem = { access, access },
		.io = { io_access, io_access }, .map = pci_map, .unmap = unmap,
		.allocate_buffer = allocate, .free_buffer = release, .flush = flush,
		.attributes = pci_attributes };
	struct cdk2_ide_init_protocol ide = { .calculate = calculate, .timing = timing };
	struct cdk2_ata_pci_adapter adapter; struct cdk2_ahci_dma_services ahci;
	struct cdk2_ide_services ide_services; void *host; UINT64 device;
	CHECK(sizeof(struct cdk2_efi_pci_io_protocol) == 160);
	CHECK(offsetof(struct cdk2_efi_pci_io_protocol, map) == 72);
	CHECK(offsetof(struct cdk2_efi_pci_io_protocol, attributes) == 120);
	CHECK(offsetof(struct cdk2_efi_pci_io_protocol, rom_image) == 152);
	CHECK(cdk2_ata_pci_adapter_init(&adapter, &pci, &ide, 5) == EFI_SUCCESS);
	cdk2_ata_pci_ahci_services(&adapter, &ahci);
	CHECK(ahci.allocate(ahci.context, 1024, 1024, &host, &device) == EFI_SUCCESS);
	CHECK(fixture.allocs == 1 && fixture.maps == 1 && device != 0);
	CHECK(ahci.read(ahci.context, 2, 0x38) == 0 && fixture.mem == 1);
	CHECK(ahci.release(ahci.context, host, 1024) == EFI_SUCCESS);
	CHECK(fixture.unmaps == 1 && fixture.frees == 1);
	cdk2_ata_pci_ide_services(&adapter, &ide_services);
	CHECK(ide_services.read8(ide_services.context, 0x2007) == 0 && fixture.io == 1);
	CHECK(ide_services.set_timing(ide_services.context, 1, 1) == EFI_SUCCESS);
	CHECK(fixture.timings == 1);
	CHECK(cdk2_ata_pci_adapter_release(&adapter) == EFI_SUCCESS);
	puts("ata atapi PCI adapter tests: PASS");
	return 0;
}
