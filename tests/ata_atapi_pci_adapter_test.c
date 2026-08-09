/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pci_adapter.h>
#include <cdk2/ata_atapi_backend.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)
typedef UINTN native_uintn_t;
typedef UINT64 native_uint64_t;
typedef BOOLEAN native_boolean_t;
typedef UINT8 native_uint8_t;
struct fixture { unsigned int allocs, frees, maps, unmaps, flushes, mem, io, timings;
	UINTN attribute_operations[4];
	unsigned int attribute_calls, pool_allocs, pool_frees, channel_calls;
};
static struct fixture fixture;
static EFI_STATUS CDK2_MS_ABI access(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{ (void)pci; (void)count; CHECK(bar < 6); CHECK(offset < 0x1000);
	fixture.mem++;
	if (width == 2U && offset == 0U)
		*(UINT32 *)buffer = 0x12345678U;
	else if (width == 2U && offset == 0x0cU)
		*(UINT32 *)buffer = 5U;
	else
		memset(buffer, 0, (size_t)1U << width);
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI config(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT32 offset, UINTN count, void *buffer)
{ UINT8 expected[3] = { 1, 6, 1 }; (void)pci; CHECK(width == 0U);
	CHECK(offset == 9 && count == 3); memcpy(buffer, expected, sizeof(expected));
	return EFI_SUCCESS; }
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
{ (void)pci; (void)value; fixture.attribute_operations[fixture.attribute_calls++] =
	operation; if (result != NULL) *result = operation == 0 ? 3 : 7;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI calculate(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, UINT8 device, void **mode)
{ (void)ide; CHECK(channel < 2 && device < 2); *mode = &fixture; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI timing(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, UINT8 device, void *mode)
{ (void)ide; (void)channel; (void)device; CHECK(mode == &fixture); fixture.timings++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI channel_info(struct cdk2_ide_init_protocol *ide,
	native_uint8_t channel, native_boolean_t *enabled, native_uint8_t *devices)
{ (void)ide; CHECK(channel < 2U); fixture.channel_calls++; *enabled = FALSE;
	*devices = 0; return EFI_SUCCESS; }
static EFI_STATUS pool_allocate(void *opaque, size_t size, void **buffer)
{ struct fixture *state = opaque; state->pool_allocs++; *buffer = calloc(1, size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void pool_release(void *opaque, void *buffer, size_t size)
{ struct fixture *state = opaque;
	const UINT8 *bytes = buffer;
	CHECK(size != 0U && bytes[0] == 0xa5U); state->pool_frees++; free(buffer); }

int main(void)
{
	struct cdk2_efi_pci_io_protocol pci = { .mem = { access, access },
		.io = { io_access, io_access }, .pci = { config, config },
		.map = pci_map, .unmap = unmap,
		.allocate_buffer = allocate, .free_buffer = release, .flush = flush,
		.attributes = pci_attributes };
	struct cdk2_ide_init_protocol ide = { .get_channel = channel_info,
		.calculate = calculate, .timing = timing };
	struct cdk2_ata_pci_adapter adapter; struct cdk2_ahci_dma_services ahci;
	struct cdk2_ide_services ide_services; void *host; UINT64 device;
	UINT8 class_code[3]; UINT32 capability, ports; UINT64 current, supported;
	struct cdk2_ata_backend_pool pool = { &fixture, pool_allocate, pool_release };
	struct cdk2_ata_controller controller = { .pci = &pci, .ide = &ide };
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
	cdk2_ata_pci_adapter_enable_timing(&adapter, 1, 1);
	CHECK(ide_services.set_timing(ide_services.context, 1, 1) == EFI_SUCCESS);
	CHECK(fixture.timings == 1);
	CHECK(cdk2_ata_pci_adapter_release(&adapter) == EFI_SUCCESS);
	CHECK(cdk2_ata_pci_read_class(&pci, class_code) == EFI_SUCCESS);
	CHECK(class_code[0] == 1 && class_code[1] == 6 && class_code[2] == 1);
	CHECK(cdk2_ata_pci_get_attributes(&pci, &current, &supported) == EFI_SUCCESS);
	CHECK(current == 3 && supported == 7);
	CHECK(cdk2_ata_pci_enable_attributes(&pci, 7) == EFI_SUCCESS);
	CHECK(cdk2_ata_pci_restore_attributes(&pci, 3) == EFI_SUCCESS);
	CHECK(fixture.attribute_operations[0] == 0 &&
		fixture.attribute_operations[1] == 1 &&
		fixture.attribute_operations[2] == 2 &&
		fixture.attribute_operations[3] == 4);
	CHECK(cdk2_ata_pci_read_ahci_capability(&pci, 5, &capability, &ports) ==
		EFI_SUCCESS);
	CHECK(capability == 0x12345678U && ports == 5U);
	controller.topology.mode = CDK2_ATA_AHCI;
	CHECK(cdk2_ata_backend_prepare(&pool, &controller) == EFI_SUCCESS);
	CHECK(controller.backend != NULL && controller.ahci != NULL);
	cdk2_ata_backend_release(&controller);
	CHECK(controller.backend == NULL && controller.ahci == NULL &&
		fixture.pool_allocs == fixture.pool_frees);
	controller.topology.mode = CDK2_ATA_IDE;
	CHECK(cdk2_ata_backend_prepare(&pool, &controller) == EFI_SUCCESS);
	CHECK(controller.ide_engine != NULL);
	CHECK(cdk2_ata_backend_discover_ide(&controller, &controller.topology) ==
		EFI_SUCCESS && controller.topology.count == 0U);
	CHECK(fixture.channel_calls == 2U);
	cdk2_ata_backend_release(&controller);
	puts("ata atapi PCI adapter tests: PASS");
	return 0;
}
