/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t cf8;
static uint8_t config[4096], bounce[4096];
static unsigned int page_frees, pool_frees, stalls;
static size_t iommu_operation;
static unsigned int iommu_maps, iommu_unmaps;

static uint64_t CDK2_MS_ABI memory_read(void *cpu, size_t width,
	uint64_t address, size_t count, void *buffer)
{
	(void)cpu;
	memcpy(buffer, (void *)(uintptr_t)address, count << (width & 3U));
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI memory_write(void *cpu, size_t width,
	uint64_t address, size_t count, void *buffer)
{
	(void)cpu;
	memcpy((void *)(uintptr_t)address, buffer, count << (width & 3U));
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI port_read(void *cpu, size_t width,
	uint64_t address, size_t count, void *buffer)
{
	(void)cpu;
	if (address < 0xcfc || address > 0xcff || count != 1)
		return EFI_DEVICE_ERROR;
	memcpy(buffer, config + (cf8 & 0xfffU) + address - 0xcfc,
		(size_t)1U << (width & 3U));
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI port_write(void *cpu, size_t width,
	uint64_t address, size_t count, void *buffer)
{
	(void)cpu;
	if (address == 0xcf8 && width == CDK2_PCI_UINT32 && count == 1) {
		memcpy(&cf8, buffer, sizeof(cf8));
		return EFI_SUCCESS;
	}
	if (address < 0xcfc || address > 0xcff || count != 1)
		return EFI_DEVICE_ERROR;
	memcpy(config + (cf8 & 0xfffU) + address - 0xcfc, buffer,
		(size_t)1U << (width & 3U));
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI stall(size_t microseconds)
{
	stalls += microseconds;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI allocate_pages(uint32_t type, uint32_t memory,
	size_t pages, uint64_t *address)
{
	(void)memory;
	if (type != 1 || pages != 1 || *address != UINT32_MAX)
		return EFI_INVALID_PARAMETER;
	*address = (uint64_t)(uintptr_t)bounce;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI free_pages(uint64_t address, size_t pages)
{
	if (address != (uint64_t)(uintptr_t)bounce || pages != 1)
		return EFI_INVALID_PARAMETER;
	page_frees++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI allocate_pool(uint32_t type, size_t size,
	void **buffer)
{
	(void)type;
	*buffer = calloc(1, size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI free_pool(void *buffer)
{
	pool_frees++;
	free(buffer);
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI iommu_map(void *self, size_t operation, void *host,
	size_t *bytes, uint64_t *device, void **mapping)
{
	(void)self; (void)bytes;
	iommu_operation = operation;
	iommu_maps++;
	*device = (uint64_t)(uintptr_t)host + 0x1000;
	*mapping = host;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI iommu_unmap(void *self, void *mapping)
{
	(void)self; (void)mapping;
	iommu_unmaps++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "pci root io test: %s\n", message);
	return condition ? 0 : 1;
}

static uint64_t read64(const void *value)
{
	uint64_t result;

	memcpy(&result, value, sizeof(result));
	return result;
}

int main(void)
{
	struct cdk2_pci_root_bridge_view root;
	struct cdk2_pci_root_io_services services;
	struct cdk2_pci_root_io io;
	uint8_t memory[32] = { 1, 2, 3, 4 };
	uint8_t host[8] = { 9, 8, 7, 6 }, value = 0;
	uint64_t result, device, attributes, supports, pci_address = 0;
	size_t bytes;
	void *mapping, *resources;
	void *allocated;
	int failures = 0;

	memset(&root, 0, sizeof(root));
	root.no_extended_config = 1;
	root.aperture[0].limit = 0xff;
	root.aperture[1].limit = 0xffff;
	root.aperture[2].base = (uint64_t)(uintptr_t)memory;
	root.aperture[2].limit = root.aperture[2].base + sizeof(memory) - 1U;
	root.aperture[3].base = 1; root.aperture[3].limit = 0;
	root.aperture[4].base = 1; root.aperture[4].limit = 0;
	root.aperture[5].base = 1; root.aperture[5].limit = 0;
	root.supports = 0x8000;
	root.attributes = 0x8000;
	memset(&services, 0, sizeof(services));
	services.mem_read = memory_read; services.mem_write = memory_write;
	services.io_read = port_read; services.io_write = port_write;
	services.stall = stall;
	services.allocate_pages = allocate_pages; services.free_pages = free_pages;
	services.allocate_pool = allocate_pool; services.free_pool = free_pool;
	failures += expect(cdk2_pci_root_io_init(&io, &root, 0, &services,
		(void *)0x44, 1) == EFI_SUCCESS, "valid root did not initialize");
	failures += expect(io.mem.read(&io, CDK2_PCI_UINT8,
		(uint64_t)(uintptr_t)memory, 1, &value) == EFI_SUCCESS && value == 1,
		"memory aperture read failed");
	failures += expect(io.mem.read(&io, CDK2_PCI_UINT32,
		(uint64_t)(uintptr_t)memory + sizeof(memory) - 1U, 1, &result) ==
		EFI_INVALID_PARAMETER, "cross-aperture access was accepted");
	failures += expect(io.copy_mem(&io, CDK2_PCI_UINT8,
		(uint64_t)(uintptr_t)memory + 1, (uint64_t)(uintptr_t)memory, 4) ==
		EFI_SUCCESS && memory[1] == 1 && memory[4] == 4,
		"overlapping CopyMem corrupted data");
	root.aperture[2].translation = 0x1000;
	root.aperture[2].base = (uint64_t)(uintptr_t)memory + 0x1000;
	root.aperture[2].limit = root.aperture[2].base + sizeof(memory) - 1U;
	failures += expect(cdk2_pci_root_io_init(&io, &root, 0, &services,
		(void *)0x44, 1) == EFI_SUCCESS && io.mem.read(&io, CDK2_PCI_UINT8,
		root.aperture[2].base, 1, &value) == EFI_SUCCESS && value == 1 &&
		io.configuration(&io, &resources) == EFI_SUCCESS &&
		read64((uint8_t *)resources + 2U * 46U + 14U) ==
			(uint64_t)(uintptr_t)memory,
		"device-to-host translation/configuration view was incorrect");
	root.aperture[2].translation = 0;
	root.aperture[2].base = (uint64_t)(uintptr_t)memory;
	root.aperture[2].limit = root.aperture[2].base + sizeof(memory) - 1U;
	failures += expect(cdk2_pci_root_io_init(&io, &root, 0, &services,
		(void *)0x44, 1) == EFI_SUCCESS, "root restore failed");
	config[0x10] = 0xa5;
	((uint8_t *)&pci_address)[0] = 0x10;
	failures += expect(io.pci.read(&io, CDK2_PCI_UINT8, pci_address, 1, &value) ==
		EFI_SUCCESS && value == 0xa5 && (cf8 & 0x80000000U) != 0,
		"CF8/CFC config read failed");
	root.no_extended_config = 0;
	config[0x110] = 0x3c;
	((uint32_t *)&pci_address)[1] = 0x110;
	failures += expect(cdk2_pci_root_io_init(&io, &root,
		(uint64_t)(uintptr_t)config, &services, (void *)0x44, 1) == EFI_SUCCESS &&
		io.pci.read(&io, CDK2_PCI_UINT8, pci_address, 1, &value) == EFI_SUCCESS &&
		value == 0x3c, "segment-zero ECAM extended config read failed");
	bytes = sizeof(host); mapping = NULL;
	failures += expect(io.map(&io, CDK2_PCI_DMA_READ, host, &bytes, &device,
		&mapping) == EFI_SUCCESS && mapping != NULL &&
		memcmp(bounce, host, bytes) == 0 && io.unmap(&io, mapping) == EFI_SUCCESS,
		"read bounce mapping did not copy and release");
	bytes = sizeof(host); mapping = NULL;
	failures += expect(io.map(&io, CDK2_PCI_DMA_WRITE, host, &bytes, &device,
		&mapping) == EFI_SUCCESS && mapping != NULL, "write bounce map failed");
	memset(bounce, 0x5a, bytes);
	failures += expect(io.unmap(&io, mapping) == EFI_SUCCESS && host[0] == 0x5a &&
		page_frees == 2 && pool_frees == 2,
		"write bounce unmap did not copy back and release");
	failures += expect(io.get_attributes(&io, &supports, &attributes) == EFI_SUCCESS &&
		supports == 0x8000 && attributes == 0x8000 &&
		io.set_attributes(&io, 1, NULL, NULL) == EFI_UNSUPPORTED,
		"attribute policy failed");
	failures += expect(io.configuration(&io, &resources) == EFI_SUCCESS &&
		*(uint8_t *)resources == 0x8a, "configuration descriptors absent");
	allocated = NULL;
	failures += expect(io.allocate_buffer(&io, 0, 4, 1, &allocated, 0x8000) ==
		EFI_SUCCESS && allocated == bounce,
		"non-DMA64 root did not force DAC buffer below 4G");
	failures += expect(io.poll_mem(&io, CDK2_PCI_UINT8,
		(uint64_t)(uintptr_t)memory, 0xff, 0xee, 10, &result) == EFI_TIMEOUT &&
		stalls == 1, "poll timeout semantics failed");
	services.iommu = (void *)0x88;
	services.iommu_map = iommu_map;
	services.iommu_unmap = iommu_unmap;
	root.no_extended_config = 1;
	failures += expect(cdk2_pci_root_io_init(&io, &root, 0, &services,
		(void *)0x44, 1) == EFI_SUCCESS, "IOMMU root did not initialize");
	bytes = sizeof(host); mapping = NULL;
	failures += expect(io.map(&io, CDK2_PCI_DMA_READ64, host, &bytes, &device,
		&mapping) == EFI_SUCCESS && iommu_maps == 1 &&
		iommu_operation == CDK2_PCI_DMA_READ && io.unmap(&io, mapping) ==
		EFI_SUCCESS && iommu_unmaps == 1,
		"IOMMU delegation did not downgrade unsupported 64-bit DMA");
	return failures == 0 ? 0 : 1;
}
