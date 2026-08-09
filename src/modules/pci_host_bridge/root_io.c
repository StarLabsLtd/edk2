/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pci_host_bridge.h>

#include <string.h>

#define PCI_ATTRIBUTE_DUAL_ADDRESS_CYCLE 0x8000U
#define PCI_ALLOCATE_VALID 0x8880U

#pragma pack(push, 1)
struct address_descriptor {
	uint8_t descriptor;
	uint16_t length;
	uint8_t type, general, specific;
	uint64_t granularity, minimum, maximum, translation, address_length;
};
struct end_descriptor { uint8_t descriptor, checksum; };
struct pci_address {
	uint8_t reg, function, device, bus;
	uint32_t extended;
};
#pragma pack(pop)

struct dma_mapping {
	struct dma_mapping *next;
	void *host;
	void *bounce;
	size_t bytes, pages, operation;
};

typedef char root_io_segment_offset_check[
	offsetof(struct cdk2_pci_root_io, segment) == 144 ? 1 : -1];

static size_t width_bytes(size_t width)
{
	return width >= CDK2_PCI_WIDTH_MAX ? 0 : (size_t)1U << (width & 3U);
}

static uint64_t checked_end(uint64_t address, size_t width, size_t count,
	uint64_t *end)
{
	size_t bytes = width_bytes(width);
	size_t elements;

	if (bytes == 0 || count == 0 || end == NULL || (address & (bytes - 1U)) != 0)
		return EFI_INVALID_PARAMETER;
	elements = width >= CDK2_PCI_FIFO8 && width <= CDK2_PCI_FIFO64 ? 1 : count;
	if (elements > UINT64_MAX / bytes || address > UINT64_MAX - elements * bytes)
		return EFI_INVALID_PARAMETER;
	*end = address + elements * bytes - 1U;
	return EFI_SUCCESS;
}

static uint64_t translate(const struct cdk2_pci_root_io *io, uint8_t memory,
	size_t width, uint64_t address, size_t count, uint64_t *host)
{
	uint64_t end;
	size_t first = memory ? 2 : 1, last = memory ? 6 : 2, index;

	if (checked_end(address, width, count, &end) != EFI_SUCCESS || host == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = first; index < last; index++) {
		const struct cdk2_pci_aperture *aperture = &io->root.aperture[index];

		if (aperture->base <= aperture->limit && address >= aperture->base &&
		    end <= aperture->limit) {
			*host = address - aperture->translation;
			return EFI_SUCCESS;
		}
	}
	return EFI_INVALID_PARAMETER;
}

static uint64_t access(struct cdk2_pci_root_io *io, uint8_t memory,
	uint8_t write, size_t width, uint64_t address, size_t count, void *buffer)
{
	cdk2_pci_io_fn *function;
	uint64_t host;

	if (io == NULL || buffer == NULL ||
	    translate(io, memory, width, address, count, &host) != EFI_SUCCESS)
		return EFI_INVALID_PARAMETER;
	function = memory ? (write ? io->services.mem_write : io->services.mem_read) :
		(write ? io->services.io_write : io->services.io_read);
	return function == NULL ? EFI_UNSUPPORTED :
		function(io->services.cpu, width, host, count, buffer);
}

static uint64_t CDK2_MS_ABI mem_read(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, size_t count, void *buffer)
{ return access(io, 1, 0, width, address, count, buffer); }
static uint64_t CDK2_MS_ABI mem_write(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, size_t count, void *buffer)
{ return access(io, 1, 1, width, address, count, buffer); }
static uint64_t CDK2_MS_ABI io_read(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, size_t count, void *buffer)
{ return access(io, 0, 0, width, address, count, buffer); }
static uint64_t CDK2_MS_ABI io_write(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, size_t count, void *buffer)
{ return access(io, 0, 1, width, address, count, buffer); }

static uint64_t poll(struct cdk2_pci_root_io *io, uint8_t memory, size_t width,
	uint64_t address, uint64_t mask, uint64_t value, uint64_t delay,
	uint64_t *result)
{
	uint64_t status;
	size_t bytes = width_bytes(width);

	if (io == NULL || result == NULL || width > CDK2_PCI_UINT64)
		return EFI_INVALID_PARAMETER;
	for (;;) {
		*result = 0;
		status = access(io, memory, 0, width, address, 1, result);
		if (status != EFI_SUCCESS || (*result & mask) == value)
			return status;
		if (delay < 10)
			return EFI_TIMEOUT;
		if (io->services.stall == NULL)
			return EFI_UNSUPPORTED;
		status = io->services.stall(1);
		if (status != EFI_SUCCESS)
			return status;
		delay -= 10;
		(void)bytes;
	}
}

static uint64_t CDK2_MS_ABI poll_mem(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, uint64_t mask, uint64_t value, uint64_t delay,
	uint64_t *result)
{ return poll(io, 1, width, address, mask, value, delay, result); }
static uint64_t CDK2_MS_ABI poll_io(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, uint64_t mask, uint64_t value, uint64_t delay,
	uint64_t *result)
{ return poll(io, 0, width, address, mask, value, delay, result); }

static uint64_t CDK2_MS_ABI copy_mem(struct cdk2_pci_root_io *io, size_t width,
	uint64_t destination, uint64_t source, size_t count)
{
	uint64_t value, status;
	uint64_t source_end, destination_end;
	size_t bytes = width_bytes(width), index;

	if (io == NULL || width > CDK2_PCI_UINT64 || bytes == 0)
		return EFI_INVALID_PARAMETER;
	if (checked_end(source, width, count, &source_end) != EFI_SUCCESS ||
	    checked_end(destination, width, count, &destination_end) != EFI_SUCCESS)
		return EFI_INVALID_PARAMETER;
	(void)destination_end;
	for (index = 0; index < count; index++) {
		size_t offset = destination > source && destination <= source_end ?
			(count - index - 1U) * bytes : index * bytes;
		status = mem_read(io, width, source + offset, 1, &value);
		if (status != EFI_SUCCESS)
			return status;
		status = mem_write(io, width, destination + offset, 1, &value);
		if (status != EFI_SUCCESS)
			return status;
	}
	return EFI_SUCCESS;
}

static uint64_t pci_parameters(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, size_t count, uint64_t *register_offset)
{
	struct pci_address encoded;
	uint64_t end;

	memcpy(&encoded, &address, sizeof(encoded));
	if (io == NULL || width_bytes(width) == 0 || encoded.device > 31 ||
	    encoded.function > 7 || encoded.bus < io->root.aperture[0].base ||
	    encoded.bus > io->root.aperture[0].limit)
		return EFI_INVALID_PARAMETER;
	*register_offset = encoded.extended != 0 ? encoded.extended : encoded.reg;
	if (checked_end(*register_offset, width, count, &end) != EFI_SUCCESS ||
	    end > (io->root.no_extended_config ? 0xffU : 0xfffU))
		return EFI_UNSUPPORTED;
	*register_offset |= (uint64_t)encoded.bus << 20 |
		(uint64_t)encoded.device << 15 | (uint64_t)encoded.function << 12;
	return EFI_SUCCESS;
}

static uint64_t pci_access(struct cdk2_pci_root_io *io, uint8_t write,
	size_t width, uint64_t address, size_t count, void *buffer)
{
	uint64_t offset, status;
	size_t index, bytes = width_bytes(width);

	if (buffer == NULL)
		return EFI_INVALID_PARAMETER;
	status = pci_parameters(io, width, address, count, &offset);
	if (status != EFI_SUCCESS)
		return status;
	if (!io->root.no_extended_config) {
		cdk2_pci_io_fn *fn = write ? io->services.mem_write : io->services.mem_read;
		return fn == NULL ? EFI_UNSUPPORTED : fn(io->services.cpu, width,
			io->ecam_base + offset, count, buffer);
	}
	if (io->services.io_write == NULL || io->services.io_read == NULL)
		return EFI_UNSUPPORTED;
	for (index = 0; index < count; index++) {
		size_t address_index = width >= CDK2_PCI_FIFO8 &&
			width <= CDK2_PCI_FIFO64 ? 0 : index;
		size_t buffer_index = width >= CDK2_PCI_FILL8 ? 0 : index;
		uint32_t cf8 = 0x80000000U | ((uint32_t)(offset >> 12) << 8) |
			(uint32_t)((offset + address_index * bytes) & 0xfcU);
		status = io->services.io_write(io->services.cpu, CDK2_PCI_UINT32,
			0xcf8, 1, &cf8);
		if (status != EFI_SUCCESS)
			return status;
		status = (write ? io->services.io_write : io->services.io_read)(
			io->services.cpu, width & 3U,
			0xcfc + ((offset + address_index * bytes) & 3U), 1,
			(uint8_t *)buffer + buffer_index * bytes);
		if (status != EFI_SUCCESS)
			return status;
	}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI pci_read(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, size_t count, void *buffer)
{ return pci_access(io, 0, width, address, count, buffer); }
static uint64_t CDK2_MS_ABI pci_write(struct cdk2_pci_root_io *io, size_t width,
	uint64_t address, size_t count, void *buffer)
{ return pci_access(io, 1, width, address, count, buffer); }

static uint64_t CDK2_MS_ABI dma_map(struct cdk2_pci_root_io *io, size_t operation,
	void *host, size_t *bytes, uint64_t *device, void **mapping)
{
	struct dma_mapping *record;
	uint64_t end, address = UINT32_MAX;
	uint64_t status;

	if (io == NULL || operation >= CDK2_PCI_DMA_MAX || host == NULL ||
	    bytes == NULL || device == NULL || mapping == NULL)
		return EFI_INVALID_PARAMETER;
	if (io->services.iommu != NULL)
		return io->services.iommu_map == NULL ? EFI_UNSUPPORTED :
			io->services.iommu_map(io->services.iommu,
				!io->root.dma_above_4g && operation >= CDK2_PCI_DMA_READ64 ?
				operation - CDK2_PCI_DMA_READ64 : operation, host, bytes,
				device, mapping);
	if (*bytes == 0) {
		*device = (uint64_t)(uintptr_t)host;
		*mapping = NULL;
		return EFI_SUCCESS;
	}
	if ((uint64_t)(uintptr_t)host > UINT64_MAX - (*bytes - 1U))
		return EFI_INVALID_PARAMETER;
	end = (uint64_t)(uintptr_t)host + *bytes - 1U;
	if ((!io->root.dma_above_4g || operation < CDK2_PCI_DMA_READ64) &&
	    end > UINT32_MAX) {
		if (operation == CDK2_PCI_DMA_COMMON ||
		    operation == CDK2_PCI_DMA_COMMON64)
			return EFI_UNSUPPORTED;
		if (io->services.allocate_pool == NULL || io->services.free_pool == NULL ||
		    io->services.allocate_pages == NULL || io->services.free_pages == NULL)
			return EFI_OUT_OF_RESOURCES;
		status = io->services.allocate_pool(4U, sizeof(*record),
			(void **)&record);
		if (status != EFI_SUCCESS) {
			*bytes = 0;
			return status;
		}
		record->pages = (*bytes + 4095U) / 4096U;
		status = io->services.allocate_pages(1U, 4U, record->pages, &address);
		if (status != EFI_SUCCESS) {
			(void)io->services.free_pool(record);
			*bytes = 0;
			return status;
		}
		record->host = host;
		record->bounce = (void *)(uintptr_t)address;
		record->bytes = *bytes;
		record->operation = operation;
		if (operation == CDK2_PCI_DMA_READ || operation == CDK2_PCI_DMA_READ64)
			memcpy(record->bounce, host, *bytes);
		record->next = io->mappings;
		io->mappings = record;
		*device = address;
		*mapping = record;
		return EFI_SUCCESS;
	}
	*device = (uint64_t)(uintptr_t)host;
	*mapping = NULL;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI dma_unmap(struct cdk2_pci_root_io *io, void *mapping)
{
	struct dma_mapping *record = mapping;
	struct dma_mapping **link;
	uint64_t status;

	if (io == NULL)
		return EFI_INVALID_PARAMETER;
	if (io->services.iommu != NULL)
		return io->services.iommu_unmap == NULL ? EFI_UNSUPPORTED :
			io->services.iommu_unmap(io->services.iommu, mapping);
	if (mapping == NULL)
		return EFI_SUCCESS;
	if (io->services.free_pages == NULL || io->services.free_pool == NULL)
		return EFI_INVALID_PARAMETER;
	for (link = (struct dma_mapping **)&io->mappings; *link != NULL;
	     link = &(*link)->next)
		if (*link == record)
			break;
	if (*link == NULL)
		return EFI_INVALID_PARAMETER;
	if (record->operation == CDK2_PCI_DMA_WRITE ||
	    record->operation == CDK2_PCI_DMA_WRITE64)
		memcpy(record->host, record->bounce, record->bytes);
	status = io->services.free_pages((uint64_t)(uintptr_t)record->bounce,
		record->pages);
	if (status != EFI_SUCCESS)
		return status;
	*link = record->next;
	return io->services.free_pool(record);
}

static uint64_t CDK2_MS_ABI allocate_buffer(struct cdk2_pci_root_io *io,
	uint32_t type, uint32_t memory_type, size_t pages, void **host,
	uint64_t attributes)
{
	uint64_t address, status;

	if (io == NULL || host == NULL || pages == 0 ||
	    (memory_type != 4U && memory_type != 6U))
		return EFI_INVALID_PARAMETER;
	if ((attributes & ~PCI_ALLOCATE_VALID) != 0)
		return EFI_UNSUPPORTED;
	if (io->services.iommu != NULL)
		return io->services.iommu_allocate == NULL ? EFI_UNSUPPORTED :
			io->services.iommu_allocate(io->services.iommu, type, memory_type,
				pages, host, io->root.dma_above_4g ? attributes :
				attributes & ~PCI_ATTRIBUTE_DUAL_ADDRESS_CYCLE);
	if (io->services.allocate_pages == NULL)
		return EFI_UNSUPPORTED;
	if (!io->root.dma_above_4g) {
		type = 1;
		address = UINT32_MAX;
	} else {
		address = 0;
	}
	status = io->services.allocate_pages(type, memory_type, pages, &address);
	if (status == EFI_SUCCESS)
		*host = (void *)(uintptr_t)address;
	return status;
}

static uint64_t CDK2_MS_ABI free_buffer(struct cdk2_pci_root_io *io,
	size_t pages, void *host)
{
	if (io == NULL || pages == 0 || host == NULL)
		return EFI_INVALID_PARAMETER;
	if (io->services.iommu != NULL)
		return io->services.iommu_free == NULL ? EFI_UNSUPPORTED :
			io->services.iommu_free(io->services.iommu, pages, host);
	return io->services.free_pages == NULL ? EFI_UNSUPPORTED :
		io->services.free_pages((uint64_t)(uintptr_t)host, pages);
}

static uint64_t CDK2_MS_ABI flush(struct cdk2_pci_root_io *io)
{ return io == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS; }

static uint64_t CDK2_MS_ABI get_attributes(struct cdk2_pci_root_io *io,
	uint64_t *supports, uint64_t *attributes)
{
	if (io == NULL || (supports == NULL && attributes == NULL))
		return EFI_INVALID_PARAMETER;
	if (supports != NULL)
		*supports = io->root.supports;
	if (attributes != NULL)
		*attributes = io->current_attributes;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI set_attributes(struct cdk2_pci_root_io *io,
	uint64_t attributes, uint64_t *base, uint64_t *length)
{
	if (io == NULL || (attributes & ~io->root.supports) != 0)
		return EFI_UNSUPPORTED;
	(void)base;
	(void)length;
	io->current_attributes = attributes;
	return EFI_SUCCESS;
}

static void build_configuration(struct cdk2_pci_root_io *io);

static uint64_t CDK2_MS_ABI configuration(struct cdk2_pci_root_io *io,
	void **resources)
{
	if (io == NULL || resources == NULL)
		return EFI_INVALID_PARAMETER;
	build_configuration(io);
	*resources = io->configuration_data;
	return EFI_SUCCESS;
}

static void build_configuration(struct cdk2_pci_root_io *io)
{
	struct address_descriptor *resource = (void *)io->configuration_data;
	size_t index, count = 0;

	memset(io->configuration_data, 0, sizeof(io->configuration_data));
	for (index = 0; index < CDK2_PCI_ROOT_BRIDGE_APERTURES; index++) {
		const struct cdk2_pci_aperture *aperture = &io->root.aperture[index];

		if (!io->resource_assigned[index])
			continue;
		resource[count].descriptor = 0x8a;
		resource[count].length = sizeof(*resource) - 3U;
		resource[count].type = index == 0 ? 2 : index == 1 ? 1 : 0;
		resource[count].granularity = index < 2 ? 0 : index < 4 ? 32 : 64;
		resource[count].specific = index == 4 || index == 5 ? 0x06 : 0;
		resource[count].minimum = io->resource_base[index];
		resource[count].maximum = io->resource_base[index] +
			io->resource_length[index] - 1U;
		resource[count].translation = aperture->translation;
		resource[count].address_length = io->resource_length[index];
		count++;
	}
	((struct end_descriptor *)(resource + count))->descriptor = 0x79;
}

uint64_t cdk2_pci_root_io_init(struct cdk2_pci_root_io *io,
	const struct cdk2_pci_root_bridge_view *root, uint64_t ecam_base,
	const struct cdk2_pci_root_io_services *services, void *parent_handle,
	uint8_t resource_assigned)
{
	size_t index;

	if (io == NULL || root == NULL || services == NULL || parent_handle == NULL ||
	    services->mem_read == NULL || services->mem_write == NULL ||
	    services->io_read == NULL || services->io_write == NULL ||
	    (root->no_extended_config == 0 && ecam_base == 0) || resource_assigned > 1U)
		return EFI_INVALID_PARAMETER;
	memset(io, 0, sizeof(*io));
	io->parent_handle = parent_handle;
	io->poll_mem = poll_mem;
	io->poll_io = poll_io;
	io->mem.read = mem_read; io->mem.write = mem_write;
	io->io.read = io_read; io->io.write = io_write;
	io->pci.read = pci_read; io->pci.write = pci_write;
	io->copy_mem = copy_mem;
	io->map = dma_map; io->unmap = dma_unmap;
	io->allocate_buffer = allocate_buffer; io->free_buffer = free_buffer;
	io->flush = flush;
	io->get_attributes = get_attributes; io->set_attributes = set_attributes;
	io->configuration = configuration;
	io->segment = root->segment;
	io->root = *root;
	io->services = *services;
	io->ecam_base = ecam_base;
	io->current_attributes = root->attributes;
	if (resource_assigned)
		for (index = 0; index < CDK2_PCI_ROOT_BRIDGE_APERTURES; index++)
			if (root->aperture[index].base <= root->aperture[index].limit) {
				io->resource_base[index] = root->aperture[index].base -
					root->aperture[index].translation;
				io->resource_length[index] = root->aperture[index].limit -
					root->aperture[index].base + 1U;
				io->resource_assigned[index] = 1;
			}
	build_configuration(io);
	return EFI_SUCCESS;
}

uint64_t cdk2_pci_root_io_set_resource(struct cdk2_pci_root_io *io,
	size_t aperture, uint64_t device_base, uint64_t length, uint8_t assigned)
{
	if (io == NULL || aperture >= CDK2_PCI_ROOT_BRIDGE_APERTURES || assigned > 1U ||
	    (assigned && length == 0))
		return EFI_INVALID_PARAMETER;
	io->resource_assigned[aperture] = assigned;
	io->resource_base[aperture] = assigned ?
		device_base - io->root.aperture[aperture].translation : 0;
	io->resource_length[aperture] = assigned ? length : 0;
	return EFI_SUCCESS;
}
