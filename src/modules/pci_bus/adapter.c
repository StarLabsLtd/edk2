/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_adapter.h>

static int result(struct cdk2_pci_io_boot_adapter *adapter, EFI_STATUS status)
{
	adapter->last_status = status;
	return EFI_ERROR(status) ? -1 : 0;
}

static int access(void *context, enum cdk2_pci_io_space space, int write,
	unsigned int width, uint64_t address, size_t count, void *buffer)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	return adapter->access == NULL ? -1 : result(adapter, adapter->access(
		adapter->context, space, write, width, address, count, buffer));
}

static int delay(void *context, uint64_t ticks)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	return adapter->delay == NULL ? -1 :
		result(adapter, adapter->delay(adapter->context, ticks));
}

static int map(void *context, unsigned int operation, void *host, size_t *size,
	uint64_t *device, void **mapping)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	EFI_STATUS (*function)(void *, unsigned int, void *, size_t *, uint64_t *,
		void **) = adapter->iommu_map != NULL ? adapter->iommu_map : adapter->root_map;
	return function == NULL ? -1 : result(adapter, function(adapter->context,
		operation, host, size, device, mapping));
}

static int unmap(void *context, void *mapping)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	EFI_STATUS (*function)(void *, void *) = adapter->iommu_unmap != NULL ?
		adapter->iommu_unmap : adapter->root_unmap;
	return function == NULL ? -1 :
		result(adapter, function(adapter->context, mapping));
}

static void *allocate(void *context, size_t pages, int below_4g)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	void *buffer = NULL;
	if (adapter->allocate_pages == NULL || result(adapter,
		adapter->allocate_pages(adapter->context, pages, below_4g, &buffer)) != 0)
		return NULL;
	return buffer;
}

static int free_pages(void *context, size_t pages, void *buffer)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	return adapter->free_pages == NULL ? -1 : result(adapter,
		adapter->free_pages(adapter->context, pages, buffer));
}

static int flush(void *context)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	return adapter->flush == NULL ? 0 :
		result(adapter, adapter->flush(adapter->context));
}

static void *allocate_pool(void *context, size_t size)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	void *buffer = NULL;
	if (adapter->allocate_pool == NULL || result(adapter,
		adapter->allocate_pool(adapter->context, size, &buffer)) != 0)
		return NULL;
	return buffer;
}

static int set_bar_attributes(void *context, unsigned int bar, uint64_t offset,
	uint64_t length, uint64_t attributes)
{
	struct cdk2_pci_io_boot_adapter *adapter = context;
	return adapter->gcd_set_attributes == NULL ? -1 : result(adapter,
		adapter->gcd_set_attributes(adapter->context, bar, offset, length,
			attributes));
}

static uint64_t get_status(void *context)
{
	return ((struct cdk2_pci_io_boot_adapter *)context)->last_status;
}

void cdk2_pci_io_attach_boot_adapter(struct cdk2_pci_io_model *io,
	struct cdk2_pci_io_boot_adapter *adapter)
{
	io->backend = (struct cdk2_pci_io_backend) {
		.context = adapter, .access = access, .delay = delay, .map = map,
		.unmap = unmap, .allocate = allocate, .free = free_pages,
		.flush = flush, .allocate_pool = allocate_pool,
		.set_bar_attributes = set_bar_attributes, .status = get_status };
}

EFI_STATUS cdk2_pci_io_adapter_status(const struct cdk2_pci_io_boot_adapter *adapter)
{
	return adapter == NULL ? EFI_INVALID_PARAMETER : adapter->last_status;
}
