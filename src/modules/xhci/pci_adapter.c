/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/xhci.h>

#include <string.h>

#define PCI_WIDTH_UINT8 0U
#define PCI_WIDTH_UINT32 2U
#define PCI_ATTRIBUTE_GET 0U
#define PCI_ATTRIBUTE_SUPPORTED 1U
#define PCI_ATTRIBUTE_ENABLE 2U
#define PCI_ATTRIBUTE_SET 4U
#define PCI_DEVICE_ENABLE 0x700U
#define PCI_MAP_COMMON_BUFFER 2U

static EFI_STATUS read32(void *opaque, UINT32 offset, UINT32 *value)
{
	struct cdk2_xhci_pci_adapter *adapter = opaque;

	return adapter->pci->mem.read(adapter->pci, PCI_WIDTH_UINT32, adapter->bar,
		offset, 1U, value);
}

static EFI_STATUS write32(void *opaque, UINT32 offset, UINT32 value)
{
	struct cdk2_xhci_pci_adapter *adapter = opaque;

	return adapter->pci->mem.write(adapter->pci, PCI_WIDTH_UINT32, adapter->bar,
		offset, 1U, &value);
}

static EFI_STATUS write64(void *opaque, UINT32 offset, UINT64 value)
{
	struct cdk2_xhci_pci_adapter *adapter = opaque;
	UINT32 halves[2] = { value, value >> 32 };

	return adapter->pci->mem.write(adapter->pci, PCI_WIDTH_UINT32, adapter->bar,
		offset, 2U, halves);
}

static void delay(void *opaque, UINTN microseconds)
{
	struct cdk2_xhci_pci_adapter *adapter = opaque;

	adapter->delay(adapter->delay_context, microseconds);
}

static EFI_STATUS allocate_dma(void *opaque, UINTN size, UINTN alignment,
	struct cdk2_xhci_dma *dma)
{
	struct cdk2_xhci_pci_adapter *adapter = opaque;
	struct cdk2_xhci_pci_allocation *record = NULL;
	UINTN pages = (size + 4095U) / 4096U;
	UINTN bytes = pages * 4096U;
	EFI_STATUS status;

	if (dma == NULL || size == 0U || alignment == 0U ||
	    (alignment & (alignment - 1U)) != 0U || alignment > 4096U)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0; index < CDK2_XHCI_PCI_ALLOCATIONS; index++)
		if (adapter->allocations[index].host == NULL) {
			record = &adapter->allocations[index];
			break;
		}
	if (record == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = adapter->pci->allocate_buffer(adapter->pci, 0U, 4U, pages,
		&dma->host, 0U);
	if (EFI_ERROR(status))
		return status;
	status = adapter->pci->map(adapter->pci, PCI_MAP_COMMON_BUFFER, dma->host,
		&bytes, &dma->device, &record->mapping);
	if (EFI_ERROR(status) || bytes < size ||
	    (((UINTN)dma->host | dma->device) & (alignment - 1U)) != 0U) {
		if (!EFI_ERROR(status))
			(void)adapter->pci->unmap(adapter->pci, record->mapping);
		(void)adapter->pci->free_buffer(adapter->pci, pages, dma->host);
		memset(dma, 0, sizeof(*dma));
		memset(record, 0, sizeof(*record));
		return EFI_DEVICE_ERROR;
	}
	dma->size = size;
	record->host = dma->host;
	record->pages = pages;
	memset(dma->host, 0, bytes);
	return EFI_SUCCESS;
}

static void release_dma(void *opaque, struct cdk2_xhci_dma *dma)
{
	struct cdk2_xhci_pci_adapter *adapter = opaque;

	for (UINTN index = 0; index < CDK2_XHCI_PCI_ALLOCATIONS; index++) {
		struct cdk2_xhci_pci_allocation *record = &adapter->allocations[index];

		if (record->host != dma->host)
			continue;
		(void)adapter->pci->unmap(adapter->pci, record->mapping);
		(void)adapter->pci->free_buffer(adapter->pci, record->pages, record->host);
		memset(record, 0, sizeof(*record));
		return;
	}
}

EFI_STATUS cdk2_xhci_pci_adapter_init(struct cdk2_xhci_pci_adapter *adapter,
	struct cdk2_efi_pci_io_protocol *pci, UINT8 bar, void *delay_context,
	cdk2_xhci_delay_fn *delay_service)
{
	UINT8 class_code[3];
	UINT64 supported;
	EFI_STATUS status;

	if (adapter == NULL || pci == NULL || delay_service == NULL ||
	    pci->mem.read == NULL || pci->mem.write == NULL || pci->pci.read == NULL ||
	    pci->map == NULL || pci->unmap == NULL || pci->allocate_buffer == NULL ||
	    pci->free_buffer == NULL || pci->attributes == NULL)
		return EFI_INVALID_PARAMETER;
	status = pci->pci.read(pci, PCI_WIDTH_UINT8, 9U, 3U, class_code);
	if (EFI_ERROR(status))
		return status;
	if (class_code[2] != 0x0cU || class_code[1] != 0x03U || class_code[0] != 0x30U)
		return EFI_UNSUPPORTED;
	memset(adapter, 0, sizeof(*adapter));
	adapter->pci = pci;
	adapter->bar = bar;
	adapter->delay_context = delay_context;
	adapter->delay = delay_service;
	status = pci->attributes(pci, PCI_ATTRIBUTE_GET, 0U,
		&adapter->original_attributes);
	if (!EFI_ERROR(status))
		status = pci->attributes(pci, PCI_ATTRIBUTE_SUPPORTED, 0U, &supported);
	if (!EFI_ERROR(status) && (supported & PCI_DEVICE_ENABLE) != PCI_DEVICE_ENABLE)
		status = EFI_UNSUPPORTED;
	if (!EFI_ERROR(status))
		status = pci->attributes(pci, PCI_ATTRIBUTE_ENABLE, PCI_DEVICE_ENABLE, NULL);
	if (EFI_ERROR(status))
		return status;
	adapter->attributes_owned = TRUE;
	return EFI_SUCCESS;
}

void cdk2_xhci_pci_controller_services(struct cdk2_xhci_pci_adapter *adapter,
	struct cdk2_xhci_controller_services *services)
{
	*services = (struct cdk2_xhci_controller_services) { adapter, read32, write32,
		write64, delay, allocate_dma, release_dma };
}

EFI_STATUS cdk2_xhci_pci_adapter_release(struct cdk2_xhci_pci_adapter *adapter)
{
	EFI_STATUS status = EFI_SUCCESS;

	if (adapter == NULL || adapter->pci == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0; index < CDK2_XHCI_PCI_ALLOCATIONS; index++)
		if (adapter->allocations[index].host != NULL) {
			struct cdk2_xhci_dma dma = { .host = adapter->allocations[index].host };

			release_dma(adapter, &dma);
		}
	if (adapter->attributes_owned)
		status = adapter->pci->attributes(adapter->pci, PCI_ATTRIBUTE_SET,
			adapter->original_attributes, NULL);
	adapter->attributes_owned = FALSE;
	return status;
}
