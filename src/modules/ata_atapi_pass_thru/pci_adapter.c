/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pci_adapter.h>

#include <string.h>

#define EFI_PCI_IO_WIDTH_UINT8 0U
#define EFI_PCI_IO_WIDTH_UINT16 1U
#define EFI_PCI_IO_WIDTH_UINT32 2U
#define EFI_PCI_IO_ATTRIBUTE_OPERATION_SET 4U
#define EFI_PCI_IO_ATTRIBUTE_OPERATION_GET 0U
#define EFI_PCI_IO_ATTRIBUTE_OPERATION_SUPPORTED 1U
#define EFI_PCI_IO_ATTRIBUTE_OPERATION_ENABLE 2U
#define EFI_PCI_IO_MAP_COMMON_BUFFER 2U

static struct cdk2_ata_adapter_allocation *find_allocation(
	struct cdk2_ata_pci_adapter *adapter, void *host)
{
	for (UINTN index = 0; index < CDK2_ATA_ADAPTER_ALLOCATIONS; index++)
		if (adapter->allocations[index].host == host)
			return &adapter->allocations[index];
	return NULL;
}

static EFI_STATUS dma_allocate(void *opaque, size_t size, size_t alignment,
	void **host, UINT64 *device)
{
	struct cdk2_ata_pci_adapter *adapter = opaque;
	struct cdk2_ata_adapter_allocation *record = NULL;
	UINTN pages = (size + 4095U) / 4096U, bytes = pages * 4096U;
	EFI_STATUS status;
	if (alignment > 4096U || host == NULL || device == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0; index < CDK2_ATA_ADAPTER_ALLOCATIONS; index++)
		if (adapter->allocations[index].host == NULL) {
			record = &adapter->allocations[index];
			break;
		}
	if (record == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = adapter->pci->allocate_buffer(adapter->pci, 0U, 4U, pages, host, 0U);
	if (EFI_ERROR(status))
		return status;
	status = adapter->pci->map(adapter->pci, EFI_PCI_IO_MAP_COMMON_BUFFER, *host,
		&bytes, device, &record->mapping);
	if (EFI_ERROR(status) || bytes < size || ((*device | (UINT64)(uintptr_t)*host) &
	    (alignment - 1U)) != 0U) {
		if (!EFI_ERROR(status))
			(void)adapter->pci->unmap(adapter->pci, record->mapping);
		(void)adapter->pci->free_buffer(adapter->pci, pages, *host);
		memset(record, 0, sizeof(*record));
		return EFI_DEVICE_ERROR;
	}
	record->host = *host; record->pages = pages;
	return EFI_SUCCESS;
}

static EFI_STATUS dma_release(void *opaque, void *host, size_t size)
{
	struct cdk2_ata_pci_adapter *adapter = opaque;
	struct cdk2_ata_adapter_allocation *record = find_allocation(adapter, host);
	EFI_STATUS first = EFI_SUCCESS, status; (void)size;
	if (record == NULL)
		return EFI_NOT_FOUND;
	status = adapter->pci->unmap(adapter->pci, record->mapping);
	if (EFI_ERROR(status))
		first = status;
	status = adapter->pci->free_buffer(adapter->pci, record->pages, record->host);
	if (EFI_ERROR(status) && !EFI_ERROR(first))
		first = status;
	memset(record, 0, sizeof(*record));
	return first;
}

static EFI_STATUS dma_map(void *opaque, enum cdk2_ahci_dma_operation operation,
	void *host, size_t *size, UINT64 *device, void **mapping)
{
	struct cdk2_ata_pci_adapter *adapter = opaque; UINTN bytes = *size;
	EFI_STATUS status = adapter->pci->map(adapter->pci, operation ==
		CDK2_AHCI_BUS_MASTER_READ ? 0U : 1U, host, &bytes, device, mapping);
	*size = bytes;
	return status;
}
static EFI_STATUS dma_unmap(void *opaque, void *mapping)
{ struct cdk2_ata_pci_adapter *adapter = opaque;
	return adapter->pci->unmap(adapter->pci, mapping); }
static EFI_STATUS dma_flush(void *opaque)
{ struct cdk2_ata_pci_adapter *adapter = opaque; return adapter->pci->flush(adapter->pci); }
static UINT32 ahci_read(void *opaque, UINT16 port, UINT16 offset)
{
	struct cdk2_ata_pci_adapter *adapter = opaque; UINT32 value = 0xffffffffU;
	UINT64 address = port == 0xffffU ? offset : 0x100U + port * 0x80U + offset;
	(void)adapter->pci->mem.read(adapter->pci, EFI_PCI_IO_WIDTH_UINT32,
		adapter->ahci_bar, address, 1, &value);
	return value;
}
static EFI_STATUS ahci_write(void *opaque, UINT16 port, UINT16 offset, UINT32 value)
{
	struct cdk2_ata_pci_adapter *adapter = opaque;
	UINT64 address = port == 0xffffU ? offset : 0x100U + port * 0x80U + offset;
	return adapter->pci->mem.write(adapter->pci, EFI_PCI_IO_WIDTH_UINT32,
		adapter->ahci_bar, address, 1, &value);
}
static UINT64 adapter_time(void *opaque)
{ return ((struct cdk2_ata_pci_adapter *)opaque)->ticks++; }
static void adapter_delay(void *opaque, UINTN microseconds)
{ ((struct cdk2_ata_pci_adapter *)opaque)->ticks += microseconds; }

static void decode_port(UINT16 encoded, UINT8 *bar, UINT64 *offset)
{ *bar = (UINT8)(encoded >> 12); *offset = encoded & 0x0fffU; }
static UINT8 ide_read8(void *opaque, UINT16 port)
{ struct cdk2_ata_pci_adapter *adapter = opaque; UINT8 bar, value = 0xff; UINT64 offset;
	decode_port(port, &bar, &offset); (void)adapter->pci->io.read(adapter->pci,
		EFI_PCI_IO_WIDTH_UINT8, bar, offset, 1, &value); return value; }
static UINT16 ide_read16(void *opaque, UINT16 port)
{ struct cdk2_ata_pci_adapter *adapter = opaque; UINT8 bar; UINT16 value = 0xffff;
	UINT64 offset; decode_port(port, &bar, &offset); (void)adapter->pci->io.read(adapter->pci,
		EFI_PCI_IO_WIDTH_UINT16, bar, offset, 1, &value); return value; }
static EFI_STATUS ide_write8(void *opaque, UINT16 port, UINT8 value)
{ struct cdk2_ata_pci_adapter *adapter = opaque; UINT8 bar; UINT64 offset;
	decode_port(port, &bar, &offset); return adapter->pci->io.write(adapter->pci,
		EFI_PCI_IO_WIDTH_UINT8, bar, offset, 1, &value); }
static EFI_STATUS ide_write16(void *opaque, UINT16 port, UINT16 value)
{ struct cdk2_ata_pci_adapter *adapter = opaque; UINT8 bar; UINT64 offset;
	decode_port(port, &bar, &offset); return adapter->pci->io.write(adapter->pci,
		EFI_PCI_IO_WIDTH_UINT16, bar, offset, 1, &value); }
static EFI_STATUS ide_write32(void *opaque, UINT16 port, UINT32 value)
{ struct cdk2_ata_pci_adapter *adapter = opaque; UINT8 bar; UINT64 offset;
	decode_port(port, &bar, &offset); return adapter->pci->io.write(adapter->pci,
		EFI_PCI_IO_WIDTH_UINT32, bar, offset, 1, &value); }
static EFI_STATUS ide_timing(void *opaque, UINT8 channel, UINT8 device)
{
	struct cdk2_ata_pci_adapter *adapter = opaque; void *mode = NULL; EFI_STATUS status;
	status = adapter->ide->calculate(adapter->ide, channel, device, &mode);
	return EFI_ERROR(status) ? status : adapter->ide->timing(adapter->ide,
		channel, device, mode);
}

EFI_STATUS cdk2_ata_pci_adapter_init(struct cdk2_ata_pci_adapter *adapter,
	struct cdk2_efi_pci_io_protocol *pci, struct cdk2_ide_init_protocol *ide,
	UINT8 ahci_bar)
{
	if (adapter == NULL || pci == NULL || ide == NULL || ahci_bar >= 6U ||
	    pci->mem.read == NULL || pci->mem.write == NULL || pci->io.read == NULL ||
	    pci->io.write == NULL || pci->map == NULL || pci->unmap == NULL ||
	    pci->allocate_buffer == NULL || pci->free_buffer == NULL || pci->flush == NULL ||
	    pci->attributes == NULL || ide->calculate == NULL || ide->timing == NULL)
		return EFI_INVALID_PARAMETER;
	memset(adapter, 0, sizeof(*adapter)); adapter->pci = pci; adapter->ide = ide;
	adapter->ahci_bar = ahci_bar;
	return EFI_SUCCESS;
}
void cdk2_ata_pci_ahci_services(struct cdk2_ata_pci_adapter *adapter,
	struct cdk2_ahci_dma_services *services)
{ *services = (struct cdk2_ahci_dma_services) { .context = adapter,
	.allocate = dma_allocate, .release = dma_release, .map = dma_map,
	.unmap = dma_unmap, .flush = dma_flush, .read = ahci_read, .write = ahci_write,
	.time = adapter_time, .delay = adapter_delay }; }
void cdk2_ata_pci_ide_services(struct cdk2_ata_pci_adapter *adapter,
	struct cdk2_ide_services *services)
{ *services = (struct cdk2_ide_services) { .context = adapter, .read8 = ide_read8,
	.read16 = ide_read16, .write8 = ide_write8, .write16 = ide_write16,
	.write32 = ide_write32, .map = dma_map, .unmap = dma_unmap, .flush = dma_flush,
	.set_timing = ide_timing, .time = adapter_time, .delay = adapter_delay }; }
EFI_STATUS cdk2_ata_pci_adapter_release(struct cdk2_ata_pci_adapter *adapter)
{
	EFI_STATUS first = EFI_SUCCESS, status;
	if (adapter == NULL || adapter->pci == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = CDK2_ATA_ADAPTER_ALLOCATIONS; index != 0U; index--)
		if (adapter->allocations[index - 1U].host != NULL) {
			status = dma_release(adapter, adapter->allocations[index - 1U].host, 0);
			if (EFI_ERROR(status) && !EFI_ERROR(first))
				first = status;
		}
	return first;
}

EFI_STATUS cdk2_ata_pci_read_class(struct cdk2_efi_pci_io_protocol *pci,
	UINT8 class_code[3])
{
	if (pci == NULL || pci->pci.read == NULL || class_code == NULL)
		return EFI_INVALID_PARAMETER;
	return pci->pci.read(pci, EFI_PCI_IO_WIDTH_UINT8, 9U, 3U, class_code);
}

EFI_STATUS cdk2_ata_pci_get_attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINT64 *current, UINT64 *supported)
{
	EFI_STATUS status;

	if (pci == NULL || pci->attributes == NULL || current == NULL ||
	    supported == NULL)
		return EFI_INVALID_PARAMETER;
	status = pci->attributes(pci, EFI_PCI_IO_ATTRIBUTE_OPERATION_GET, 0,
		current);
	return EFI_ERROR(status) ? status : pci->attributes(pci,
		EFI_PCI_IO_ATTRIBUTE_OPERATION_SUPPORTED, 0, supported);
}

EFI_STATUS cdk2_ata_pci_enable_attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINT64 attributes)
{
	return pci == NULL || pci->attributes == NULL ? EFI_INVALID_PARAMETER :
		pci->attributes(pci, EFI_PCI_IO_ATTRIBUTE_OPERATION_ENABLE,
			attributes, NULL);
}

EFI_STATUS cdk2_ata_pci_restore_attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINT64 attributes)
{
	return pci == NULL || pci->attributes == NULL ? EFI_INVALID_PARAMETER :
		pci->attributes(pci, EFI_PCI_IO_ATTRIBUTE_OPERATION_SET, attributes,
			NULL);
}

EFI_STATUS cdk2_ata_pci_read_ahci_capability(
	struct cdk2_efi_pci_io_protocol *pci, UINT8 bar, UINT32 *capability,
	UINT32 *ports_implemented)
{
	EFI_STATUS status;

	if (pci == NULL || pci->mem.read == NULL || bar >= 6U ||
	    capability == NULL || ports_implemented == NULL)
		return EFI_INVALID_PARAMETER;
	status = pci->mem.read(pci, EFI_PCI_IO_WIDTH_UINT32, bar, 0U, 1U,
		capability);
	return EFI_ERROR(status) ? status : pci->mem.read(pci,
		EFI_PCI_IO_WIDTH_UINT32, bar, 0x0cU, 1U, ports_implemented);
}
