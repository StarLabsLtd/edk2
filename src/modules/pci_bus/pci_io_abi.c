/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_io_abi.h>

#include <string.h>

static struct cdk2_pci_io_model *model(struct cdk2_efi_pci_io_protocol *protocol)
{
	return ((struct cdk2_pci_io_instance *)protocol)->model;
}

static EFI_STATUS status(struct cdk2_pci_io_model *io, int call_result)
{
	if (call_result == 0)
		return EFI_SUCCESS;
	if (call_result == 1)
		return EFI_TIMEOUT;
	if (io != NULL && io->backend.status != NULL)
		return io->backend.status(io->backend.context);
	return EFI_DEVICE_ERROR;
}

static EFI_STATUS access(struct cdk2_efi_pci_io_protocol *this,
	enum cdk2_pci_io_space space, int write, UINTN width, UINT8 bar,
	UINT64 offset, UINTN count, void *buffer)
{
	return status(model(this), cdk2_pci_io_access(model(this), space, write, bar, offset,
		width, count, buffer));
}

static EFI_STATUS CDK2_MS_ABI mem_read(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{ return access(this, CDK2_PCI_IO_MEM, 0, width, bar, offset, count, buffer); }
static EFI_STATUS CDK2_MS_ABI mem_write(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{ return access(this, CDK2_PCI_IO_MEM, 1, width, bar, offset, count, buffer); }
static EFI_STATUS CDK2_MS_ABI io_read(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{ return access(this, CDK2_PCI_IO_PORT, 0, width, bar, offset, count, buffer); }
static EFI_STATUS CDK2_MS_ABI io_write(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{ return access(this, CDK2_PCI_IO_PORT, 1, width, bar, offset, count, buffer); }
static EFI_STATUS CDK2_MS_ABI pci_read(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT32 offset, UINTN count, void *buffer)
{ return access(this, CDK2_PCI_IO_CONFIG, 0, width, 0, offset, count, buffer); }
static EFI_STATUS CDK2_MS_ABI pci_write(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT32 offset, UINTN count, void *buffer)
{ return access(this, CDK2_PCI_IO_CONFIG, 1, width, 0, offset, count, buffer); }

static EFI_STATUS CDK2_MS_ABI poll_mem(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT8 bar, UINT64 offset, UINT64 mask, UINT64 value,
	UINT64 delay,
	UINT64 *result)
{
	uint64_t native_result;
	int call_status = cdk2_pci_io_poll(model(this), CDK2_PCI_IO_MEM, bar, offset,
		width, mask, value, delay, &native_result);
	if (result != NULL && call_status <= 1)
		*result = native_result;
	return status(model(this), call_status);
}

static EFI_STATUS CDK2_MS_ABI poll_io(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT8 bar, UINT64 offset, UINT64 mask, UINT64 value,
	UINT64 delay,
	UINT64 *result)
{
	uint64_t native_result;
	int call_status = cdk2_pci_io_poll(model(this), CDK2_PCI_IO_PORT, bar, offset,
		width, mask, value, delay, &native_result);
	if (result != NULL && call_status <= 1)
		*result = native_result;
	return status(model(this), call_status);
}

static EFI_STATUS CDK2_MS_ABI copy_mem(struct cdk2_efi_pci_io_protocol *this,
	UINTN width, UINT8 destination_bar, UINT64 destination_offset,
	UINT8 source_bar, UINT64 source_offset, UINTN count)
{
	return status(model(this), cdk2_pci_io_copy(model(this), width, destination_bar,
		destination_offset, source_bar, source_offset, count));
}

static EFI_STATUS CDK2_MS_ABI map_dma(struct cdk2_efi_pci_io_protocol *this,
	UINTN operation, void *host, UINTN *bytes, UINT64 *device, void **mapping)
{
	size_t native_bytes;
	uint64_t native_device;
	int call_status;
	if (bytes == NULL || device == NULL)
		return EFI_INVALID_PARAMETER;
	native_bytes = *bytes;
	call_status = cdk2_pci_io_map(model(this), operation, host, &native_bytes,
		&native_device, mapping);
	*bytes = native_bytes;
	if (call_status == 0)
		*device = native_device;
	return status(model(this), call_status);
}

static EFI_STATUS CDK2_MS_ABI unmap_dma(struct cdk2_efi_pci_io_protocol *this,
	void *mapping)
{
	return status(model(this), cdk2_pci_io_unmap(model(this), mapping));
}

static EFI_STATUS CDK2_MS_ABI allocate_buffer(
	struct cdk2_efi_pci_io_protocol *this, UINTN type, UINTN memory_type,
	UINTN pages, void **host, UINT64 attributes)
{
	(void)memory_type;
	if (host == NULL || type > 1U)
		return EFI_INVALID_PARAMETER;
	*host = cdk2_pci_io_allocate_buffer(model(this), pages, attributes);
	return *host == NULL ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI free_buffer(struct cdk2_efi_pci_io_protocol *this,
	UINTN pages, void *host)
{
	return status(model(this), cdk2_pci_io_free_buffer(model(this), pages, host));
}

static EFI_STATUS CDK2_MS_ABI flush(struct cdk2_efi_pci_io_protocol *this)
{
	return status(model(this), cdk2_pci_io_flush(model(this)));
}

static EFI_STATUS CDK2_MS_ABI get_location(struct cdk2_efi_pci_io_protocol *this,
	UINTN *segment, UINTN *bus, UINTN *device, UINTN *function)
{
	uint16_t segment16; uint8_t bus8, device8, function8;
	if (segment == NULL || bus == NULL || device == NULL || function == NULL ||
	    cdk2_pci_io_get_location(model(this), &segment16, &bus8, &device8,
		&function8) != 0)
		return EFI_INVALID_PARAMETER;
	*segment = segment16; *bus = bus8; *device = device8; *function = function8;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI attributes(struct cdk2_efi_pci_io_protocol *this,
	UINTN operation, UINT64 attributes_value, UINT64 *result)
{
	uint64_t native_result;
	int call_status = cdk2_pci_io_attributes(model(this), operation,
		attributes_value, result == NULL ? NULL : &native_result);
	if (result != NULL && call_status == 0)
		*result = native_result;
	return status(model(this), call_status);
}

static EFI_STATUS CDK2_MS_ABI get_bar_attributes(
	struct cdk2_efi_pci_io_protocol *this, UINT8 bar, UINT64 *supports,
	void **resources)
{
	struct cdk2_pci_io_model *io = model(this);
	uint8_t *descriptor;
	if (bar >= CDK2_PCI_IO_MAX_BARS || supports == NULL || resources == NULL)
		return EFI_INVALID_PARAMETER;
	if (io->backend.allocate_pool == NULL || io->bar_size[bar] == 0U)
		return EFI_UNSUPPORTED;
	descriptor = io->backend.allocate_pool(io->backend.context, 48);
	if (descriptor == NULL)
		return EFI_DEVICE_ERROR;
	memset(descriptor, 0, 48);
	descriptor[0] = 0x8a; descriptor[1] = 0x2b;
	descriptor[3] = io->bar_space[bar] == CDK2_PCI_IO_PORT ? 1U : 0U;
	for (unsigned int byte = 0; byte < 8U; byte++) {
		descriptor[14 + byte] = (uint8_t)(io->bar_base[bar] >> (byte * 8U));
		descriptor[22 + byte] = (uint8_t)((io->bar_base[bar] +
			io->bar_size[bar] - 1U) >> (byte * 8U));
		descriptor[38 + byte] = (uint8_t)(io->bar_size[bar] >> (byte * 8U));
	}
	descriptor[46] = 0x79;
	*supports = io->supported_attributes;
	*resources = descriptor;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI set_bar_attributes(
	struct cdk2_efi_pci_io_protocol *this, UINT64 attributes_value, UINT8 bar,
	UINT64 *offset, UINT64 *length)
{
	struct cdk2_pci_io_model *io = model(this);
	if (bar >= CDK2_PCI_IO_MAX_BARS || offset == NULL || length == NULL ||
	    *offset > io->bar_size[bar] || *length > io->bar_size[bar] - *offset ||
	    (attributes_value & ~io->supported_attributes) != 0U)
		return EFI_UNSUPPORTED;
	if (io->backend.set_bar_attributes == NULL)
		return EFI_UNSUPPORTED;
	return status(io, io->backend.set_bar_attributes(io->backend.context, bar,
		*offset, *length, attributes_value));
}

void cdk2_pci_io_initialize_protocol(struct cdk2_pci_io_instance *instance,
	struct cdk2_pci_io_model *io)
{
	memset(instance, 0, sizeof(*instance));
	instance->model = io;
	instance->protocol.revision = 0x00010000U;
	instance->protocol.poll_mem = poll_mem; instance->protocol.poll_io = poll_io;
	instance->protocol.mem = (struct cdk2_pci_io_access_pair) { mem_read, mem_write };
	instance->protocol.io = (struct cdk2_pci_io_access_pair) { io_read, io_write };
	instance->protocol.pci = (struct cdk2_pci_io_config_pair) { pci_read, pci_write };
	instance->protocol.copy_mem = copy_mem; instance->protocol.map = map_dma;
	instance->protocol.unmap = unmap_dma;
	instance->protocol.allocate_buffer = allocate_buffer;
	instance->protocol.free_buffer = free_buffer; instance->protocol.flush = flush;
	instance->protocol.get_location = get_location;
	instance->protocol.attributes = attributes;
	instance->protocol.get_bar_attributes = get_bar_attributes;
	instance->protocol.set_bar_attributes = set_bar_attributes;
	instance->protocol.rom_size = io->rom_size;
	instance->protocol.rom_image = io->rom_image;
}
