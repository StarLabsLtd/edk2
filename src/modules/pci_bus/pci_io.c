/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_io_model.h>

#include <string.h>

#define PCI_ATTR_IO 0x100U
#define PCI_ATTR_MEMORY 0x200U
#define PCI_ATTR_BUS_MASTER 0x400U
#define PCI_ATTR_DAC 0x8000U

struct bounce_mapping {
	void *host;
	size_t size, pages;
	unsigned int operation;
	uint8_t data[];
};

static int width_size(unsigned int width, size_t *size)
{
	unsigned int base = width & 3U;
	if (width > 11U || size == NULL)
		return -1;
	*size = (size_t)1U << base;
	return 0;
}

int cdk2_pci_io_access(struct cdk2_pci_io_model *io,
	enum cdk2_pci_io_space space, int write, unsigned int bar,
	uint64_t offset, unsigned int width, size_t count, void *buffer)
{
	size_t unit, span;
	uint64_t address;
	if (io == NULL || io->backend.access == NULL || buffer == NULL ||
	    width_size(width, &unit) != 0 || count == 0U)
		return -1;
	if (space == CDK2_PCI_IO_CONFIG) {
		if (bar != 0U || offset > 0xfffU || count > (0x1000U - offset) / unit)
			return -1;
		address = offset;
	} else {
		if (bar >= CDK2_PCI_IO_MAX_BARS || unit > io->bar_size[bar])
			return -1;
		/* FIFO widths touch one element; FILL and normal widths touch count. */
		span = width >= 4U && width <= 7U ? unit : unit * count;
		if (span / unit != (width >= 4U && width <= 7U ? 1U : count) ||
		    offset > io->bar_size[bar] - span ||
		    io->bar_base[bar] > UINT64_MAX - offset)
			return -1;
		address = io->bar_base[bar] + offset;
	}
	return io->backend.access(io->backend.context, space, write, width, address,
		count, buffer);
}

int cdk2_pci_io_attributes(struct cdk2_pci_io_model *io, unsigned int operation,
	uint64_t attributes, uint64_t *result)
{
	uint64_t updated;
	uint16_t command;
	if (io == NULL)
		return -1;
	switch (operation) {
	case 0: /* Get */
		if (result == NULL)
			return -1;
		*result = io->attributes;
		return 0;
	case 1: /* Set */
		if ((attributes & ~io->supported_attributes) != 0U)
			return -1;
		updated = attributes;
		break;
	case 2: /* Enable */
		if ((attributes & ~io->supported_attributes) != 0U)
			return -1;
		updated = io->attributes | attributes;
		break;
	case 3: /* Disable */
		if ((attributes & ~io->supported_attributes) != 0U)
			return -1;
		updated = io->attributes & ~attributes;
		break;
	case 4: /* Supported */
		if (result == NULL)
			return -1;
		*result = io->supported_attributes;
		return 0;
	default:
		return -1;
	}
	if (io->backend.access == NULL ||
	    io->backend.access(io->backend.context, CDK2_PCI_IO_CONFIG, 0, 1, 4, 1,
		&command) != 0)
		return -1;
	command &= ~7U;
	if ((updated & PCI_ATTR_IO) != 0U)
		command |= 1U;
	if ((updated & PCI_ATTR_MEMORY) != 0U)
		command |= 2U;
	if ((updated & PCI_ATTR_BUS_MASTER) != 0U)
		command |= 4U;
	if (io->backend.access(io->backend.context, CDK2_PCI_IO_CONFIG, 1, 1, 4, 1,
		&command) != 0)
		return -1;
	io->attributes = updated;
	return 0;
}

int cdk2_pci_io_poll(struct cdk2_pci_io_model *io, enum cdk2_pci_io_space space,
	unsigned int bar, uint64_t offset, unsigned int width, uint64_t mask,
	uint64_t value, uint64_t delay, uint64_t *result)
{
	uint64_t current = 0, elapsed = 0;
	if (result == NULL || width > 3U)
		return -1;
	for (;;) {
		if (cdk2_pci_io_access(io, space, 0, bar, offset, width, 1, &current) != 0)
			return -1;
		*result = current;
		if ((current & mask) == value)
			return 0;
		if (elapsed >= delay)
			return 1;
		if (io->backend.delay == NULL || io->backend.delay(io->backend.context, 1) != 0)
			return -1;
		elapsed++;
	}
}

int cdk2_pci_io_copy(struct cdk2_pci_io_model *io, unsigned int width,
	unsigned int destination_bar, uint64_t destination_offset,
	unsigned int source_bar, uint64_t source_offset, size_t count)
{
	uint64_t value;
	size_t unit;
	if (width > 3U || width_size(width, &unit) != 0)
		return -1;
	if (count > SIZE_MAX / unit)
		return -1;
	for (size_t step = 0; step < count; step++) {
		size_t index = destination_bar == source_bar &&
			destination_offset > source_offset &&
			destination_offset < source_offset + count * unit ?
			count - step - 1U : step;
		if (cdk2_pci_io_access(io, CDK2_PCI_IO_MEM, 0, source_bar,
			source_offset + index * unit, width, 1, &value) != 0 ||
		    cdk2_pci_io_access(io, CDK2_PCI_IO_MEM, 1, destination_bar,
			destination_offset + index * unit, width, 1, &value) != 0)
			return -1;
	}
	return 0;
}

int cdk2_pci_io_map(struct cdk2_pci_io_model *io, unsigned int operation,
	void *host, size_t *size, uint64_t *device, void **mapping)
{
	struct bounce_mapping *bounce;
	size_t pages;
	if (io == NULL || host == NULL || size == NULL || *size == 0U ||
	    device == NULL || mapping == NULL || operation > 5U)
		return -1;
	if (io->backend.map != NULL)
		return io->backend.map(io->backend.context, operation, host, size,
			device, mapping);
	if (operation >= 3U || ((uint64_t)(uintptr_t)host <= UINT32_MAX &&
	    *size - 1U <= UINT32_MAX - (uint64_t)(uintptr_t)host)) {
		if ((uint64_t)(uintptr_t)host > UINT64_MAX - (*size - 1U))
			return -1;
		*device = (uint64_t)(uintptr_t)host;
		*mapping = NULL;
		return 0;
	}
	if (io->backend.allocate == NULL || *size > SIZE_MAX - sizeof(*bounce))
		return -1;
	if (operation == 2U || operation == 5U)
		return -1;
	pages = (sizeof(*bounce) + *size + 4095U) / 4096U;
	bounce = io->backend.allocate(io->backend.context, pages, 1);
	if (bounce == NULL)
		return -1;
	bounce->host = host; bounce->size = *size; bounce->pages = pages;
	bounce->operation = operation;
	if (operation == 0U || operation == 3U)
		memcpy(bounce->data, host, *size);
	*device = (uint64_t)(uintptr_t)bounce->data;
	*mapping = bounce;
	return 0;
}

int cdk2_pci_io_unmap(struct cdk2_pci_io_model *io, void *mapping)
{
	struct bounce_mapping *bounce = mapping;
	if (io == NULL)
		return -1;
	if (io->backend.unmap != NULL)
		return io->backend.unmap(io->backend.context, mapping);
	if (bounce == NULL)
		return 0;
	if (io->backend.free == NULL)
		return -1;
	if (bounce->operation == 1U || bounce->operation == 4U)
		memcpy(bounce->host, bounce->data, bounce->size);
	return io->backend.free(io->backend.context, bounce->pages, bounce);
}

void *cdk2_pci_io_allocate_buffer(struct cdk2_pci_io_model *io, size_t pages,
	uint64_t attributes)
{
	if (io == NULL || io->backend.allocate == NULL || pages == 0U ||
	    (attributes & ~PCI_ATTR_DAC) != 0U)
		return NULL;
	return io->backend.allocate(io->backend.context, pages,
		(attributes & PCI_ATTR_DAC) == 0U);
}

int cdk2_pci_io_free_buffer(struct cdk2_pci_io_model *io, size_t pages,
	void *buffer)
{
	if (io == NULL || io->backend.free == NULL || pages == 0U || buffer == NULL)
		return -1;
	return io->backend.free(io->backend.context, pages, buffer);
}

int cdk2_pci_io_flush(struct cdk2_pci_io_model *io)
{
	if (io == NULL)
		return -1;
	return io->backend.flush == NULL ? 0 : io->backend.flush(io->backend.context);
}

int cdk2_pci_io_get_location(const struct cdk2_pci_io_model *io,
	uint16_t *segment, uint8_t *bus, uint8_t *device, uint8_t *function)
{
	if (io == NULL || segment == NULL || bus == NULL || device == NULL ||
	    function == NULL)
		return -1;
	*segment = io->segment; *bus = io->bus; *device = io->device;
	*function = io->function;
	return 0;
}
