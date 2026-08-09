/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_io_model.h>

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
		io->attributes = attributes;
		return 0;
	case 2: /* Enable */
		if ((attributes & ~io->supported_attributes) != 0U)
			return -1;
		io->attributes |= attributes;
		return 0;
	case 3: /* Disable */
		io->attributes &= ~attributes;
		return 0;
	case 4: /* Supported */
		if (result == NULL)
			return -1;
		*result = io->supported_attributes;
		return 0;
	default:
		return -1;
	}
}
