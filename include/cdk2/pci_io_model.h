/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CDK2_PCI_IO_MODEL_H
#define CDK2_PCI_IO_MODEL_H

#include <stddef.h>
#include <stdint.h>

#define CDK2_PCI_IO_MAX_BARS 6U

enum cdk2_pci_io_space { CDK2_PCI_IO_MEM, CDK2_PCI_IO_PORT, CDK2_PCI_IO_CONFIG };

struct cdk2_pci_io_backend {
	void *context;
	int (*access)(void *context, enum cdk2_pci_io_space space, int write,
		unsigned int width, uint64_t address, size_t count, void *buffer);
};

struct cdk2_pci_io_model {
	struct cdk2_pci_io_backend backend;
	uint64_t bar_base[CDK2_PCI_IO_MAX_BARS];
	uint64_t bar_size[CDK2_PCI_IO_MAX_BARS];
	uint64_t supported_attributes;
	uint64_t attributes;
};

int cdk2_pci_io_access(struct cdk2_pci_io_model *io,
	enum cdk2_pci_io_space space, int write, unsigned int bar,
	uint64_t offset, unsigned int width, size_t count, void *buffer);
int cdk2_pci_io_attributes(struct cdk2_pci_io_model *io, unsigned int operation,
	uint64_t attributes, uint64_t *result);

#endif
