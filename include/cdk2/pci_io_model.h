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
	int (*delay)(void *context, uint64_t ticks);
	int (*map)(void *context, unsigned int operation, void *host, size_t *size,
		uint64_t *device, void **mapping);
	int (*unmap)(void *context, void *mapping);
	void *(*allocate)(void *context, size_t pages, int below_4g);
	int (*free)(void *context, size_t pages, void *buffer);
	int (*flush)(void *context);
	void *(*allocate_pool)(void *context, size_t size);
	int (*set_bar_attributes)(void *context, unsigned int bar, uint64_t offset,
		uint64_t length, uint64_t attributes);
	uint64_t (*status)(void *context);
};

struct cdk2_pci_io_model {
	struct cdk2_pci_io_backend backend;
	uint64_t bar_base[CDK2_PCI_IO_MAX_BARS];
	uint64_t bar_size[CDK2_PCI_IO_MAX_BARS];
	enum cdk2_pci_io_space bar_space[CDK2_PCI_IO_MAX_BARS];
	uint64_t supported_attributes;
	uint64_t attributes;
	uint16_t segment;
	uint8_t bus, device, function;
	void *rom_image;
	uint64_t rom_size;
};

int cdk2_pci_io_access(struct cdk2_pci_io_model *io,
	enum cdk2_pci_io_space space, int write, unsigned int bar,
	uint64_t offset, unsigned int width, size_t count, void *buffer);
int cdk2_pci_io_attributes(struct cdk2_pci_io_model *io, unsigned int operation,
	uint64_t attributes, uint64_t *result);
int cdk2_pci_io_poll(struct cdk2_pci_io_model *io, enum cdk2_pci_io_space space,
	unsigned int bar, uint64_t offset, unsigned int width, uint64_t mask,
	uint64_t value, uint64_t delay, uint64_t *result);
int cdk2_pci_io_copy(struct cdk2_pci_io_model *io, unsigned int width,
	unsigned int destination_bar, uint64_t destination_offset,
	unsigned int source_bar, uint64_t source_offset, size_t count);
int cdk2_pci_io_map(struct cdk2_pci_io_model *io, unsigned int operation,
	void *host, size_t *size, uint64_t *device, void **mapping);
int cdk2_pci_io_unmap(struct cdk2_pci_io_model *io, void *mapping);
void *cdk2_pci_io_allocate_buffer(struct cdk2_pci_io_model *io, size_t pages,
	uint64_t attributes);
int cdk2_pci_io_free_buffer(struct cdk2_pci_io_model *io, size_t pages,
	void *buffer);
int cdk2_pci_io_flush(struct cdk2_pci_io_model *io);
int cdk2_pci_io_get_location(const struct cdk2_pci_io_model *io,
	uint16_t *segment, uint8_t *bus, uint8_t *device, uint8_t *function);

#endif
