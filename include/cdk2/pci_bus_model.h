/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CDK2_PCI_BUS_MODEL_H
#define CDK2_PCI_BUS_MODEL_H

#include <stddef.h>
#include <stdint.h>

#define CDK2_PCI_MAX_FUNCTIONS 256U
#define CDK2_PCI_MAX_BARS 7U
#define CDK2_PCI_MAX_VFS 64U

enum cdk2_pci_bar_kind {
	CDK2_PCI_BAR_NONE,
	CDK2_PCI_BAR_IO,
	CDK2_PCI_BAR_MEM32,
	CDK2_PCI_BAR_MEM64,
	CDK2_PCI_BAR_ROM,
};

struct cdk2_pci_cfg {
	void *context;
	unsigned int crs_retries;
	int (*read)(void *context, uint8_t bus, uint8_t device, uint8_t function,
		uint16_t offset, uint8_t width, uint32_t *value);
	int (*write)(void *context, uint8_t bus, uint8_t device, uint8_t function,
		uint16_t offset, uint8_t width, uint32_t value);
};

struct cdk2_pci_bar {
	enum cdk2_pci_bar_kind kind;
	uint8_t index;
	uint8_t prefetchable;
	uint64_t base;
	uint64_t size;
};

struct cdk2_pci_function {
	uint8_t bus, device, function;
	uint8_t header_type, class_code, subclass, programming_interface;
	uint8_t secondary_bus, subordinate_bus;
	uint16_t vendor_id, device_id;
	uint16_t pcie_cap, ari_cap, sriov_cap, resizable_bar_cap;
	uint16_t total_vfs, initial_vfs, vf_offset, vf_stride;
	uint16_t vf_device_id;
	uint16_t vf_rids[CDK2_PCI_MAX_VFS];
	uint8_t vf_count;
	uint8_t ari_forwarding;
	uint8_t selected_rebar_size;
	uint64_t io_base, io_limit;
	uint64_t memory_base, memory_limit;
	uint64_t prefetch_base, prefetch_limit;
	struct cdk2_pci_bar bars[CDK2_PCI_MAX_BARS];
	uint8_t bar_count;
};

struct cdk2_pci_resource_request {
	enum cdk2_pci_bar_kind kind;
	uint64_t length;
	uint64_t alignment;
};

struct cdk2_pci_topology {
	struct cdk2_pci_function functions[CDK2_PCI_MAX_FUNCTIONS];
	size_t count;
	struct cdk2_pci_resource_request requests[4];
};

int cdk2_pci_probe_function(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *function);
int cdk2_pci_enumerate(const struct cdk2_pci_cfg *cfg, uint8_t first_bus,
	uint8_t last_bus, struct cdk2_pci_topology *topology);

#endif
