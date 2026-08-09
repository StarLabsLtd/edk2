/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PCI_HOST_BRIDGE_H_
#define CDK2_PCI_HOST_BRIDGE_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_PCI_ROOT_BRIDGES_REVISION 1U
#define CDK2_PCI_ROOT_BRIDGE_APERTURES 6U
#define CDK2_PCI_HOST_MAX_ROOTS 16U
#define CDK2_PCI_RESOURCE_TYPES 5U

#pragma pack(push, 1)
struct cdk2_payload_header {
	uint16_t revision, length;
};

struct cdk2_pci_aperture {
	uint64_t base, limit, translation;
};

struct cdk2_pci_root_bridge_record {
	uint32_t segment;
	uint64_t supports, attributes;
	uint8_t dma_above_4g, no_extended_config;
	uint64_t allocation_attributes;
	struct cdk2_pci_aperture aperture[CDK2_PCI_ROOT_BRIDGE_APERTURES];
	uint32_t hid, uid;
};

struct cdk2_pci_root_bridges_hob {
	struct cdk2_payload_header header;
	uint8_t resource_assigned, count;
	struct cdk2_pci_root_bridge_record bridge[];
};
#pragma pack(pop)

struct cdk2_pci_root_bridge_view {
	uint32_t segment, hid, uid;
	uint64_t supports, attributes, allocation_attributes;
	uint8_t dma_above_4g, no_extended_config;
	struct cdk2_pci_aperture aperture[CDK2_PCI_ROOT_BRIDGE_APERTURES];
};

enum cdk2_pci_host_phase {
	CDK2_PCI_BEGIN_ENUMERATION,
	CDK2_PCI_BEGIN_BUS_ALLOCATION,
	CDK2_PCI_END_BUS_ALLOCATION,
	CDK2_PCI_BEGIN_RESOURCE_ALLOCATION,
	CDK2_PCI_ALLOCATE_RESOURCES,
	CDK2_PCI_SET_RESOURCES,
	CDK2_PCI_FREE_RESOURCES,
	CDK2_PCI_END_RESOURCE_ALLOCATION
};

struct cdk2_pci_resource_request {
	uint64_t length, alignment, base;
	uint8_t submitted, allocated;
};

typedef uint64_t CDK2_MS_ABI cdk2_pci_reserve_fn(void *, uint8_t, uint64_t,
	uint64_t, uint64_t, uint64_t *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_release_fn(void *, uint8_t, uint64_t,
	uint64_t);

struct cdk2_pci_host_model {
	struct cdk2_pci_root_bridge_view root[CDK2_PCI_HOST_MAX_ROOTS];
	struct cdk2_pci_resource_request
		request[CDK2_PCI_HOST_MAX_ROOTS][CDK2_PCI_RESOURCE_TYPES];
	size_t count;
	uint8_t can_restart, resource_assigned;
	void *allocator_context;
	cdk2_pci_reserve_fn *reserve;
	cdk2_pci_release_fn *release;
};

uint64_t cdk2_pci_root_bridges_validate(const void *hob, size_t hob_size,
	size_t *count, uint8_t *resource_assigned);
uint64_t cdk2_pci_root_bridge_get(const void *hob, size_t hob_size,
	size_t index, struct cdk2_pci_root_bridge_view *bridge);
uint64_t cdk2_pci_host_init(struct cdk2_pci_host_model *host,
	const void *hob, size_t hob_size);
uint64_t cdk2_pci_host_notify(struct cdk2_pci_host_model *host,
	enum cdk2_pci_host_phase phase);
uint64_t cdk2_pci_host_submit(struct cdk2_pci_host_model *host, size_t root,
	size_t type, uint64_t length, uint64_t alignment);
uint64_t cdk2_pci_host_set_allocator(struct cdk2_pci_host_model *host,
	void *context, cdk2_pci_reserve_fn *reserve, cdk2_pci_release_fn *release);

#endif
