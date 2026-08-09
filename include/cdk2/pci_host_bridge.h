/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PCI_HOST_BRIDGE_H_
#define CDK2_PCI_HOST_BRIDGE_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_PCI_ROOT_BRIDGES_REVISION 1U
#define CDK2_PCI_ROOT_BRIDGE_APERTURES 6U

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

uint64_t cdk2_pci_root_bridges_validate(const void *hob, size_t hob_size,
	size_t *count, uint8_t *resource_assigned);
uint64_t cdk2_pci_root_bridge_get(const void *hob, size_t hob_size,
	size_t index, struct cdk2_pci_root_bridge_view *bridge);

#endif
