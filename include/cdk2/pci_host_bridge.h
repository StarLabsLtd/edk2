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
	CDK2_PCI_END_RESOURCE_ALLOCATION,
	CDK2_PCI_END_ENUMERATION
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
	uint8_t resource_submitted[CDK2_PCI_HOST_MAX_ROOTS];
	void *allocator_context;
	cdk2_pci_reserve_fn *reserve;
	cdk2_pci_release_fn *release;
};

enum cdk2_pci_width {
	CDK2_PCI_UINT8, CDK2_PCI_UINT16, CDK2_PCI_UINT32, CDK2_PCI_UINT64,
	CDK2_PCI_FIFO8, CDK2_PCI_FIFO16, CDK2_PCI_FIFO32, CDK2_PCI_FIFO64,
	CDK2_PCI_FILL8, CDK2_PCI_FILL16, CDK2_PCI_FILL32, CDK2_PCI_FILL64,
	CDK2_PCI_WIDTH_MAX
};

enum cdk2_pci_dma_operation {
	CDK2_PCI_DMA_READ, CDK2_PCI_DMA_WRITE, CDK2_PCI_DMA_COMMON,
	CDK2_PCI_DMA_READ64, CDK2_PCI_DMA_WRITE64, CDK2_PCI_DMA_COMMON64,
	CDK2_PCI_DMA_MAX
};

struct cdk2_pci_root_io;
typedef uint64_t CDK2_MS_ABI cdk2_pci_io_fn(void *, size_t, uint64_t,
	size_t, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_stall_fn(size_t);
typedef uint64_t CDK2_MS_ABI cdk2_pci_iommu_map_fn(void *, size_t, void *,
	size_t *, uint64_t *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_pci_iommu_unmap_fn(void *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_iommu_allocate_fn(void *, uint32_t,
	uint32_t, size_t, void **, uint64_t);
typedef uint64_t CDK2_MS_ABI cdk2_pci_iommu_free_fn(void *, size_t, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_pages_fn(uint32_t, uint32_t, size_t,
	uint64_t *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_free_pages_fn(uint64_t, size_t);
typedef uint64_t CDK2_MS_ABI cdk2_pci_pool_fn(uint32_t, size_t, void **);
typedef uint64_t CDK2_MS_ABI cdk2_pci_free_pool_fn(void *);

struct cdk2_pci_root_io_services {
	void *cpu, *iommu;
	cdk2_pci_io_fn *mem_read, *mem_write, *io_read, *io_write;
	cdk2_pci_stall_fn *stall;
	cdk2_pci_iommu_map_fn *iommu_map;
	cdk2_pci_iommu_unmap_fn *iommu_unmap;
	cdk2_pci_iommu_allocate_fn *iommu_allocate;
	cdk2_pci_iommu_free_fn *iommu_free;
	cdk2_pci_pages_fn *allocate_pages;
	cdk2_pci_free_pages_fn *free_pages;
	cdk2_pci_pool_fn *allocate_pool;
	cdk2_pci_free_pool_fn *free_pool;
};

typedef uint64_t CDK2_MS_ABI cdk2_pci_poll_fn(struct cdk2_pci_root_io *,
	size_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_access_fn(struct cdk2_pci_root_io *,
	size_t, uint64_t, size_t, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_copy_fn(struct cdk2_pci_root_io *,
	size_t, uint64_t, uint64_t, size_t);
typedef uint64_t CDK2_MS_ABI cdk2_pci_map_fn(struct cdk2_pci_root_io *, size_t,
	void *, size_t *, uint64_t *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_pci_unmap_fn(struct cdk2_pci_root_io *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_allocate_buffer_fn(
	struct cdk2_pci_root_io *, uint32_t, uint32_t, size_t, void **, uint64_t);
typedef uint64_t CDK2_MS_ABI cdk2_pci_free_buffer_fn(
	struct cdk2_pci_root_io *, size_t, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_flush_fn(struct cdk2_pci_root_io *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_get_attributes_fn(
	struct cdk2_pci_root_io *, uint64_t *, uint64_t *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_set_attributes_fn(
	struct cdk2_pci_root_io *, uint64_t, uint64_t *, uint64_t *);
typedef uint64_t CDK2_MS_ABI cdk2_pci_configuration_fn(
	struct cdk2_pci_root_io *, void **);

struct cdk2_pci_root_io {
	void *parent_handle;
	cdk2_pci_poll_fn *poll_mem, *poll_io;
	struct {
		cdk2_pci_access_fn *read;
		cdk2_pci_access_fn *write;
	} mem, io, pci;
	cdk2_pci_copy_fn *copy_mem;
	cdk2_pci_map_fn *map;
	cdk2_pci_unmap_fn *unmap;
	cdk2_pci_allocate_buffer_fn *allocate_buffer;
	cdk2_pci_free_buffer_fn *free_buffer;
	cdk2_pci_flush_fn *flush;
	cdk2_pci_get_attributes_fn *get_attributes;
	cdk2_pci_set_attributes_fn *set_attributes;
	cdk2_pci_configuration_fn *configuration;
	uint32_t segment;
	struct cdk2_pci_root_bridge_view root;
	struct cdk2_pci_root_io_services services;
	uint64_t ecam_base, current_attributes;
	void *mappings;
	uint64_t resource_base[CDK2_PCI_ROOT_BRIDGE_APERTURES];
	uint64_t resource_length[CDK2_PCI_ROOT_BRIDGE_APERTURES];
	uint8_t resource_assigned[CDK2_PCI_ROOT_BRIDGE_APERTURES];
	uint8_t configuration_data[6 * 46 + 2];
};

uint64_t cdk2_pci_root_io_init(struct cdk2_pci_root_io *io,
	const struct cdk2_pci_root_bridge_view *root, uint64_t ecam_base,
	const struct cdk2_pci_root_io_services *services, void *parent_handle,
	uint8_t resource_assigned);
uint64_t cdk2_pci_root_io_set_resource(struct cdk2_pci_root_io *io,
	size_t aperture, uint64_t device_base, uint64_t length, uint8_t assigned);

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
