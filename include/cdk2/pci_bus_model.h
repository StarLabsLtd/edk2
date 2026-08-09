/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CDK2_PCI_BUS_MODEL_H
#define CDK2_PCI_BUS_MODEL_H

#include <stddef.h>
#include <stdint.h>

#define CDK2_PCI_MAX_FUNCTIONS 256U
#define CDK2_PCI_MAX_BARS 7U
#define CDK2_PCI_MAX_VFS 64U
#define CDK2_PCI_MAX_REBAR 6U
#define CDK2_PCI_MAX_ROOTS 8U
#define CDK2_PCI_RESOURCE_CLASSES 4U
#define CDK2_PCI_MAX_ROM_IMAGES 16U
#define CDK2_PCI_ROOT_PARENT UINT16_MAX

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
	int (*read_memory)(void *context, uint64_t address, void *buffer, size_t size);
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
	uint16_t parent_index;
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
	uint8_t hotplug_bridge;
	uint64_t hotplug_padding[CDK2_PCI_RESOURCE_CLASSES];
	uint8_t rebar_count;
	struct {
		uint16_t control_offset;
		uint32_t supported_sizes;
		uint8_t bar_index;
		uint8_t selected_size;
	} rebar[CDK2_PCI_MAX_REBAR];
	uint64_t io_base, io_limit;
	uint64_t memory_base, memory_limit;
	uint64_t prefetch_base, prefetch_limit;
	struct cdk2_pci_bar bars[CDK2_PCI_MAX_BARS];
	uint8_t bar_count;
	struct cdk2_pci_bar vf_bars[6];
	uint8_t vf_bar_count;
	uint8_t option_rom_images;
	uint8_t option_rom_efi_images;
	uint8_t option_rom_load_file;
	void *option_rom_shadow;
	size_t option_rom_shadow_size;
	void *option_rom_image_handle;
	struct {
		uint32_t offset;
		uint32_t size;
		uint32_t payload_offset;
		uint16_t machine;
		uint8_t code_type;
		uint8_t compression;
		void *image_handle;
		void *decompressed;
		size_t decompressed_size;
	} option_rom[CDK2_PCI_MAX_ROM_IMAGES];
};

struct cdk2_pci_bus_resource_request {
	enum cdk2_pci_bar_kind kind;
	uint64_t length;
	uint64_t alignment;
};

struct cdk2_pci_aperture {
	uint64_t base;
	uint64_t limit;
	uint64_t cursor;
};

struct cdk2_pci_allocation_policy {
	struct cdk2_pci_aperture io, mem32, mem64, prefetch;
	uint64_t hotplug_padding[4];
	uint8_t maximum_rebar_size;
	uint8_t enable_sriov;
};

struct cdk2_pci_root_allocation {
	uint16_t segment;
	uint8_t first_bus, last_bus;
	struct cdk2_pci_allocation_policy policy;
};

enum cdk2_pci_bus_host_phase {
	CDK2_PCI_HOST_IDLE,
	CDK2_PCI_HOST_BEGIN,
	CDK2_PCI_HOST_ALLOCATED,
	CDK2_PCI_HOST_SET,
	CDK2_PCI_HOST_ENDED,
};

struct cdk2_pci_bus_host_model {
	enum cdk2_pci_bus_host_phase phase;
	struct cdk2_pci_topology *topology;
	const struct cdk2_pci_cfg *cfg;
	struct cdk2_pci_allocation_policy proposed;
	int allocation_status;
	struct {
		uint16_t segment;
		uint8_t first_bus, last_bus;
		struct cdk2_pci_bus_resource_request proposed[CDK2_PCI_RESOURCE_CLASSES];
		int status[CDK2_PCI_RESOURCE_CLASSES];
		struct cdk2_pci_allocation_policy policy;
		uint8_t policy_valid;
	} roots[CDK2_PCI_MAX_ROOTS];
	size_t root_count;
};

struct cdk2_pci_hotplug_ops {
	void *context;
	int (*initialize_controller)(void *context,
		const struct cdk2_pci_function *bridge);
	void (*deinitialize_controller)(void *context,
		const struct cdk2_pci_function *bridge);
	int (*get_padding)(void *context, const struct cdk2_pci_function *bridge,
		uint64_t padding[CDK2_PCI_RESOURCE_CLASSES]);
};

struct cdk2_pci_rom_ops {
	void *context;
	void *(*allocate)(void *context, size_t size);
	void (*free)(void *context, void *buffer);
	int (*decompress)(void *context, const void *source, size_t source_size,
		void *destination, size_t *destination_size);
	int (*load_image)(void *context, const void *image, size_t size, void **handle);
	void (*unload_image)(void *context, void *handle);
};

struct cdk2_pci_cardbus_socket {
	void *context;
	int (*set_power)(void *context, int enabled);
	int (*reset)(void *context);
	int (*notify)(void *context, int inserted, uint64_t generation);
	int (*bind_child)(void *context, void **child_handle);
	void (*unbind_child)(void *context, void *child_handle);
	uint64_t generation;
	uint64_t debounce_ticks;
	uint64_t last_event_tick;
	struct { uint64_t tick; uint8_t inserted; } events[8];
	uint8_t event_head, event_count;
	uint8_t present;
	uint8_t powered;
	void *child_handle;
};

struct cdk2_pci_topology {
	struct cdk2_pci_function functions[CDK2_PCI_MAX_FUNCTIONS];
	size_t count;
	struct cdk2_pci_bus_resource_request requests[4];
};

int cdk2_pci_probe_function(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *function);
int cdk2_pci_enumerate(const struct cdk2_pci_cfg *cfg, uint8_t first_bus,
	uint8_t last_bus, struct cdk2_pci_topology *topology);
int cdk2_pci_allocate_resources(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_topology *topology,
	const struct cdk2_pci_allocation_policy *policy);
int cdk2_pci_allocate_root_resources(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_topology *topology,
	const struct cdk2_pci_root_allocation *roots, size_t root_count);
int cdk2_pci_host_begin(struct cdk2_pci_bus_host_model *host,
	const struct cdk2_pci_cfg *cfg, struct cdk2_pci_topology *topology);
int cdk2_pci_host_submit(struct cdk2_pci_bus_host_model *host,
	const struct cdk2_pci_allocation_policy *proposed);
int cdk2_pci_host_allocate(struct cdk2_pci_bus_host_model *host);
int cdk2_pci_host_set(struct cdk2_pci_bus_host_model *host);
int cdk2_pci_host_end(struct cdk2_pci_bus_host_model *host);
int cdk2_pci_host_add_root(struct cdk2_pci_bus_host_model *host, uint16_t segment,
	uint8_t first_bus, uint8_t last_bus,
	const struct cdk2_pci_bus_resource_request proposed[CDK2_PCI_RESOURCE_CLASSES]);
int cdk2_pci_host_set_root_policy(struct cdk2_pci_bus_host_model *host, size_t root,
	const struct cdk2_pci_allocation_policy *policy);
int cdk2_pci_apply_hotplug(const struct cdk2_pci_hotplug_ops *ops,
	struct cdk2_pci_topology *topology,
	struct cdk2_pci_allocation_policy *policy);
int cdk2_pci_discover_option_rom(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *function);
int cdk2_pci_prepare_option_rom(const struct cdk2_pci_cfg *cfg,
	const struct cdk2_pci_rom_ops *ops, struct cdk2_pci_function *function);
void cdk2_pci_release_option_rom(const struct cdk2_pci_rom_ops *ops,
	struct cdk2_pci_function *function);
int cdk2_pci_option_rom_load_file(const struct cdk2_pci_function *function,
	unsigned int image, size_t offset, void *buffer, size_t *size);
int cdk2_pci_option_rom_load_file_path(const struct cdk2_pci_function *function,
	const void *device_path, size_t path_size, size_t offset, void *buffer,
	size_t *size);
int cdk2_pci_cardbus_insert(struct cdk2_pci_cardbus_socket *socket);
int cdk2_pci_cardbus_remove(struct cdk2_pci_cardbus_socket *socket);
int cdk2_pci_cardbus_queue_event(struct cdk2_pci_cardbus_socket *socket,
	int inserted, uint64_t tick);
int cdk2_pci_cardbus_process_event(struct cdk2_pci_cardbus_socket *socket);

#endif
