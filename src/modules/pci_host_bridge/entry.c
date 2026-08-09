/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pci_host_bridge.h>
#include <cdk2/pcd.h>

#include <string.h>

typedef uint64_t CDK2_MS_ABI install_fn(void **, const EFI_GUID *, void *, ...);
typedef uint64_t CDK2_MS_ABI allocate_fn(uint32_t, size_t, void **);
typedef uint64_t CDK2_MS_ABI free_fn(void *);
typedef uint64_t CDK2_MS_ABI locate_fn(const EFI_GUID *, void *, void **);
typedef uint64_t CDK2_MS_ABI uninstall_fn(void *, const EFI_GUID *, void *, ...);
typedef uint64_t CDK2_MS_ABI pages_fn(uint32_t, uint32_t, size_t, uint64_t *);
typedef uint64_t CDK2_MS_ABI free_pages_fn(uint64_t, size_t);
typedef uint64_t CDK2_MS_ABI gcd_allocate_fn(uint32_t, uint32_t, size_t,
	uint64_t, uint64_t *, void *, void *);
typedef uint64_t CDK2_MS_ABI gcd_free_fn(uint64_t, uint64_t);
typedef uint64_t CDK2_MS_ABI gcd_add_fn(uint32_t, uint64_t, uint64_t, ...);
typedef uint64_t CDK2_MS_ABI gcd_set_fn(uint64_t, uint64_t, uint64_t);
typedef uint64_t CDK2_MS_ABI gcd_get_map_fn(size_t *, void **);

struct gcd_memory_descriptor {
	uint64_t base, length, capabilities, attributes;
	uint32_t type, pad;
	void *image, *device;
};
struct gcd_io_descriptor {
	uint64_t base, length;
	uint32_t type, pad;
	void *image, *device;
};

struct boot_services_view {
	uint8_t before_allocate_pages[40];
	pages_fn *allocate_pages;
	free_pages_fn *free_pages;
	uint8_t before_allocate[8];
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	uint8_t before_stall[168];
	cdk2_pci_stall_fn *stall;
	uint8_t before_locate[64];
	locate_fn *locate_protocol;
	install_fn *install_multiple_protocols;
	uninstall_fn *uninstall_multiple_protocols;
};
typedef char allocate_pages_offset_check[
	offsetof(struct boot_services_view, allocate_pages) == 40 ? 1 : -1];
typedef char stall_offset_check[
	offsetof(struct boot_services_view, stall) == 248 ? 1 : -1];
typedef char locate_offset_check[
	offsetof(struct boot_services_view, locate_protocol) == 320 ? 1 : -1];
typedef char uninstall_offset_check[
	offsetof(struct boot_services_view, uninstall_multiple_protocols) == 336 ? 1 : -1];

struct cpu_io_view {
	struct {
		cdk2_pci_io_fn *read;
		cdk2_pci_io_fn *write;
	} mem, io;
};

struct iommu_view {
	uint64_t revision;
	void *set_attribute;
	cdk2_pci_iommu_map_fn *map;
	cdk2_pci_iommu_unmap_fn *unmap;
	cdk2_pci_iommu_allocate_fn *allocate;
	cdk2_pci_iommu_free_fn *free;
};

struct system_table_view {
	uint8_t header[24];
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6], *runtime;
	struct boot_services_view *boot;
	size_t table_count;
	struct { EFI_GUID guid; void *table; } *tables;
};

struct dxe_services_view {
	uint8_t header[24];
	gcd_add_fn *add_memory;
	gcd_allocate_fn *allocate_memory;
	gcd_free_fn *free_memory;
	gcd_free_fn *remove_memory;
	void *get_memory;
	gcd_set_fn *set_memory;
	gcd_get_map_fn *get_memory_map;
	gcd_add_fn *add_io;
	gcd_allocate_fn *allocate_io;
	gcd_free_fn *free_io;
	gcd_free_fn *remove_io;
	void *get_io;
	gcd_get_map_fn *get_io_map;
};

struct gcd_context {
	struct dxe_services_view *services;
	void *image;
};

struct hob_header { uint16_t type, length; uint32_t reserved; };
struct guid_hob { struct hob_header header; EFI_GUID guid; };

typedef uint64_t CDK2_MS_ABI phase_fn(void *, size_t);
typedef uint64_t CDK2_MS_ABI next_root_fn(void *, void **);
typedef uint64_t CDK2_MS_ABI attributes_fn(void *, void *, uint64_t *);
typedef uint64_t CDK2_MS_ABI configuration_fn(void *, void *, void **);
typedef uint64_t CDK2_MS_ABI set_configuration_fn(void *, void *, void *);
typedef uint64_t CDK2_MS_ABI preprocess_fn(void *, void *, uint64_t, size_t);

#pragma pack(push, 1)
struct acpi_resource {
	uint8_t descriptor;
	uint16_t length;
	uint8_t resource_type, general_flags, specific_flags;
	uint64_t granularity, minimum, maximum, translation, address_length;
};
struct acpi_end { uint8_t descriptor, checksum; };
#pragma pack(pop)

struct resource_protocol {
	phase_fn *notify_phase;
	next_root_fn *get_next_root_bridge;
	attributes_fn *get_alloc_attributes;
	configuration_fn *start_bus_enumeration;
	set_configuration_fn *set_bus_numbers, *submit_resources;
	configuration_fn *get_proposed_resources;
	preprocess_fn *preprocess_controller;
};

static struct cdk2_pci_host_model host;
static void *host_handle;
static uint8_t resource_protocol_installed;
static struct boot_services_view *boot_services;
static struct gcd_context gcd;
struct gcd_owned_range {
	uint64_t base, length;
	uint8_t memory, added, allocated;
};
static struct gcd_owned_range gcd_owned[128];
static size_t gcd_owned_count;

static uint64_t record_gcd(uint8_t memory, uint8_t added, uint8_t allocated,
	uint64_t base, uint64_t length)
{
	if (gcd_owned_count == ARRAY_SIZE(gcd_owned))
		return EFI_OUT_OF_RESOURCES;
	gcd_owned[gcd_owned_count++] = (struct gcd_owned_range){ base, length,
		memory, added, allocated };
	return EFI_SUCCESS;
}

static void rollback_gcd(void)
{
	while (gcd_owned_count != 0) {
		struct gcd_owned_range *range = &gcd_owned[--gcd_owned_count];
		gcd_free_fn *free = range->memory ? gcd.services->free_memory :
			gcd.services->free_io;
		gcd_free_fn *remove = range->memory ? gcd.services->remove_memory :
			gcd.services->remove_io;

		if (range->allocated && free != NULL)
			(void)free(range->base, range->length);
		if (range->added && remove != NULL)
			(void)remove(range->base, range->length);
	}
}
static uint64_t pci_express_base;
static struct cdk2_pci_root_io root_io[CDK2_PCI_HOST_MAX_ROOTS];
static void *root_handles[CDK2_PCI_HOST_MAX_ROOTS];

#pragma pack(push, 1)
struct root_device_path {
	uint8_t acpi_type, acpi_subtype;
	uint16_t acpi_length;
	uint32_t hid, uid;
	uint8_t end_type, end_subtype;
	uint16_t end_length;
};
#pragma pack(pop)
static struct root_device_path root_paths[CDK2_PCI_HOST_MAX_ROOTS];
typedef char root_device_path_size_check[sizeof(struct root_device_path) == 16 ? 1 : -1];

static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID root_hob_guid = {
	0xec4ebacb, 0x2638, 0x416e, { 0xbe, 0x80, 0xe5, 0xfa, 0x4b, 0x51, 0x19, 0x01 }
};
static const EFI_GUID resource_protocol_guid = {
	0xcf8034be, 0x6768, 0x4d8b, { 0xb7, 0x39, 0x7c, 0xce, 0x68, 0x3a, 0x9f, 0xbe }
};
static const EFI_GUID dxe_services_guid = {
	0x05ad34ba, 0x6f02, 0x4214, { 0x95, 0x2e, 0x4d, 0xa0, 0x39, 0x8e, 0x2b, 0xb9 }
};
static const EFI_GUID pcd_protocol_guid = {
	0x11b34006, 0xd85b, 0x4d0a, { 0xa2, 0x90, 0xd5, 0xa5, 0x71, 0x31, 0x0e, 0xf7 }
};
static const EFI_GUID pcd_info_protocol_guid = {
	0x5be40f57, 0xfa68, 0x4610, { 0xbb, 0xbf, 0xe9, 0xc5, 0xfc, 0xda, 0xd3, 0x65 }
};
static const EFI_GUID cpu_io_protocol_guid = {
	0xad61f191, 0xae5f, 0x4c0e, { 0xb9, 0xfa, 0xe8, 0x69, 0xd2, 0x88, 0xc6, 0x4f }
};
static const EFI_GUID iommu_protocol_guid = {
	0x4e939de9, 0xd948, 0x4b0f, { 0x88, 0xed, 0xe6, 0xe1, 0xce, 0x51, 0x7c, 0x1e }
};
static const EFI_GUID root_io_protocol_guid = {
	0x2f707ebb, 0x4a1a, 0x11d4, { 0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID device_path_protocol_guid = {
	0x09576e91, 0x6d3f, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b }
};

#define CDK2_PCD_PCIE_BASE_TOKEN 33U

static int is_pci_express_base_name(const char *name)
{
	static const char short_name[] = "PciExpressBaseAddress";
	static const char pcd_name[] = "PcdPciExpressBaseAddress";
	const char *component, *cursor;
	size_t length;

	if (name == NULL)
		return 0;
	component = name;
	for (cursor = name; *cursor != 0; cursor++)
		if (*cursor == '.')
			component = cursor + 1;
	length = (size_t)(cursor - component) + 1U;
	return (length == sizeof(short_name) &&
		memcmp(component, short_name, sizeof(short_name)) == 0) ||
		(length == sizeof(pcd_name) &&
		 memcmp(component, pcd_name, sizeof(pcd_name)) == 0);
}

static uint64_t discover_pci_express_base(struct boot_services_view *boot,
	uint64_t *base)
{
	struct cdk2_pcd_protocol *pcd;
	struct cdk2_get_pcd_info_protocol *info;
	struct cdk2_pcd_info description;
	size_t token = CDK2_PCD_INVALID_TOKEN;
	uint64_t status;

	if (boot == NULL || base == NULL || boot->locate_protocol == NULL)
		return EFI_UNSUPPORTED;
	status = boot->locate_protocol(&pcd_protocol_guid, NULL, (void **)&pcd);
	if (status != EFI_SUCCESS)
		return EFI_UNSUPPORTED;
	status = boot->locate_protocol(&pcd_info_protocol_guid, NULL, (void **)&info);
	if (status != EFI_SUCCESS || pcd == NULL || info == NULL ||
	    pcd->get_next_token == NULL || pcd->get64 == NULL || info->get_info == NULL)
		return EFI_UNSUPPORTED;
	for (;;) {
		status = pcd->get_next_token(NULL, &token);
		if (status != EFI_SUCCESS) {
			*base = pcd->get64(CDK2_PCD_PCIE_BASE_TOKEN);
			return *base == 0 || (*base & 0xfffffffU) != 0 ||
				*base > UINT64_MAX - 0xfffffffU ?
				EFI_UNSUPPORTED : EFI_SUCCESS;
		}
		memset(&description, 0, sizeof(description));
		status = info->get_info(token, &description);
		if (status != EFI_SUCCESS)
			return EFI_UNSUPPORTED;
		if (is_pci_express_base_name(description.pcd_name)) {
			if (description.pcd_size != sizeof(uint64_t)) {
				(void)boot->free_pool(description.pcd_name);
				return EFI_UNSUPPORTED;
			}
			*base = pcd->get64(token);
			(void)boot->free_pool(description.pcd_name);
			return *base == 0 || (*base & 0xfffffffU) != 0 ||
				*base > UINT64_MAX - 0xfffffffU ? EFI_UNSUPPORTED : EFI_SUCCESS;
		}
		if (description.pcd_name != NULL)
			(void)boot->free_pool(description.pcd_name);
	}
}

static uint64_t validate_config_backends(struct boot_services_view *boot)
{
	size_t index;
	uint8_t needs_ecam = 0;

	for (index = 0; index < host.count; index++) {
		if (host.root[index].segment != 0)
			return EFI_UNSUPPORTED;
		needs_ecam |= host.root[index].no_extended_config == 0;
	}
	if (!needs_ecam) {
		pci_express_base = 0;
		return EFI_SUCCESS;
	}
	return discover_pci_express_base(boot, &pci_express_base);
}

struct scan_context {
	struct cpu_io_view *cpu;
	uint64_t ecam;
};

static uint64_t scan_config(void *context, uint8_t bus, uint8_t device,
	uint8_t function, uint16_t offset, size_t width, uint32_t *value,
	uint8_t write)
{
	struct scan_context *scan = context;
	uint64_t address;
	size_t access_width;
	cdk2_pci_io_fn *access;

	if (scan == NULL || scan->cpu == NULL || value == NULL ||
	    (width != 1 && width != 2 && width != 4) || offset > 4095U)
		return EFI_INVALID_PARAMETER;
	address = scan->ecam + ((uint64_t)bus << 20) +
		((uint64_t)device << 15) + ((uint64_t)function << 12) + offset;
	access_width = width == 1 ? CDK2_PCI_UINT8 :
		(width == 2 ? CDK2_PCI_UINT16 : CDK2_PCI_UINT32);
	access = write ? scan->cpu->mem.write : scan->cpu->mem.read;
	return access == NULL ? EFI_UNSUPPORTED :
		access(scan->cpu, access_width, address, 1, value);
}

static uint64_t scan_read(void *context, uint8_t bus, uint8_t device,
	uint8_t function, uint16_t offset, size_t width, uint32_t *value)
{
	return scan_config(context, bus, device, function, offset, width, value, 0);
}

static uint64_t scan_write(void *context, uint8_t bus, uint8_t device,
	uint8_t function, uint16_t offset, size_t width, uint32_t *value)
{
	return scan_config(context, bus, device, function, offset, width, value, 1);
}

static size_t alignment_exponent(uint64_t mask)
{
	size_t exponent = 0;

	while (mask != 0) {
		exponent++;
		mask >>= 1;
	}
	return exponent;
}

static uint64_t CDK2_MS_ABI gcd_reserve(void *context, uint8_t memory,
	uint64_t base, uint64_t length, uint64_t alignment, uint64_t *allocated)
{
	struct gcd_context *owner = context;
	gcd_allocate_fn *function;

	if (owner == NULL || owner->services == NULL || allocated == NULL)
		return EFI_INVALID_PARAMETER;
	function = memory ? owner->services->allocate_memory :
		owner->services->allocate_io;
	if (function == NULL)
		return EFI_UNSUPPORTED;
	*allocated = base;
	return function(2U, memory ? 3U : 2U, alignment_exponent(alignment),
		length, allocated, owner->image, NULL);
}

static uint64_t CDK2_MS_ABI gcd_release(void *context, uint8_t memory,
	uint64_t base, uint64_t length)
{
	struct gcd_context *owner = context;
	gcd_free_fn *function;

	if (owner == NULL || owner->services == NULL)
		return EFI_INVALID_PARAMETER;
	function = memory ? owner->services->free_memory : owner->services->free_io;
	return function == NULL ? EFI_UNSUPPORTED : function(base, length);
}

static uint64_t add_io_aperture(struct boot_services_view *boot,
	struct dxe_services_view *services, uint64_t base, uint64_t length)
{
	struct gcd_io_descriptor *map;
	size_t count, index;
	uint64_t status = services->get_io_map(&count, (void **)&map);

	if (status != EFI_SUCCESS)
		return status;
	for (index = 0; index < count; index++) {
		uint64_t start = map[index].base > base ? map[index].base : base;
		uint64_t map_end = map[index].base + map[index].length;
		uint64_t end = map_end < base + length ? map_end : base + length;

		if (start >= end || map[index].type == 2U)
			continue;
		if (map[index].type != 0U) {
			status = EFI_INVALID_PARAMETER;
			break;
		}
		status = services->add_io(2U, start, end - start);
		if (status != EFI_SUCCESS)
			break;
		status = record_gcd(0, 1, 0, start, end - start);
		if (status != EFI_SUCCESS) {
			(void)services->remove_io(start, end - start);
			break;
		}
	}
	(void)boot->free_pool(map);
	return status;
}

static uint64_t add_memory_aperture(struct boot_services_view *boot,
	struct dxe_services_view *services, uint64_t base, uint64_t length)
{
	struct gcd_memory_descriptor *map;
	size_t count, index;
	uint64_t status = services->get_memory_map(&count, (void **)&map);

	if (status != EFI_SUCCESS)
		return status;
	for (index = 0; index < count; index++) {
		uint64_t start = map[index].base > base ? map[index].base : base;
		uint64_t map_end = map[index].base + map[index].length;
		uint64_t end = map_end < base + length ? map_end : base + length;

		if (start >= end || (map[index].type == 3U &&
		    (map[index].capabilities & 1ULL) == 1ULL))
			continue;
		if (map[index].type != 0U) {
			status = EFI_INVALID_PARAMETER;
			break;
		}
		status = services->add_memory(3U, start, end - start, 1ULL);
		if (status != EFI_SUCCESS)
			break;
		status = record_gcd(1, 1, 0, start, end - start);
		if (status != EFI_SUCCESS) {
			(void)services->remove_memory(start, end - start);
			break;
		}
	}
	(void)boot->free_pool(map);
	if (status == EFI_SUCCESS)
		(void)services->set_memory(base, length, 1ULL);
	return status;
}

static uint64_t initialize_gcd_apertures(struct boot_services_view *boot,
	struct dxe_services_view *services)
{
	size_t root, aperture;
	uint64_t status = EFI_SUCCESS;

	gcd_owned_count = 0;
	for (root = 0; root < host.count; root++)
		for (aperture = 1; aperture < CDK2_PCI_ROOT_BRIDGE_APERTURES;
		     aperture++) {
			const struct cdk2_pci_aperture *range =
				&host.root[root].aperture[aperture];
			uint64_t base, length;

			if (range->base > range->limit)
				continue;
			base = range->base - range->translation;
			length = range->limit - range->base + 1U;
			status = aperture == 1 ? add_io_aperture(boot, services,
				base, length) : add_memory_aperture(boot, services,
				base, length);
			if (status != EFI_SUCCESS)
				goto fail;
			if (host.resource_assigned) {
				uint64_t allocated = base;
				gcd_allocate_fn *allocate = aperture == 1 ?
					services->allocate_io : services->allocate_memory;

				status = allocate(2U, aperture == 1 ? 2U : 3U, 0,
					length, &allocated, gcd.image, NULL);
				if (status == EFI_SUCCESS && allocated != base) {
					(void)(aperture == 1 ? services->free_io :
						services->free_memory)(allocated, length);
					status = EFI_DEVICE_ERROR;
				}
				if (status != EFI_SUCCESS)
					goto fail;
				status = record_gcd(aperture != 1, 0, 1, base, length);
				if (status != EFI_SUCCESS)
					goto fail;
			}
		}
	return EFI_SUCCESS;
fail:
	if (status == EFI_SUCCESS)
		status = EFI_DEVICE_ERROR;
	rollback_gcd();
	return status;
}

static int same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

static uint64_t CDK2_MS_ABI notify(void *self, size_t phase)
{
	static const uint8_t aperture_index[CDK2_PCI_RESOURCE_TYPES] = {
		1, 2, 4, 3, 5
	};
	size_t root, type;
	uint64_t status;

	(void)self;
	status = cdk2_pci_host_notify(&host, (enum cdk2_pci_host_phase)phase);
	if (status != EFI_SUCCESS)
		return status;
	if (phase == CDK2_PCI_FREE_RESOURCES)
		for (root = 0; root < host.count; root++)
			for (type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++)
				(void)cdk2_pci_root_io_set_resource(&root_io[root],
					aperture_index[type], 0, 0, 0);
	if (phase == CDK2_PCI_ALLOCATE_RESOURCES)
		for (root = 0; root < host.count; root++)
			for (type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++) {
				struct cdk2_pci_resource_request *request =
					&host.request[root][type];

				if (request->allocated)
					(void)cdk2_pci_root_io_set_resource(&root_io[root],
						aperture_index[type], request->base,
						request->length, 1);
			}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI next_root(void *self, void **handle)
{
	size_t index;
	(void)self;

	if (handle == NULL)
		return EFI_INVALID_PARAMETER;
	if (*handle == NULL)
		index = 0;
	else {
		for (index = 0; index < host.count; index++)
			if (root_handles[index] == *handle)
				break;
		if (index == host.count)
			return EFI_INVALID_PARAMETER;
		index++;
	}
	if (index >= host.count)
		return EFI_NOT_FOUND;
	*handle = root_handles[index];
	return EFI_SUCCESS;
}

static uint64_t root_index(void *handle, size_t *index);

static uint64_t CDK2_MS_ABI attributes(void *self, void *handle, uint64_t *value)
{
	size_t index;
	(void)self;

	if (value == NULL || root_index(handle, &index) != EFI_SUCCESS)
		return EFI_INVALID_PARAMETER;
	*value = host.root[index].allocation_attributes;
	if (host.root[index].aperture[4].base > host.root[index].aperture[4].limit &&
	    host.root[index].aperture[5].base > host.root[index].aperture[5].limit)
		*value |= 1U;
	if (host.root[index].aperture[3].base > host.root[index].aperture[3].limit &&
	    host.root[index].aperture[5].base > host.root[index].aperture[5].limit)
		*value &= ~2U;
	return EFI_SUCCESS;
}

static uint64_t root_index(void *handle, size_t *index)
{
	size_t candidate;

	if (index == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	for (candidate = 0; candidate < host.count; candidate++)
		if (root_handles[candidate] == handle) {
			*index = candidate;
			return EFI_SUCCESS;
		}
	return EFI_INVALID_PARAMETER;
}

static uint64_t allocate_descriptors(size_t count, void **configuration)
{
	if (configuration == NULL || boot_services == NULL ||
	    boot_services->allocate_pool == NULL)
		return EFI_INVALID_PARAMETER;
	return boot_services->allocate_pool(4U,
		count * sizeof(struct acpi_resource) + sizeof(struct acpi_end),
		configuration);
}

static void end_descriptors(struct acpi_resource *resource, size_t count)
{
	struct acpi_end *end = (struct acpi_end *)(resource + count);

	end->descriptor = 0x79;
	end->checksum = 0;
}

static uint64_t CDK2_MS_ABI start_bus(void *self, void *handle,
	void **configuration)
{
	struct acpi_resource *resource;
	size_t index;
	uint64_t status;
	(void)self;

	status = root_index(handle, &index);
	if (status != EFI_SUCCESS)
		return status;
	status = allocate_descriptors(1, configuration);
	if (status != EFI_SUCCESS)
		return status;
	resource = *configuration;
	memset(resource, 0, sizeof(*resource) + sizeof(struct acpi_end));
	resource->descriptor = 0x8a;
	resource->length = sizeof(*resource) - 3U;
	resource->resource_type = 2;
	resource->minimum = host.root[index].aperture[0].base;
	resource->address_length = host.root[index].aperture[0].limit -
		host.root[index].aperture[0].base + 1U;
	end_descriptors(resource, 1);
	return EFI_SUCCESS;
}

static uint64_t validate_resource(const struct acpi_resource *resource)
{
	return resource->descriptor == 0x8a &&
		resource->length == sizeof(*resource) - 3U ? EFI_SUCCESS :
		EFI_INVALID_PARAMETER;
}

static uint64_t CDK2_MS_ABI set_bus(void *self, void *handle, void *configuration)
{
	struct acpi_resource *resource = configuration;
	struct acpi_end *end;
	size_t index;
	uint64_t status, limit;
	(void)self;

	status = root_index(handle, &index);
	if (status != EFI_SUCCESS || resource == NULL ||
	    validate_resource(resource) != EFI_SUCCESS || resource->resource_type != 2 ||
	    resource->address_length == 0 || resource->minimum > UINT64_MAX -
		(resource->address_length - 1U))
		return EFI_INVALID_PARAMETER;
	end = (struct acpi_end *)(resource + 1);
	if (end->descriptor != 0x79)
		return EFI_INVALID_PARAMETER;
	limit = resource->minimum + resource->address_length - 1U;
	if (resource->minimum < host.root[index].aperture[0].base ||
	    limit > host.root[index].aperture[0].limit)
		return EFI_INVALID_PARAMETER;
	host.root[index].aperture[0].base = resource->minimum;
	host.root[index].aperture[0].limit = limit;
	return cdk2_pci_root_io_set_resource(&root_io[index], 0,
		resource->minimum, resource->address_length, 1);
}

static size_t resource_type(const struct acpi_resource *resource)
{
	if (resource->resource_type == 1)
		return 0;
	if (resource->resource_type != 0)
		return CDK2_PCI_RESOURCE_TYPES;
	if (resource->granularity == 32)
		return (resource->specific_flags & 0x06U) == 0x06U ? 2 : 1;
	if (resource->granularity == 64)
		return (resource->specific_flags & 0x06U) == 0x06U ? 4 : 3;
	return CDK2_PCI_RESOURCE_TYPES;
}

static uint64_t validate_submission(const struct acpi_resource *resource,
	size_t root)
{
	uint64_t boundary;
	size_t type = resource_type(resource);

	if (validate_resource(resource) != EFI_SUCCESS ||
	    type >= CDK2_PCI_RESOURCE_TYPES || resource->maximum == UINT64_MAX)
		return EFI_INVALID_PARAMETER;
	boundary = resource->maximum + 1U;
	if ((boundary & (boundary - 1U)) != 0)
		return EFI_INVALID_PARAMETER;
	if (resource->resource_type == 0 && resource->granularity == 32 &&
	    resource->address_length >= ((uint64_t)1 << 32))
		return EFI_INVALID_PARAMETER;
	if ((host.root[root].allocation_attributes & 1U) != 0 &&
	    (resource->specific_flags & 0x06U) != 0)
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI submit(void *self, void *handle, void *configuration)
{
	struct acpi_resource *resource = configuration;
	size_t index, count, type, submitted = 0;
	uint64_t status;
	(void)self;

	status = root_index(handle, &index);
	if (status != EFI_SUCCESS || resource == NULL)
		return EFI_INVALID_PARAMETER;
	for (count = 0; count < CDK2_PCI_RESOURCE_TYPES; count++, resource++) {
		if (*(uint8_t *)resource == 0x79)
			break;
		if (validate_submission(resource, index) != EFI_SUCCESS)
			return EFI_INVALID_PARAMETER;
	}
	if (*(uint8_t *)resource != 0x79)
		return EFI_INVALID_PARAMETER;
	resource = configuration;
	for (count = 0; *(uint8_t *)resource != 0x79; count++, resource++) {
		type = resource_type(resource);
		status = cdk2_pci_host_submit(&host, index, type,
			resource->address_length, resource->maximum);
		if (status != EFI_SUCCESS)
			return status;
		submitted |= (size_t)1U << type;
	}
	for (type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++)
		if ((submitted & ((size_t)1U << type)) == 0) {
			host.request[index][type].length = 0;
			host.request[index][type].alignment = 0;
			host.request[index][type].base = 0;
			host.request[index][type].submitted = 0;
			host.request[index][type].allocated = 0;
		}
	host.resource_submitted[index] = 1;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI proposed(void *self, void *handle,
	void **configuration)
{
	struct acpi_resource *resource;
	size_t index, type, count = 0;
	uint64_t status;
	(void)self;

	status = root_index(handle, &index);
	if (status != EFI_SUCCESS)
		return status;
	for (type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++)
		count += host.request[index][type].submitted;
	status = allocate_descriptors(count, configuration);
	if (status != EFI_SUCCESS)
		return status;
	resource = *configuration;
	memset(resource, 0, count * sizeof(*resource) + sizeof(struct acpi_end));
	count = 0;
	for (type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++) {
		struct cdk2_pci_resource_request *request = &host.request[index][type];

		if (!request->submitted)
			continue;
		resource[count].descriptor = 0x8a;
		resource[count].length = sizeof(*resource) - 3U;
		resource[count].resource_type = type == 0 ? 1 : 0;
		resource[count].granularity = type == 1 || type == 2 ? 32 :
			type == 0 ? 0 : 64;
		resource[count].specific_flags = type == 2 || type == 4 ? 0x06 : 0;
		resource[count].minimum = request->base;
		resource[count].translation = request->allocated ? 0 :
			0xfffffffffffffffeULL;
		resource[count].address_length = request->length;
		count++;
	}
	end_descriptors(resource, count);
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI preprocess(void *self, void *handle,
	uint64_t address, size_t phase)
{
	size_t index;
	(void)self;
	(void)address;
	(void)phase;
	return root_index(handle, &index);
}

static struct resource_protocol protocol = {
	notify, next_root, attributes, start_bus, set_bus, submit, proposed, preprocess
};

static void initialize_root_path(size_t index)
{
	root_paths[index].acpi_type = 2;
	root_paths[index].acpi_subtype = 1;
	root_paths[index].acpi_length = 12;
	root_paths[index].hid = host.root[index].hid;
	root_paths[index].uid = host.root[index].uid;
	root_paths[index].end_type = 0x7f;
	root_paths[index].end_subtype = 0xff;
	root_paths[index].end_length = 4;
}

static void rollback_publication(struct boot_services_view *boot, size_t count)
{
	while (count != 0) {
		count--;
		(void)boot->uninstall_multiple_protocols(root_handles[count],
			&device_path_protocol_guid, &root_paths[count],
			&root_io_protocol_guid, &root_io[count], NULL);
		root_handles[count] = NULL;
	}
	if (resource_protocol_installed && host_handle != NULL) {
		(void)boot->uninstall_multiple_protocols(host_handle,
			&resource_protocol_guid, &protocol, NULL);
		host_handle = NULL;
		resource_protocol_installed = 0;
	}
}

static uint64_t publish_protocols(struct boot_services_view *boot)
{
	struct cdk2_pci_root_io_services services;
	struct cpu_io_view *cpu = NULL;
	struct iommu_view *iommu = NULL;
	size_t index;
	uint64_t status;

	if (boot->locate_protocol == NULL || boot->uninstall_multiple_protocols == NULL ||
	    boot->allocate_pages == NULL || boot->free_pages == NULL || boot->stall == NULL)
		return EFI_UNSUPPORTED;
	status = boot->locate_protocol(&cpu_io_protocol_guid, NULL, (void **)&cpu);
	if (status != EFI_SUCCESS || cpu == NULL || cpu->mem.read == NULL ||
	    cpu->mem.write == NULL || cpu->io.read == NULL || cpu->io.write == NULL)
		return EFI_UNSUPPORTED;
	(void)boot->locate_protocol(&iommu_protocol_guid, NULL, (void **)&iommu);
	memset(&services, 0, sizeof(services));
	services.cpu = cpu;
	services.mem_read = cpu->mem.read;
	services.mem_write = cpu->mem.write;
	services.io_read = cpu->io.read;
	services.io_write = cpu->io.write;
	services.stall = boot->stall;
	services.allocate_pages = boot->allocate_pages;
	services.free_pages = boot->free_pages;
	services.allocate_pool = boot->allocate_pool;
	services.free_pool = boot->free_pool;
	if (iommu != NULL) {
		services.iommu = iommu;
		services.iommu_map = iommu->map;
		services.iommu_unmap = iommu->unmap;
		services.iommu_allocate = iommu->allocate;
		services.iommu_free = iommu->free;
	}
	memset(root_handles, 0, sizeof(root_handles));
	host_handle = NULL;
	resource_protocol_installed = 0;
	status = boot->install_multiple_protocols(&host_handle,
		&resource_protocol_guid, &protocol, NULL);
	if (status != EFI_SUCCESS)
		return status;
	resource_protocol_installed = 1;
	for (index = 0; index < host.count; index++) {
		status = cdk2_pci_root_io_init(&root_io[index], &host.root[index],
			pci_express_base, &services, host_handle, host.resource_assigned);
		if (status != EFI_SUCCESS)
			goto fail;
		initialize_root_path(index);
		status = boot->install_multiple_protocols(&root_handles[index],
			&device_path_protocol_guid, &root_paths[index],
			&root_io_protocol_guid, &root_io[index], NULL);
		if (status != EFI_SUCCESS)
			goto fail;
	}
	return EFI_SUCCESS;
fail:
	if (index < host.count)
		root_handles[index] = NULL;
	rollback_publication(boot, index);
	return status;
}

uint64_t CDK2_MS_ABI cdk2_pci_host_bridge_entry(void *image, void *system)
{
	struct system_table_view *table = system;
	struct hob_header *hob = NULL;
	struct dxe_services_view *dxe = NULL;
	size_t index;
	uint64_t status;

	if (image == NULL || table == NULL || table->boot == NULL ||
	    table->boot->allocate_pool == NULL || table->boot->free_pool == NULL ||
	    table->boot->install_multiple_protocols == NULL ||
	    (table->table_count != 0 && table->tables == NULL))
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < table->table_count; index++) {
		if (same_guid(&table->tables[index].guid, &hob_list_guid)) {
			hob = table->tables[index].table;
		}
		if (same_guid(&table->tables[index].guid, &dxe_services_guid)) {
			dxe = table->tables[index].table;
		}
	}
	if (dxe == NULL || dxe->add_memory == NULL || dxe->allocate_memory == NULL ||
	    dxe->free_memory == NULL || dxe->remove_memory == NULL ||
	    dxe->set_memory == NULL ||
	    dxe->get_memory_map == NULL || dxe->add_io == NULL ||
	    dxe->allocate_io == NULL || dxe->free_io == NULL || dxe->remove_io == NULL ||
	    dxe->get_io_map == NULL)
		return EFI_NOT_FOUND;
	while (hob != NULL && hob->type != 0xffffU) {
		struct guid_hob *guid = (struct guid_hob *)hob;

		if (hob->length < sizeof(*hob) || (hob->length & 7U) != 0)
			return EFI_COMPROMISED_DATA;
		if (hob->type == 4U && hob->length >= sizeof(*guid) &&
		    same_guid(&guid->guid, &root_hob_guid)) {
			status = cdk2_pci_host_init(&host, guid + 1,
				hob->length - sizeof(*guid));
			if (status != EFI_SUCCESS)
				return status;
			status = validate_config_backends(table->boot);
			if (status != EFI_SUCCESS)
				return status;
			gcd.services = dxe;
			gcd.image = image;
			status = cdk2_pci_host_set_allocator(&host, &gcd, gcd_reserve,
				gcd_release);
			if (status != EFI_SUCCESS)
				return status;
			boot_services = table->boot;
			status = initialize_gcd_apertures(table->boot, dxe);
			if (status != EFI_SUCCESS)
				return status;
			status = publish_protocols(table->boot);
			if (status != EFI_SUCCESS)
				rollback_gcd();
			return status;
		}
		hob = (struct hob_header *)((uint8_t *)hob + hob->length);
	}
	{
		struct scan_context scan;

		memset(&scan, 0, sizeof(scan));
		status = discover_pci_express_base(table->boot, &scan.ecam);
		if (status != EFI_SUCCESS)
			return status;
		status = table->boot->locate_protocol(&cpu_io_protocol_guid, NULL,
			(void **)&scan.cpu);
		if (status != EFI_SUCCESS || scan.cpu == NULL)
			return EFI_UNSUPPORTED;
		status = cdk2_pci_host_scan(&host, &scan, scan_read, scan_write);
		if (status != EFI_SUCCESS)
			return status;
		pci_express_base = scan.ecam;
		gcd.services = dxe;
		gcd.image = image;
		status = cdk2_pci_host_set_allocator(&host, &gcd, gcd_reserve,
			gcd_release);
		if (status != EFI_SUCCESS)
			return status;
		boot_services = table->boot;
		status = initialize_gcd_apertures(table->boot, dxe);
		if (status != EFI_SUCCESS)
			return status;
		status = publish_protocols(table->boot);
		if (status != EFI_SUCCESS)
			rollback_gcd();
		return status;
	}
}
