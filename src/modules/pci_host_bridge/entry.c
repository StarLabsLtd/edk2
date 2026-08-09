/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pci_host_bridge.h>

#include <string.h>

typedef uint64_t CDK2_MS_ABI install_fn(void **, const EFI_GUID *, void *, ...);
typedef uint64_t CDK2_MS_ABI allocate_fn(uint32_t, size_t, void **);
typedef uint64_t CDK2_MS_ABI free_fn(void *);
typedef uint64_t CDK2_MS_ABI gcd_allocate_fn(uint32_t, uint32_t, size_t,
	uint64_t, uint64_t *, void *, void *);
typedef uint64_t CDK2_MS_ABI gcd_free_fn(uint64_t, uint64_t);

struct boot_services_view {
	uint8_t before_allocate[64];
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	uint8_t before_install[248];
	install_fn *install_multiple_protocols;
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
	void *add_memory;
	gcd_allocate_fn *allocate_memory;
	gcd_free_fn *free_memory;
	void *remove_memory, *get_memory, *set_memory, *get_memory_map, *add_io;
	gcd_allocate_fn *allocate_io;
	gcd_free_fn *free_io;
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
static struct boot_services_view *boot_services;
static struct gcd_context gcd;

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

static int same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

static uint64_t CDK2_MS_ABI notify(void *self, size_t phase)
{
	(void)self;
	return cdk2_pci_host_notify(&host, (enum cdk2_pci_host_phase)phase);
}

static uint64_t CDK2_MS_ABI next_root(void *self, void **handle)
{
	uintptr_t index;
	(void)self;

	if (handle == NULL)
		return EFI_INVALID_PARAMETER;
	if (*handle == NULL)
		index = 0;
	else {
		index = (uintptr_t)*handle;
		if (index == 0 || index > host.count)
			return EFI_INVALID_PARAMETER;
	}
	if (index >= host.count)
		return EFI_NOT_FOUND;
	*handle = (void *)(index + 1U);
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI attributes(void *self, void *handle, uint64_t *value)
{
	uintptr_t index = (uintptr_t)handle;
	(void)self;

	if (value == NULL || index == 0 || index > host.count)
		return EFI_INVALID_PARAMETER;
	*value = host.root[index - 1U].allocation_attributes;
	return EFI_SUCCESS;
}

static uint64_t root_index(void *handle, size_t *index)
{
	uintptr_t value = (uintptr_t)handle;

	if (index == NULL || value == 0 || value > host.count)
		return EFI_INVALID_PARAMETER;
	*index = value - 1U;
	return EFI_SUCCESS;
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
	return EFI_SUCCESS;
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
			status = cdk2_pci_host_submit(&host, index, type, 0, 0);
			if (status != EFI_SUCCESS)
				return status;
		}
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
		if (same_guid(&table->tables[index].guid, &dxe_services_guid))
			dxe = table->tables[index].table;
	}
	if (dxe == NULL || dxe->allocate_memory == NULL || dxe->free_memory == NULL ||
	    dxe->allocate_io == NULL || dxe->free_io == NULL)
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
			gcd.services = dxe;
			gcd.image = image;
			status = cdk2_pci_host_set_allocator(&host, &gcd, gcd_reserve,
				gcd_release);
			if (status != EFI_SUCCESS)
				return status;
			boot_services = table->boot;
			return table->boot->install_multiple_protocols(&host_handle,
				&resource_protocol_guid, &protocol, NULL);
		}
		hob = (struct hob_header *)((uint8_t *)hob + hob->length);
	}
	return EFI_NOT_FOUND;
}
