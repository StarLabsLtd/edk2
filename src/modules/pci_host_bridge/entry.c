/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pci_host_bridge.h>

#include <string.h>

typedef uint64_t CDK2_MS_ABI install_fn(void **, const EFI_GUID *, void *, ...);

struct boot_services_view {
	uint8_t before_install[328];
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

struct hob_header { uint16_t type, length; uint32_t reserved; };
struct guid_hob { struct hob_header header; EFI_GUID guid; };

typedef uint64_t CDK2_MS_ABI phase_fn(void *, size_t);
typedef uint64_t CDK2_MS_ABI next_root_fn(void *, void **);
typedef uint64_t CDK2_MS_ABI attributes_fn(void *, void *, uint64_t *);
typedef uint64_t CDK2_MS_ABI unsupported_fn(void);

struct resource_protocol {
	phase_fn *notify_phase;
	next_root_fn *get_next_root_bridge;
	attributes_fn *get_alloc_attributes;
	unsupported_fn *start_bus_enumeration, *set_bus_numbers, *submit_resources;
	unsupported_fn *get_proposed_resources, *preprocess_controller;
};

static struct cdk2_pci_host_model host;
static void *host_handle;

static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID root_hob_guid = {
	0xec4ebacb, 0x2638, 0x416e, { 0xbe, 0x80, 0xe5, 0xfa, 0x4b, 0x51, 0x19, 0x01 }
};
static const EFI_GUID resource_protocol_guid = {
	0xcf8034be, 0x6768, 0x4d8b, { 0xb7, 0x39, 0x7c, 0xce, 0x68, 0x3a, 0x9f, 0xbe }
};

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

static uint64_t CDK2_MS_ABI unsupported(void)
{
	return EFI_UNSUPPORTED;
}

static struct resource_protocol protocol = {
	notify, next_root, attributes, unsupported, unsupported, unsupported,
	unsupported, unsupported
};

uint64_t CDK2_MS_ABI cdk2_pci_host_bridge_entry(void *image, void *system)
{
	struct system_table_view *table = system;
	struct hob_header *hob = NULL;
	size_t index;
	uint64_t status;

	(void)image;
	if (table == NULL || table->boot == NULL ||
	    table->boot->install_multiple_protocols == NULL ||
	    (table->table_count != 0 && table->tables == NULL))
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < table->table_count; index++)
		if (same_guid(&table->tables[index].guid, &hob_list_guid)) {
			hob = table->tables[index].table;
			break;
		}
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
			return table->boot->install_multiple_protocols(&host_handle,
				&resource_protocol_guid, &protocol, NULL);
		}
		hob = (struct hob_header *)((uint8_t *)hob + hob->length);
	}
	return EFI_NOT_FOUND;
}
