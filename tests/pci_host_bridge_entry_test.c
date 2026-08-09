/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t CDK2_MS_ABI cdk2_pci_host_bridge_entry(void *, void *);

static void *installed;
static unsigned int allocations, frees;

static uint64_t CDK2_MS_ABI install(void **handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)guid;
	*handle = (void *)0x55;
	installed = interface;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI allocate(uint32_t type, size_t size, void **buffer)
{
	(void)type;
	*buffer = calloc(1, size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI release(void *buffer)
{
	free(buffer);
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI gcd_allocate(uint32_t allocation, uint32_t type,
	size_t alignment, uint64_t length, uint64_t *base, void *image, void *device)
{
	(void)device;
	if (allocation != 2 || image != (void *)0x44 || length == 0 ||
	    alignment > 63 || (type != 2 && type != 3))
		return EFI_INVALID_PARAMETER;
	allocations++;
	return (*base & (((uint64_t)1 << alignment) - 1U)) == 0 ? EFI_SUCCESS :
		EFI_NOT_FOUND;
}

static uint64_t CDK2_MS_ABI gcd_free(uint64_t base, uint64_t length)
{
	(void)base;
	if (length == 0)
		return EFI_INVALID_PARAMETER;
	frees++;
	return EFI_SUCCESS;
}

struct boot_view {
	uint8_t pad[64]; void *allocate, *release; uint8_t before_install[248];
	void *install;
};
struct config_view { EFI_GUID guid; void *table; };
struct dxe_view {
	uint8_t header[24]; void *add_memory, *allocate_memory, *free_memory;
	void *remove_memory, *get_memory, *set_memory, *get_memory_map, *add_io;
	void *allocate_io, *free_io;
};
struct system_view {
	uint8_t header[24]; uint16_t *vendor; uint32_t revision, pad;
	void *console[6], *runtime; struct boot_view *boot;
	size_t count; struct config_view *tables;
};
struct protocol_view {
	uint64_t (CDK2_MS_ABI *notify)(void *, size_t);
	uint64_t (CDK2_MS_ABI *next)(void *, void **);
	uint64_t (CDK2_MS_ABI *attributes)(void *, void *, uint64_t *);
	uint64_t (CDK2_MS_ABI *start_bus)(void *, void *, void **);
	uint64_t (CDK2_MS_ABI *set_bus)(void *, void *, void *);
	uint64_t (CDK2_MS_ABI *submit)(void *, void *, void *);
	uint64_t (CDK2_MS_ABI *proposed)(void *, void *, void **);
	void *preprocess;
};
#pragma pack(push, 1)
struct resource_view {
	uint8_t descriptor; uint16_t length;
	uint8_t type, general, specific;
	uint64_t granularity, minimum, maximum, translation, address_length;
};
struct end_view { uint8_t descriptor, checksum; };
#pragma pack(pop)
struct hob_fixture {
	struct { uint16_t type, length; uint32_t reserved; } header;
	EFI_GUID guid;
	struct {
		struct cdk2_pci_root_bridges_hob header;
		struct cdk2_pci_root_bridge_record bridge;
		uint8_t padding[4];
	} payload;
	struct { uint16_t type, length; uint32_t reserved; } end;
};

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "pci host bridge entry test: %s\n", message);
	return condition ? 0 : 1;
}

int main(void)
{
	static const EFI_GUID hob_list = {
		0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
	};
	static const EFI_GUID root_hob = {
		0xec4ebacb, 0x2638, 0x416e, { 0xbe, 0x80, 0xe5, 0xfa, 0x4b, 0x51, 0x19, 0x01 }
	};
	static const EFI_GUID dxe_guid = {
		0x05ad34ba, 0x6f02, 0x4214, { 0x95, 0x2e, 0x4d, 0xa0, 0x39, 0x8e, 0x2b, 0xb9 }
	};
	struct hob_fixture hob;
	struct boot_view boot;
	struct config_view config[2];
	struct dxe_view dxe;
	struct system_view system;
	struct protocol_view *protocol;
	void *root = NULL;
	uint64_t attributes;
	void *configuration;
	int failures = 0;

	memset(&hob, 0, sizeof(hob));
	hob.header.type = 4;
	hob.header.length = offsetof(struct hob_fixture, end);
	hob.guid = root_hob;
	hob.payload.header.header.revision = CDK2_PCI_ROOT_BRIDGES_REVISION;
	hob.payload.header.header.length = sizeof(hob.payload) - sizeof(hob.payload.padding);
	hob.payload.header.count = 1;
	hob.payload.bridge.allocation_attributes = 0x1234;
	hob.payload.bridge.aperture[0].limit = 0xff;
	hob.payload.bridge.aperture[2].base = 0x80000000;
	hob.payload.bridge.aperture[2].limit = 0x800fffff;
	hob.end.type = 0xffff;
	hob.end.length = sizeof(hob.end);
	memset(&boot, 0, sizeof(boot));
	boot.allocate = allocate;
	boot.release = release;
	boot.install = install;
	memset(&dxe, 0, sizeof(dxe));
	dxe.allocate_memory = gcd_allocate;
	dxe.free_memory = gcd_free;
	dxe.allocate_io = gcd_allocate;
	dxe.free_io = gcd_free;
	config[0].guid = hob_list;
	config[0].table = &hob;
	config[1].guid = dxe_guid;
	config[1].table = &dxe;
	memset(&system, 0, sizeof(system));
	system.boot = &boot;
	system.count = 2;
	system.tables = config;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) == EFI_SUCCESS &&
		installed != NULL, "valid root-bridge hob was not published");
	protocol = installed;
	failures += expect(protocol->next(protocol, &root) == EFI_SUCCESS && root != NULL &&
		protocol->attributes(protocol, root, &attributes) == EFI_SUCCESS &&
		attributes == 0x1234 && protocol->next(protocol, &root) == EFI_NOT_FOUND,
		"published host-bridge enumeration ABI failed");
	failures += expect(protocol->notify(protocol, CDK2_PCI_BEGIN_BUS_ALLOCATION) ==
		EFI_SUCCESS && protocol->notify(protocol, CDK2_PCI_BEGIN_ENUMERATION) ==
		EFI_NOT_READY, "published phase ABI did not enforce restart semantics");
	failures += expect(protocol->start_bus(protocol, (void *)1, &configuration) ==
		EFI_SUCCESS && ((struct resource_view *)configuration)->type == 2 &&
		((struct end_view *)((struct resource_view *)configuration + 1))->descriptor ==
		0x79, "bus-enumeration descriptor was not produced");
	failures += expect(protocol->set_bus(protocol, (void *)1, configuration) ==
		EFI_SUCCESS, "valid bus range was not accepted");
	(void)release(configuration);
	{
		struct { struct resource_view resource; struct end_view end; } request;

		memset(&request, 0, sizeof(request));
		request.resource.descriptor = 0x8a;
		request.resource.length = sizeof(request.resource) - 3;
		request.resource.type = 0;
		request.resource.granularity = 32;
		request.resource.maximum = 0xfff;
		request.resource.address_length = 0x100;
		request.end.descriptor = 0x79;
		failures += expect(protocol->submit(protocol, (void *)1, &request) ==
			EFI_SUCCESS && protocol->notify(protocol,
			CDK2_PCI_ALLOCATE_RESOURCES) == EFI_SUCCESS && allocations == 1,
			"descriptor submission did not reserve through GCD");
		failures += expect(protocol->proposed(protocol, (void *)1,
			&configuration) == EFI_SUCCESS &&
			((struct resource_view *)configuration)[1].type == 0 &&
			((struct resource_view *)configuration)[1].translation == 0,
			"allocated proposal did not report EFI_RESOURCE_SATISFIED");
		(void)release(configuration);
		failures += expect(protocol->notify(protocol, CDK2_PCI_FREE_RESOURCES) ==
			EFI_SUCCESS && frees == 1, "GCD allocation was not released");
	}
	hob.payload.header.header.revision++;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_COMPROMISED_DATA, "malformed handoff was published");
	return failures == 0 ? 0 : 1;
}
