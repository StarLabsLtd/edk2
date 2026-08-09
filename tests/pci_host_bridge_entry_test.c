/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>
#include <cdk2/pcd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t CDK2_MS_ABI cdk2_pci_host_bridge_entry(void *, void *);

static void *installed;
static unsigned int allocations, frees, installs;
static int provide_pcd;
static int provide_pcd_names = 1;
static unsigned int uninstalls;
static unsigned int gcd_memory_adds, gcd_io_adds;
static unsigned int gcd_removes, fail_gcd_add_on;
static unsigned int fail_install_on;
static void *published_path;

static uint64_t CDK2_MS_ABI install(void **handle, const EFI_GUID *guid,
	void *interface, ...)
{
	if (fail_install_on != 0 && installs + 1U == fail_install_on) {
		installs++;
		return EFI_OUT_OF_RESOURCES;
	}
	*handle = (void *)(uintptr_t)(0x55 + installs);
	if (guid->data1 == 0xcf8034be)
		installed = interface;
	if (guid->data1 == 0x09576e91) {
		published_path = interface;
	}
	installs++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI uninstall(void *handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)handle; (void)guid; (void)interface;
	uninstalls++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI pages(uint32_t type, uint32_t memory, size_t count,
	uint64_t *address)
{ (void)type; (void)memory; (void)count; (void)address; return EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI free_page(uint64_t address, size_t count)
{ (void)address; (void)count; return EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI delay(size_t microseconds)
{ (void)microseconds; return EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI cpu_access(void *self, size_t width,
	uint64_t address, size_t count, void *buffer)
{ (void)self; (void)width; (void)address; (void)count; (void)buffer; return EFI_SUCCESS; }
struct cpu_view { struct { void *read, *write; } mem, io; };
static struct cpu_view cpu = {
	{ cpu_access, cpu_access }, { cpu_access, cpu_access }
};

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

static uint64_t CDK2_MS_ABI gcd_add(uint32_t type, uint64_t base,
	uint64_t length, ...)
{
	(void)base;
	if (gcd_memory_adds + gcd_io_adds + 1U == fail_gcd_add_on)
		return EFI_OUT_OF_RESOURCES;
	if (type == 2U)
		gcd_io_adds++;
	if (type == 3U)
		gcd_memory_adds++;
	return (type == 2U || type == 3U) && length != 0 ? EFI_SUCCESS :
		EFI_INVALID_PARAMETER;
}

static uint64_t CDK2_MS_ABI gcd_remove(uint64_t base, uint64_t length)
{
	(void)base;
	if (length == 0)
		return EFI_INVALID_PARAMETER;
	gcd_removes++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI gcd_set(uint64_t base, uint64_t length,
	uint64_t attributes)
{
	(void)base;
	return length != 0 && attributes == 1U ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

struct memory_map_view {
	uint64_t base, length, capabilities, attributes;
	uint32_t type, pad;
	void *image, *device;
};
struct io_map_view {
	uint64_t base, length;
	uint32_t type, pad;
	void *image, *device;
};

static uint64_t CDK2_MS_ABI memory_map(size_t *count, void **map)
{
	struct memory_map_view *entry = calloc(1, sizeof(*entry));

	if (entry == NULL)
		return EFI_OUT_OF_RESOURCES;
	entry->length = UINT64_MAX;
	*count = 1; *map = entry;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI io_map(size_t *count, void **map)
{
	struct io_map_view *entry = calloc(1, sizeof(*entry));

	if (entry == NULL)
		return EFI_OUT_OF_RESOURCES;
	entry->length = UINT64_MAX;
	*count = 1; *map = entry;
	return EFI_SUCCESS;
}

struct boot_view {
	uint8_t pad[40]; void *pages, *free_pages; uint8_t before_pool[8];
	void *allocate, *release; uint8_t before_stall[168]; void *stall;
	uint8_t before_locate[64];
	void *locate, *install, *uninstall;
};
struct config_view { EFI_GUID guid; void *table; };
struct dxe_view {
	uint8_t header[24]; void *add_memory, *allocate_memory, *free_memory;
	void *remove_memory, *get_memory, *set_memory, *get_memory_map, *add_io;
	void *allocate_io, *free_io, *remove_io, *get_io, *get_io_map;
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

static uint64_t CDK2_MS_ABI pcd_next(const EFI_GUID *space, size_t *token)
{
	(void)space;
	if (!provide_pcd_names)
		return EFI_NOT_FOUND;
	if (*token != 0)
		return EFI_NOT_FOUND;
	*token = 7;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI pcd_info(size_t token, struct cdk2_pcd_info *info)
{
	static const char name[] = "gEfiMdePkgTokenSpaceGuid.PcdPciExpressBaseAddress";

	if (token != 7)
		return EFI_NOT_FOUND;
	info->pcd_size = sizeof(uint64_t);
	info->pcd_name = malloc(sizeof(name));
	if (info->pcd_name == NULL)
		return EFI_OUT_OF_RESOURCES;
	memcpy(info->pcd_name, name, sizeof(name));
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI pcd_get64(size_t token)
{
	return token == 7 || token == 33 ? 0xe0000000ULL : 0;
}

static struct cdk2_pcd_protocol pcd = { .get64 = pcd_get64,
	.get_next_token = pcd_next };
static struct cdk2_get_pcd_info_protocol pcd_info_protocol = {
	.get_info = pcd_info
};

static uint64_t CDK2_MS_ABI locate(const EFI_GUID *guid, void *registration,
	void **interface)
{
	(void)registration;
	if (guid->data1 == 0xad61f191) {
		*interface = &cpu;
		return EFI_SUCCESS;
	}
	if (guid->data1 == 0x4e939de9)
		return EFI_NOT_FOUND;
	if (!provide_pcd)
		return EFI_NOT_FOUND;
	if (guid->data1 == 0x11b34006)
		*interface = &pcd;
	else if (guid->data1 == 0x5be40f57)
		*interface = &pcd_info_protocol;
	else
		return EFI_NOT_FOUND;
	return EFI_SUCCESS;
}

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
	hob.payload.bridge.no_extended_config = 1;
	hob.payload.bridge.aperture[0].limit = 0xff;
	hob.payload.bridge.aperture[1].base = 0x1000;
	hob.payload.bridge.aperture[1].limit = 0x1fff;
	hob.payload.bridge.aperture[2].base = 0x80000000;
	hob.payload.bridge.aperture[2].limit = 0x800fffff;
	for (size_t aperture = 3; aperture < CDK2_PCI_ROOT_BRIDGE_APERTURES;
	     aperture++) {
		hob.payload.bridge.aperture[aperture].base = 1;
		hob.payload.bridge.aperture[aperture].limit = 0;
	}
	hob.end.type = 0xffff;
	hob.end.length = sizeof(hob.end);
	memset(&boot, 0, sizeof(boot));
	boot.pages = pages;
	boot.free_pages = free_page;
	boot.allocate = allocate;
	boot.release = release;
	boot.stall = delay;
	boot.locate = locate;
	boot.install = install;
	boot.uninstall = uninstall;
	memset(&dxe, 0, sizeof(dxe));
	dxe.add_memory = gcd_add;
	dxe.allocate_memory = gcd_allocate;
	dxe.free_memory = gcd_free;
	dxe.remove_memory = gcd_remove;
	dxe.set_memory = gcd_set;
	dxe.get_memory_map = memory_map;
	dxe.add_io = gcd_add;
	dxe.allocate_io = gcd_allocate;
	dxe.free_io = gcd_free;
	dxe.remove_io = gcd_remove;
	dxe.get_io_map = io_map;
	config[0].guid = hob_list;
	config[0].table = &hob;
	config[1].guid = dxe_guid;
	config[1].table = &dxe;
	memset(&system, 0, sizeof(system));
	system.boot = &boot;
	system.count = 2;
	system.tables = config;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) == EFI_SUCCESS &&
		installed != NULL && published_path != NULL &&
		*(uint8_t *)published_path == 2,
		"host, root I/O, and ACPI device path were not atomically published");
	failures += expect(gcd_io_adds == 1 && gcd_memory_adds == 1,
		"root apertures were not registered in the GCD maps before publication");
	protocol = installed;
	hob.payload.header.resource_assigned = 1;
	installed = NULL;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_SUCCESS && installed != NULL,
		"assigned roots did not retain the host resource protocol");
	hob.payload.header.resource_assigned = 0;
	protocol = installed;
	{
		unsigned int before_removes = gcd_removes;

		fail_gcd_add_on = gcd_memory_adds + gcd_io_adds + 2U;
		failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
			EFI_OUT_OF_RESOURCES && gcd_removes == before_removes + 1U,
			"partial GCD additions were not removed in reverse rollback");
		fail_gcd_add_on = 0;
	}
	hob.payload.header.resource_assigned = 1;
	installed = NULL;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_SUCCESS && installed != NULL,
		"assigned host protocol was not restored after rollback fixture");
	protocol = installed;
	failures += expect(protocol->next(protocol, &root) == EFI_SUCCESS && root != NULL &&
	protocol->attributes(protocol, root, &attributes) == EFI_SUCCESS &&
		attributes == 0x1235 && protocol->next(protocol, &root) == EFI_NOT_FOUND,
		"published host-bridge enumeration ABI failed");
	failures += expect(protocol->notify(protocol, CDK2_PCI_BEGIN_BUS_ALLOCATION) ==
		EFI_SUCCESS && protocol->notify(protocol, CDK2_PCI_BEGIN_ENUMERATION) ==
		EFI_NOT_READY, "published phase ABI did not enforce restart semantics");
	failures += expect(protocol->start_bus(protocol, root, &configuration) ==
		EFI_SUCCESS && ((struct resource_view *)configuration)->type == 2 &&
		((struct end_view *)((struct resource_view *)configuration + 1))->descriptor ==
		0x79, "bus-enumeration descriptor was not produced");
	failures += expect(protocol->set_bus(protocol, root, configuration) ==
		EFI_SUCCESS, "valid bus range was not accepted");
	(void)release(configuration);
	{
		struct { struct resource_view resource; struct end_view end; } request;
		unsigned int before_allocations = allocations;
		unsigned int before_frees = frees;

		memset(&request, 0, sizeof(request));
		request.resource.descriptor = 0x8a;
		request.resource.length = sizeof(request.resource) - 3;
		request.resource.type = 0;
		request.resource.granularity = 32;
		request.resource.maximum = 0xfff;
		request.resource.address_length = 0x100;
		request.end.descriptor = 0x79;
		failures += expect(protocol->submit(protocol, root, &request) ==
			EFI_SUCCESS && protocol->notify(protocol,
			CDK2_PCI_ALLOCATE_RESOURCES) == EFI_SUCCESS &&
			allocations == before_allocations,
			"assigned descriptor submission re-reserved through GCD");
		failures += expect(protocol->proposed(protocol, root,
			&configuration) == EFI_SUCCESS &&
			((struct resource_view *)configuration)[0].type == 0 &&
			((struct resource_view *)configuration)[0].translation == 0 &&
			((struct end_view *)((struct resource_view *)configuration + 1))->
				descriptor == 0x79,
			"allocated proposal did not report EFI_RESOURCE_SATISFIED");
		(void)release(configuration);
		failures += expect(protocol->notify(protocol, CDK2_PCI_FREE_RESOURCES) ==
			EFI_SUCCESS && frees == before_frees,
			"assigned GCD ownership was incorrectly released");
	}
	hob.payload.header.header.revision++;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_COMPROMISED_DATA, "malformed handoff was published");
	hob.payload.header.header.revision = CDK2_PCI_ROOT_BRIDGES_REVISION;
	hob.payload.bridge.segment = 1;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_UNSUPPORTED, "nonzero PCI segment was partially published");
	hob.payload.bridge.segment = 0;
	hob.payload.bridge.no_extended_config = 0;
	provide_pcd = 0;
	{
		unsigned int before = installs;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_UNSUPPORTED && installs == before,
		"extended config without platform base was partially published");
	}
	provide_pcd = 1;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_SUCCESS, "generated segment-zero configuration base was not consumed");
	provide_pcd_names = 0;
	failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
		EFI_SUCCESS, "generated token 33 configuration base was not consumed");
	provide_pcd_names = 1;
	hob.payload.bridge.no_extended_config = 1;
	provide_pcd = 0;
	{
		unsigned int before_uninstalls = uninstalls;

		fail_install_on = installs + 2U;
		failures += expect(cdk2_pci_host_bridge_entry((void *)0x44, &system) ==
			EFI_OUT_OF_RESOURCES && uninstalls == before_uninstalls + 1U,
			"root publication failure did not roll back host publication");
		fail_install_on = 0;
	}
	return failures == 0 ? 0 : 1;
}
