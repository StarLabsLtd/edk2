/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>

#include <stdio.h>
#include <string.h>

uint64_t CDK2_MS_ABI cdk2_pci_host_bridge_entry(void *, void *);

static void *installed;

static uint64_t CDK2_MS_ABI install(void **handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)guid;
	*handle = (void *)0x55;
	installed = interface;
	return EFI_SUCCESS;
}

struct boot_view { uint8_t pad[328]; void *install; };
struct config_view { EFI_GUID guid; void *table; };
struct system_view {
	uint8_t header[24]; uint16_t *vendor; uint32_t revision, pad;
	void *console[6], *runtime; struct boot_view *boot;
	size_t count; struct config_view *tables;
};
struct protocol_view {
	uint64_t (CDK2_MS_ABI *notify)(void *, size_t);
	uint64_t (CDK2_MS_ABI *next)(void *, void **);
	uint64_t (CDK2_MS_ABI *attributes)(void *, void *, uint64_t *);
	void *unsupported[5];
};
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
	struct hob_fixture hob;
	struct boot_view boot;
	struct config_view config;
	struct system_view system;
	struct protocol_view *protocol;
	void *root = NULL;
	uint64_t attributes;
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
	hob.end.type = 0xffff;
	hob.end.length = sizeof(hob.end);
	memset(&boot, 0, sizeof(boot));
	boot.install = install;
	config.guid = hob_list;
	config.table = &hob;
	memset(&system, 0, sizeof(system));
	system.boot = &boot;
	system.count = 1;
	system.tables = &config;
	failures += expect(cdk2_pci_host_bridge_entry(NULL, &system) == EFI_SUCCESS &&
		installed != NULL, "valid root-bridge hob was not published");
	protocol = installed;
	failures += expect(protocol->next(protocol, &root) == EFI_SUCCESS && root != NULL &&
		protocol->attributes(protocol, root, &attributes) == EFI_SUCCESS &&
		attributes == 0x1234 && protocol->next(protocol, &root) == EFI_NOT_FOUND,
		"published host-bridge enumeration ABI failed");
	failures += expect(protocol->notify(protocol, CDK2_PCI_BEGIN_BUS_ALLOCATION) ==
		EFI_SUCCESS && protocol->notify(protocol, CDK2_PCI_BEGIN_ENUMERATION) ==
		EFI_NOT_READY, "published phase ABI did not enforce restart semantics");
	hob.payload.header.header.revision++;
	failures += expect(cdk2_pci_host_bridge_entry(NULL, &system) ==
		EFI_COMPROMISED_DATA, "malformed handoff was published");
	return failures == 0 ? 0 : 1;
}
