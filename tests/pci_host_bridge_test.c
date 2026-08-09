/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>

#include <stdio.h>
#include <string.h>

struct fixture {
	struct cdk2_pci_root_bridges_hob header;
	struct cdk2_pci_root_bridge_record bridge[2];
};
static unsigned int reservations, releases;
static unsigned int fail_reservation;

static uint64_t CDK2_MS_ABI reserve(void *context, uint8_t memory,
	uint64_t base, uint64_t length, uint64_t alignment, uint64_t *allocated)
{
	(void)context;
	(void)memory;
	(void)length;
	(void)alignment;
	reservations++;
	if (reservations == fail_reservation)
		return EFI_OUT_OF_RESOURCES;
	*allocated = base;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI release(void *context, uint8_t memory,
	uint64_t base, uint64_t length)
{
	(void)context;
	(void)memory;
	(void)base;
	(void)length;
	releases++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "pci host bridge test: %s\n", message);
	return condition ? 0 : 1;
}

static void make_fixture(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->header.header.revision = CDK2_PCI_ROOT_BRIDGES_REVISION;
	fixture->header.header.length = sizeof(*fixture);
	fixture->header.resource_assigned = 1;
	fixture->header.count = 2;
	fixture->bridge[0].segment = 0;
	fixture->bridge[0].dma_above_4g = 1;
	fixture->bridge[0].aperture[0] = (struct cdk2_pci_aperture){ 0, 0x7f, 0 };
	fixture->bridge[0].aperture[2] =
		(struct cdk2_pci_aperture){ 0x80000000, 0x8fffffff, 0 };
	fixture->bridge[0].hid = 0x0a0341d0;
	fixture->bridge[0].uid = 7;
	fixture->bridge[1].aperture[0] =
		(struct cdk2_pci_aperture){ 0x80, 0xff, 0 };
}

int main(void)
{
	struct fixture fixture;
	struct cdk2_pci_root_bridge_view bridge;
	struct cdk2_pci_host_model host;
	size_t count;
	uint8_t assigned;
	int failures = 0;

	make_fixture(&fixture);
	failures += expect(cdk2_pci_root_bridges_validate(&fixture, sizeof(fixture),
		&count, &assigned) == EFI_SUCCESS && count == 2 && assigned == 1,
		"valid universal payload root-bridge hob rejected");
	failures += expect(cdk2_pci_root_bridge_get(&fixture, sizeof(fixture), 0,
		&bridge) == EFI_SUCCESS && bridge.uid == 7 && bridge.dma_above_4g == 1 &&
		bridge.aperture[2].limit == 0x8fffffff,
		"root-bridge handoff fields were not preserved");
	failures += expect(cdk2_pci_root_bridge_get(&fixture, sizeof(fixture), 2,
		&bridge) == EFI_NOT_FOUND, "out-of-range root bridge accepted");
	failures += expect(cdk2_pci_host_init(&host, &fixture, sizeof(fixture)) ==
		EFI_SUCCESS && host.count == 2 && host.can_restart,
		"host allocation model did not import all root bridges");
	failures += expect(cdk2_pci_host_notify(&host,
		CDK2_PCI_BEGIN_BUS_ALLOCATION) == EFI_SUCCESS && !host.can_restart &&
		cdk2_pci_host_notify(&host, CDK2_PCI_BEGIN_ENUMERATION) == EFI_NOT_READY,
		"enumeration restart gate was not enforced");
	failures += expect(cdk2_pci_host_notify(&host, CDK2_PCI_FREE_RESOURCES) ==
		EFI_SUCCESS && host.can_restart, "free phase did not permit restart");
	failures += expect(cdk2_pci_host_submit(&host, 0, 1, 0x1000, 0xfff) ==
		EFI_SUCCESS, "aligned memory request rejected");
	for (size_t type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++)
		if (type != 1)
			failures += expect(cdk2_pci_host_submit(&host, 0, type, 0, 0) ==
				EFI_SUCCESS, "empty resource request rejected");
	host.resource_submitted[0] = 1;
	failures += expect(cdk2_pci_host_notify(&host, CDK2_PCI_ALLOCATE_RESOURCES) ==
		EFI_NOT_READY, "allocation proceeded before every root submitted resources");
	for (size_t type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++)
		failures += expect(cdk2_pci_host_submit(&host, 1, type, 0, 0) ==
			EFI_SUCCESS, "second root empty request rejected");
	host.resource_submitted[1] = 1;
	failures += expect(cdk2_pci_host_notify(&host, CDK2_PCI_ALLOCATE_RESOURCES) ==
		EFI_SUCCESS && host.request[0][1].allocated &&
		host.request[0][1].base == 0x80000000,
		"memory request was not allocated inside its admitted aperture");
	failures += expect(cdk2_pci_host_notify(&host, CDK2_PCI_FREE_RESOURCES) ==
		EFI_SUCCESS, "allocated resources were not released");
	reservations = releases = 0;
	make_fixture(&fixture);
	fixture.bridge[0].aperture[1] =
		(struct cdk2_pci_aperture){ 0x1000, 0x1fff, 0 };
	failures += expect(cdk2_pci_host_init(&host, &fixture, sizeof(fixture)) ==
		EFI_SUCCESS && cdk2_pci_host_set_allocator(&host, NULL, reserve, release) ==
		EFI_SUCCESS, "gcd allocator callbacks were not configured");
	for (size_t root_index = 0; root_index < host.count; root_index++)
		for (size_t type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++)
			failures += expect(cdk2_pci_host_submit(&host, root_index, type,
				root_index == 0 && type < 2 ? 0x100 : 0, 0) == EFI_SUCCESS,
				"rollback fixture resource submission failed");
	for (size_t root_index = 0; root_index < host.count; root_index++)
		host.resource_submitted[root_index] = 1;
	fail_reservation = 2;
	failures += expect(cdk2_pci_host_notify(&host, CDK2_PCI_ALLOCATE_RESOURCES) ==
		EFI_OUT_OF_RESOURCES && reservations == 2 && releases == 1 &&
		!host.request[0][0].allocated && !host.request[0][1].allocated,
		"failed gcd reservation was not rolled back");
	fail_reservation = 0;
	failures += expect(cdk2_pci_host_submit(&host, 0, 1, 0x1000, 0x123) ==
		EFI_INVALID_PARAMETER, "non power-of-two alignment mask accepted");
	fixture.header.header.length--;
	failures += expect(cdk2_pci_root_bridges_validate(&fixture, sizeof(fixture),
		&count, &assigned) == EFI_COMPROMISED_DATA,
		"truncated bridge array accepted");
	make_fixture(&fixture);
	fixture.header.count = 0xff;
	failures += expect(cdk2_pci_root_bridges_validate(&fixture, sizeof(fixture),
		&count, &assigned) == EFI_COMPROMISED_DATA,
		"overflowing bridge count accepted");
	make_fixture(&fixture);
	fixture.bridge[0].aperture[0].limit = 0x100;
	failures += expect(cdk2_pci_root_bridges_validate(&fixture, sizeof(fixture),
		&count, &assigned) == EFI_COMPROMISED_DATA,
		"bus aperture outside eight-bit configuration space accepted");
	make_fixture(&fixture);
	fixture.bridge[0].dma_above_4g = 2;
	failures += expect(cdk2_pci_root_bridges_validate(&fixture, sizeof(fixture),
		&count, &assigned) == EFI_COMPROMISED_DATA,
		"non-boolean root-bridge capability accepted");
	return failures == 0 ? 0 : 1;
}
