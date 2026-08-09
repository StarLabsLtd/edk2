/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>

#include <stdio.h>
#include <string.h>

struct fixture {
	struct cdk2_pci_root_bridges_hob header;
	struct cdk2_pci_root_bridge_record bridge[2];
};

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
