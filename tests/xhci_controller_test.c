/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/xhci.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	UINT32 registers[0x3000U / 4U];
	UINTN allocations, releases, fail_allocation, writes;
	UINT64 next_device;
};

static EFI_STATUS read32(void *opaque, UINT32 offset, UINT32 *value)
{
	struct fixture *fixture = opaque;

	*value = fixture->registers[offset / 4U];
	return EFI_SUCCESS;
}

static EFI_STATUS write32(void *opaque, UINT32 offset, UINT32 value)
{
	struct fixture *fixture = opaque;

	fixture->writes++;
	if (offset == 0x40U && (value & 2U) != 0U)
		value &= ~2U;
	fixture->registers[offset / 4U] = value;
	return EFI_SUCCESS;
}

static EFI_STATUS write64(void *opaque, UINT32 offset, UINT64 value)
{
	struct fixture *fixture = opaque;

	fixture->writes++;
	fixture->registers[offset / 4U] = value;
	fixture->registers[offset / 4U + 1U] = value >> 32;
	return EFI_SUCCESS;
}

static void delay(void *opaque, UINTN microseconds)
{
	(void)opaque;
	(void)microseconds;
}

static EFI_STATUS allocate_dma(void *opaque, UINTN size, UINTN alignment,
	struct cdk2_xhci_dma *dma)
{
	struct fixture *fixture = opaque;
	void *buffer;

	fixture->allocations++;
	if (fixture->fail_allocation == fixture->allocations)
		return EFI_OUT_OF_RESOURCES;
	buffer = aligned_alloc(alignment, (size + alignment - 1U) & ~(alignment - 1U));
	if (buffer == NULL)
		return EFI_OUT_OF_RESOURCES;
	dma->host = buffer;
	dma->device = fixture->next_device;
	dma->size = size;
	fixture->next_device += (size + 0xfffU) & ~0xfffU;
	return EFI_SUCCESS;
}

static void release_dma(void *opaque, struct cdk2_xhci_dma *dma)
{
	struct fixture *fixture = opaque;

	fixture->releases++;
	free(dma->host);
}

int main(void)
{
	struct fixture fixture = { .next_device = 0x100000U };
	struct cdk2_xhci_controller_services services = { &fixture, read32, write32,
		write64, delay, allocate_dma, release_dma };
	struct cdk2_xhci_capabilities capability = { .capability_length = 0x40U,
		.maximum_slots = 8U, .maximum_ports = 4U, .runtime_offset = 0x2000U,
		.doorbell_offset = 0x1000U, .page_size = 4096U };
	struct cdk2_xhci_controller controller;

	fixture.registers[0x44U / 4U] = 1U;
	CHECK(cdk2_xhci_controller_init(&controller, &services, &capability) ==
		EFI_SUCCESS && controller.running && fixture.allocations == 4U &&
		fixture.registers[0x40U / 4U] == 5U &&
		fixture.registers[0x2038U / 4U] == controller.event_dma.device);
	cdk2_xhci_controller_destroy(&controller);
	CHECK(fixture.releases == 4U && fixture.registers[0x40U / 4U] == 0U);
	for (UINTN fault = 1U; fault <= 4U; fault++) {
		memset(&fixture, 0, sizeof(fixture));
		fixture.next_device = 0x100000U;
		fixture.fail_allocation = fault;
		fixture.registers[0x44U / 4U] = 1U;
		CHECK(cdk2_xhci_controller_init(&controller, &services, &capability) ==
			EFI_OUT_OF_RESOURCES && fixture.releases == fault - 1U);
	}
	puts("xhci controller tests: PASS");
	return 0;
}
