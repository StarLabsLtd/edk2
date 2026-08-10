/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/xhci.h>

#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

int main(void)
{
	struct cdk2_xhci_capabilities capability;
	struct cdk2_xhci_trb trbs[CDK2_XHCI_RING_TRBS] __aligned(64);
	struct cdk2_xhci_ring ring;
	struct cdk2_xhci_event_ring events;
	struct cdk2_xhci_trb event_trbs[16] = { 0 };
	struct cdk2_xhci_trb event;
	UINT16 index;

	CHECK(sizeof(struct cdk2_xhci_trb) == 16U &&
		sizeof(struct cdk2_xhci_erst_entry) == 16U &&
		cdk2_xhci_parse_capabilities(0x01100040U, 8U | 4U << 8 | 6U << 24,
		1U << 27 | 3U << 21, 4U, 0x1000U, 0x2000U, 5U, &capability) ==
		EFI_SUCCESS && capability.capability_length == 0x40U &&
		capability.interface_version == 0x110U && capability.maximum_slots == 8U &&
		capability.maximum_interrupters == 4U && capability.maximum_ports == 6U &&
		capability.scratchpad_count == 35U && capability.context_64 &&
		capability.page_size == 4096U);
	CHECK(cdk2_xhci_parse_capabilities(0x01100010U, 1U | 1U << 24, 0, 0,
		0x1000U, 0x2000U, 1U, &capability) == EFI_UNSUPPORTED &&
		cdk2_xhci_ring_init(&ring, trbs, 0x100000U) == EFI_SUCCESS &&
		(trbs[255].control >> 10 & 0x3fU) == CDK2_XHCI_LINK_TYPE);
	for (UINTN count = 0; count < 255U; count++)
		CHECK(cdk2_xhci_ring_enqueue(&ring, count, (UINT32)count, 1U << 5,
			&index) == EFI_SUCCESS && index == count &&
			(trbs[index].control & 1U) != 0U);
	CHECK(ring.enqueue == 0U && !ring.cycle &&
		cdk2_xhci_ring_enqueue(&ring, 0xaaU, 0xbbU, 0, &index) == EFI_SUCCESS &&
		index == 0U && (trbs[0].control & 1U) == 0U && trbs[0].parameter == 0xaaU);
	CHECK(cdk2_xhci_event_ring_init(&events, event_trbs, 16U) == EFI_SUCCESS &&
		cdk2_xhci_event_ring_dequeue(&events, &event) == EFI_NOT_READY);
	for (UINTN count = 0; count < 16U; count++)
		event_trbs[count] = (struct cdk2_xhci_trb) { .parameter = count,
			.control = 1U | 32U << 10 };
	for (UINTN count = 0; count < 16U; count++)
		CHECK(cdk2_xhci_event_ring_dequeue(&events, &event) == EFI_SUCCESS &&
			event.parameter == count);
	CHECK(events.dequeue == 0U && !events.cycle &&
		cdk2_xhci_event_ring_dequeue(&events, &event) == EFI_NOT_READY);
	event_trbs[0] = (struct cdk2_xhci_trb) { .parameter = 0xbeefU,
		.control = 32U << 10 };
	CHECK(cdk2_xhci_event_ring_dequeue(&events, &event) == EFI_SUCCESS &&
		event.parameter == 0xbeefU);
	puts("xhci model tests: PASS");
	return 0;
}
