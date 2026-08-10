/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/xhci.h>

#include <string.h>

EFI_STATUS cdk2_xhci_parse_capabilities(UINT32 capability0, UINT32 hcs1,
	UINT32 hcs2, UINT32 hcc1, UINT32 doorbell, UINT32 runtime,
	UINT32 page_size_mask, struct cdk2_xhci_capabilities *capabilities)
{
	UINT32 page_size;
	UINT32 bit;

	if (capabilities == NULL || (capability0 & 0xffU) < 0x20U ||
	    (hcs1 & 0xffU) == 0U || ((hcs1 >> 24) & 0xffU) == 0U ||
	    page_size_mask == 0U || (doorbell & 3U) != 0U || (runtime & 0x1fU) != 0U)
		return EFI_UNSUPPORTED;
	for (bit = 0U; bit < 16U && (page_size_mask & (1U << bit)) == 0U; bit++)
		;
	if (bit == 16U)
		return EFI_UNSUPPORTED;
	page_size = 4096U << bit;
	*capabilities = (struct cdk2_xhci_capabilities) {
		.capability_length = capability0 & 0xffU,
		.interface_version = capability0 >> 16,
		.maximum_slots = hcs1 & 0xffU,
		.maximum_interrupters = (hcs1 >> 8) & 0x7ffU,
		.maximum_ports = hcs1 >> 24,
		.scratchpad_count = ((hcs2 >> 27) & 0x1fU) << 5 |
			((hcs2 >> 21) & 0x1fU),
		.context_64 = (hcc1 & 4U) != 0U,
		.doorbell_offset = doorbell,
		.runtime_offset = runtime,
		.page_size = page_size,
	};
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_ring_init(struct cdk2_xhci_ring *ring,
	struct cdk2_xhci_trb trbs[CDK2_XHCI_RING_TRBS], UINT64 device_address)
{
	if (ring == NULL || trbs == NULL || (device_address & 0x3fU) != 0U)
		return EFI_INVALID_PARAMETER;
	memset(trbs, 0, sizeof(*trbs) * CDK2_XHCI_RING_TRBS);
	*ring = (struct cdk2_xhci_ring) { .trbs = trbs,
		.device_address = device_address, .cycle = TRUE };
	trbs[CDK2_XHCI_RING_TRBS - 1U] = (struct cdk2_xhci_trb) {
		.parameter = device_address,
		.control = CDK2_XHCI_LINK_TYPE << 10 | 1U << 1 | 1U,
	};
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_ring_enqueue(struct cdk2_xhci_ring *ring,
	UINT64 parameter, UINT32 status, UINT32 control, UINT16 *index)
{
	struct cdk2_xhci_trb *trb;

	if (ring == NULL || ring->trbs == NULL || index == NULL ||
	    ring->enqueue >= CDK2_XHCI_RING_TRBS - 1U)
		return EFI_INVALID_PARAMETER;
	*index = ring->enqueue;
	trb = &ring->trbs[ring->enqueue++];
	*trb = (struct cdk2_xhci_trb) { parameter, status,
		(control & ~1U) | ring->cycle };
	if (ring->enqueue == CDK2_XHCI_RING_TRBS - 1U) {
		ring->trbs[ring->enqueue].control = CDK2_XHCI_LINK_TYPE << 10 |
			1U << 1 | ring->cycle;
		ring->enqueue = 0U;
		ring->cycle = !ring->cycle;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_event_ring_init(struct cdk2_xhci_event_ring *ring,
	struct cdk2_xhci_trb *trbs, UINT16 count)
{
	if (ring == NULL || trbs == NULL || count < 16U || count > 4096U)
		return EFI_INVALID_PARAMETER;
	*ring = (struct cdk2_xhci_event_ring) { .trbs = trbs, .count = count,
		.cycle = TRUE };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_event_ring_dequeue(struct cdk2_xhci_event_ring *ring,
	struct cdk2_xhci_trb *event)
{
	struct cdk2_xhci_trb *source;

	if (ring == NULL || ring->trbs == NULL || event == NULL || ring->count == 0U)
		return EFI_INVALID_PARAMETER;
	source = &ring->trbs[ring->dequeue];
	if ((source->control & 1U) != ring->cycle)
		return EFI_NOT_READY;
	*event = *source;
	ring->dequeue++;
	if (ring->dequeue == ring->count) {
		ring->dequeue = 0U;
		ring->cycle = !ring->cycle;
	}
	return EFI_SUCCESS;
}
