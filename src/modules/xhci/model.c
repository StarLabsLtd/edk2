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

EFI_STATUS cdk2_xhci_command_enqueue(struct cdk2_xhci_ring *ring, UINT8 type,
	UINT8 slot, UINT64 parameter, UINT64 *command_address)
{
	UINT16 index;
	EFI_STATUS status;

	if (ring == NULL || command_address == NULL || type < 9U || type > 23U)
		return EFI_INVALID_PARAMETER;
	status = cdk2_xhci_ring_enqueue(ring, parameter, 0U,
		(UINT32)type << 10 | (UINT32)slot << 24, &index);
	if (EFI_ERROR(status))
		return status;
	*command_address = ring->device_address + index * sizeof(struct cdk2_xhci_trb);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_command_completion(struct cdk2_xhci_event_ring *ring,
	UINT64 command_address, UINT8 *completion_code, UINT8 *slot)
{
	struct cdk2_xhci_trb event;
	EFI_STATUS status;

	if (ring == NULL || completion_code == NULL || slot == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_xhci_event_ring_dequeue(ring, &event);
	if (EFI_ERROR(status))
		return status;
	if ((event.control >> 10 & 0x3fU) != 33U ||
	    (event.parameter & ~0xfULL) != (command_address & ~0xfULL))
		return EFI_COMPROMISED_DATA;
	*completion_code = event.status >> 24;
	*slot = event.control >> 24;
	return *completion_code == 1U ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS cdk2_xhci_build_control_transfer(struct cdk2_xhci_ring *ring,
	const struct cdk2_usb_request *request, UINT64 data_device, UINT32 data_length,
	BOOLEAN data_in, UINT16 *first, UINT16 *count)
{
	UINT64 setup = 0U;
	UINT32 transfer_type;
	UINT16 index;
	EFI_STATUS status;

	if (ring == NULL || request == NULL || first == NULL || count == NULL ||
	    request->length != data_length || data_length > 0x1ffffU ||
	    (data_length != 0U && data_device == 0U))
		return EFI_INVALID_PARAMETER;
	memcpy(&setup, request, sizeof(*request));
	transfer_type = data_length == 0U ? 0U : data_in ? 3U : 2U;
	status = cdk2_xhci_ring_enqueue(ring, setup, 8U,
		2U << 10 | 1U << 6 | transfer_type << 16, &index);
	if (EFI_ERROR(status))
		return status;
	*first = index;
	*count = 1U;
	if (data_length != 0U) {
		status = cdk2_xhci_ring_enqueue(ring, data_device, data_length,
			3U << 10 | (data_in ? 1U << 16 : 0U), &index);
		if (EFI_ERROR(status))
			return status;
		(*count)++;
	}
	status = cdk2_xhci_ring_enqueue(ring, 0U, 0U,
		4U << 10 | 1U << 5 | (!data_in || data_length == 0U ? 1U << 16 : 0U),
		&index);
	if (!EFI_ERROR(status))
		(*count)++;
	return status;
}

EFI_STATUS cdk2_xhci_build_bulk_transfer(struct cdk2_xhci_ring *ring,
	const struct cdk2_xhci_segment *segments, UINTN segment_count,
	UINT16 *first, UINT16 *count)
{
	UINT16 index;
	EFI_STATUS status;

	if (ring == NULL || segments == NULL || segment_count == 0U ||
	    segment_count > 64U || first == NULL || count == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN segment = 0; segment < segment_count; segment++)
		if (segments[segment].device == 0U || segments[segment].length == 0U ||
		    segments[segment].length > 0x1ffffU)
			return EFI_BAD_BUFFER_SIZE;
	*count = 0U;
	for (UINTN segment = 0; segment < segment_count; segment++) {
		status = cdk2_xhci_ring_enqueue(ring, segments[segment].device,
			segments[segment].length, 1U << 10 |
			(segment + 1U == segment_count ? 1U << 5 : 1U << 4), &index);
		if (EFI_ERROR(status))
			return status;
		if (*count == 0U)
			*first = index;
		(*count)++;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_decode_port(UINT32 portsc,
	struct cdk2_xhci_port_status *status)
{
	UINT8 speed;

	if (status == NULL)
		return EFI_INVALID_PARAMETER;
	speed = portsc >> 10 & 0xfU;
	if (speed > 5U || (speed == 0U && (portsc & 1U) != 0U))
		return EFI_UNSUPPORTED;
	*status = (struct cdk2_xhci_port_status) { .speed = speed,
		.connected = (portsc & 1U) != 0U, .enabled = (portsc & 2U) != 0U,
		.powered = (portsc & 1U << 9) != 0U,
		.resetting = (portsc & 1U << 4) != 0U,
		.changes = portsc >> 17 & 0x7fU };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_build_address_context(void *input_context,
	UINTN input_size, void *device_context, UINTN device_size, BOOLEAN context_64,
	UINT8 speed, UINT8 root_port, UINT16 maximum_packet, UINT64 endpoint_ring)
{
	UINTN context_size = context_64 ? 64U : 32U;
	UINT32 *input = input_context;
	UINT32 *device = device_context;
	UINT32 *input_slot;
	UINT32 *input_ep0;
	UINT32 *device_slot;
	UINT32 *device_ep0;

	if (input == NULL || device == NULL || speed == 0U || speed > 5U ||
	    root_port == 0U || maximum_packet == 0U || (endpoint_ring & 0x3fU) != 0U ||
	    input_size < context_size * 3U || device_size < context_size * 2U)
		return EFI_INVALID_PARAMETER;
	memset(input, 0, input_size);
	memset(device, 0, device_size);
	input[1] = 3U;
	input_slot = (void *)((UINT8 *)input + context_size);
	input_ep0 = (void *)((UINT8 *)input_slot + context_size);
	device_slot = device;
	device_ep0 = (void *)((UINT8 *)device + context_size);
	input_slot[0] = (UINT32)speed << 20 | 1U << 27;
	input_slot[1] = (UINT32)root_port << 16;
	input_ep0[1] = 3U << 1 | 4U << 3 | (UINT32)maximum_packet << 16;
	input_ep0[2] = (UINT32)endpoint_ring | 1U;
	input_ep0[3] = endpoint_ring >> 32;
	input_ep0[4] = 8U;
	memcpy(device_slot, input_slot, context_size);
	memcpy(device_ep0, input_ep0, context_size);
	return EFI_SUCCESS;
}
