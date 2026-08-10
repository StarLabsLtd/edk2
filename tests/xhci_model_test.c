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
	UINT64 command_address;
	UINT8 completion, slot;
	struct cdk2_usb_request request = { 0x80U, 6U, 0x100U, 0U, 18U };
	struct cdk2_xhci_segment segments[2] = { { 0x200000U, 4096U },
		{ 0x201000U, 512U } };
	UINT16 first, count;
	struct cdk2_xhci_port_status port;
	UINT8 input_context[192], device_context[128];
	UINT32 *words;

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
	CHECK(cdk2_xhci_command_enqueue(&ring, 9U, 0U, 0U, &command_address) ==
		EFI_SUCCESS && command_address == 0x100010U);
	event_trbs[1] = (struct cdk2_xhci_trb) { .parameter = command_address,
		.status = 1U << 24, .control = 33U << 10 | 7U << 24 };
	CHECK(cdk2_xhci_command_completion(&events, command_address, &completion,
		&slot) == EFI_SUCCESS && completion == 1U && slot == 7U);
	event_trbs[2] = (struct cdk2_xhci_trb) { .parameter = command_address + 16U,
		.status = 1U << 24, .control = 33U << 10 | 7U << 24 };
	CHECK(cdk2_xhci_command_completion(&events, command_address, &completion,
		&slot) == EFI_COMPROMISED_DATA);
	CHECK(cdk2_xhci_build_control_transfer(&ring, &request, 0x300000U, 18U, TRUE,
		&first, &count) == EFI_SUCCESS && count == 3U &&
		(trbs[first].control >> 10 & 0x3fU) == 2U &&
		(trbs[(first + 1U) % 255U].control >> 10 & 0x3fU) == 3U &&
		(trbs[(first + 2U) % 255U].control >> 10 & 0x3fU) == 4U);
	CHECK(cdk2_xhci_build_bulk_transfer(&ring, segments, 2U, &first, &count) ==
		EFI_SUCCESS && count == 2U && (trbs[first].control & 1U << 4) != 0U &&
		(trbs[(first + 1U) % 255U].control & 1U << 5) != 0U);
	CHECK(cdk2_xhci_decode_port(1U | 2U | 1U << 9 | 4U << 10 | 3U << 17,
		&port) == EFI_SUCCESS && port.connected && port.enabled && port.powered &&
		port.speed == 4U && port.changes == 3U);
	CHECK(cdk2_xhci_build_address_context(input_context, 96U, device_context, 64U,
		FALSE, 3U, 2U, 64U, 0x400000U) == EFI_SUCCESS);
	words = (void *)(input_context + 32U);
	CHECK((words[0] >> 20 & 0xfU) == 3U && (words[1] >> 16 & 0xffU) == 2U);
	words = (void *)(input_context + 64U);
	CHECK((words[1] >> 16) == 64U && (words[1] >> 3 & 7U) == 4U &&
		(words[2] & ~0x3fU) == 0x400000U);
	CHECK(cdk2_xhci_build_address_context(input_context, sizeof(input_context),
		device_context, sizeof(device_context), TRUE, 4U, 1U, 512U,
		0x500000U) == EFI_SUCCESS);
	words = (void *)(input_context + 128U);
	CHECK((words[1] >> 16) == 512U && (words[2] & ~0x3fU) == 0x500000U);
	puts("xhci model tests: PASS");
	return 0;
}
