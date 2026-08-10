/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_XHCI_H_
#define CDK2_XHCI_H_

#include <uefi.h>

#define CDK2_XHCI_RING_TRBS 256U
#define CDK2_XHCI_LINK_TYPE 6U
#define CDK2_XHCI_MAX_SCRATCHPADS 1023U

struct cdk2_xhci_capabilities {
	UINT8 capability_length;
	UINT16 interface_version;
	UINT8 maximum_slots, maximum_ports;
	UINT16 maximum_interrupters, scratchpad_count;
	UINT32 runtime_offset, doorbell_offset, page_size;
	BOOLEAN context_64;
};

struct cdk2_xhci_trb {
	UINT64 parameter;
	UINT32 status;
	UINT32 control;
} __packed;

struct cdk2_xhci_ring {
	struct cdk2_xhci_trb *trbs;
	UINT64 device_address;
	UINT16 enqueue;
	BOOLEAN cycle;
};

struct cdk2_xhci_event_ring {
	struct cdk2_xhci_trb *trbs;
	UINT16 count, dequeue;
	BOOLEAN cycle;
};

struct cdk2_xhci_erst_entry {
	UINT64 address;
	UINT32 size;
	UINT32 reserved;
} __packed;

struct cdk2_xhci_dma {
	void *host;
	UINT64 device;
	UINTN size;
};

typedef EFI_STATUS cdk2_xhci_read32_fn(void *context, UINT32 offset,
	UINT32 *value);
typedef EFI_STATUS cdk2_xhci_write32_fn(void *context, UINT32 offset,
	UINT32 value);
typedef EFI_STATUS cdk2_xhci_write64_fn(void *context, UINT32 offset,
	UINT64 value);
typedef void cdk2_xhci_delay_fn(void *context, UINTN microseconds);
typedef EFI_STATUS cdk2_xhci_allocate_dma_fn(void *context, UINTN size,
	UINTN alignment, struct cdk2_xhci_dma *dma);
typedef void cdk2_xhci_release_dma_fn(void *context, struct cdk2_xhci_dma *dma);

struct cdk2_xhci_controller_services {
	void *context;
	cdk2_xhci_read32_fn *read32;
	cdk2_xhci_write32_fn *write32;
	cdk2_xhci_write64_fn *write64;
	cdk2_xhci_delay_fn *delay;
	cdk2_xhci_allocate_dma_fn *allocate_dma;
	cdk2_xhci_release_dma_fn *release_dma;
};

struct cdk2_xhci_controller {
	struct cdk2_xhci_controller_services services;
	struct cdk2_xhci_capabilities capability;
	struct cdk2_xhci_dma dcbaa, command_dma, event_dma, erst_dma;
	struct cdk2_xhci_dma scratchpad_array;
	struct cdk2_xhci_dma scratchpads[CDK2_XHCI_MAX_SCRATCHPADS];
	struct cdk2_xhci_ring command_ring;
	struct cdk2_xhci_event_ring event_ring;
	UINT16 scratchpads_owned;
	BOOLEAN running;
};

EFI_STATUS cdk2_xhci_parse_capabilities(UINT32 capability0, UINT32 hcs1,
	UINT32 hcs2, UINT32 hcc1, UINT32 doorbell, UINT32 runtime,
	UINT32 page_size_mask, struct cdk2_xhci_capabilities *capabilities);
EFI_STATUS cdk2_xhci_ring_init(struct cdk2_xhci_ring *ring,
	struct cdk2_xhci_trb trbs[CDK2_XHCI_RING_TRBS], UINT64 device_address);
EFI_STATUS cdk2_xhci_ring_enqueue(struct cdk2_xhci_ring *ring,
	UINT64 parameter, UINT32 status, UINT32 control, UINT16 *index);
EFI_STATUS cdk2_xhci_event_ring_init(struct cdk2_xhci_event_ring *ring,
	struct cdk2_xhci_trb *trbs, UINT16 count);
EFI_STATUS cdk2_xhci_event_ring_dequeue(struct cdk2_xhci_event_ring *ring,
	struct cdk2_xhci_trb *event);
EFI_STATUS cdk2_xhci_controller_init(struct cdk2_xhci_controller *controller,
	const struct cdk2_xhci_controller_services *services,
	const struct cdk2_xhci_capabilities *capability);
void cdk2_xhci_controller_destroy(struct cdk2_xhci_controller *controller);

#endif
