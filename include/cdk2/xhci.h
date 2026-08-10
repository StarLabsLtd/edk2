/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_XHCI_H_
#define CDK2_XHCI_H_

#include <uefi.h>
#include <cdk2/pci_io_abi.h>

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

struct cdk2_usb_request {
	UINT8 request_type, request;
	UINT16 value, index, length;
} __packed;

struct cdk2_xhci_segment {
	UINT64 device;
	UINT32 length;
};

struct cdk2_xhci_port_status {
	UINT8 speed;
	BOOLEAN connected, enabled, powered, resetting;
	UINT32 changes;
};

enum cdk2_xhci_port_feature {
	CDK2_XHCI_PORT_ENABLE,
	CDK2_XHCI_PORT_RESET,
	CDK2_XHCI_PORT_POWER,
	CDK2_XHCI_PORT_CONNECT_CHANGE,
	CDK2_XHCI_PORT_ENABLE_CHANGE,
	CDK2_XHCI_PORT_RESET_CHANGE,
};

struct cdk2_xhci_dma {
	void *host;
	UINT64 device;
	UINTN size;
};

#define CDK2_XHCI_TRANSFER_SEGMENTS 64U
struct cdk2_xhci_mapping {
	struct cdk2_xhci_segment segments[CDK2_XHCI_TRANSFER_SEGMENTS];
	void *tokens[CDK2_XHCI_TRANSFER_SEGMENTS];
	UINTN count, length;
};

typedef EFI_STATUS cdk2_xhci_read32_fn(void *context, UINT32 offset,
	UINT32 *value);
typedef EFI_STATUS cdk2_xhci_write32_fn(void *context, UINT32 offset,
	UINT32 value);
typedef EFI_STATUS cdk2_xhci_write64_fn(void *context, UINT32 offset,
	UINT64 value);
typedef EFI_STATUS cdk2_xhci_flush_fn(void *context);
typedef void cdk2_xhci_delay_fn(void *context, UINTN microseconds);
typedef EFI_STATUS cdk2_xhci_allocate_dma_fn(void *context, UINTN size,
	UINTN alignment, struct cdk2_xhci_dma *dma);
typedef void cdk2_xhci_release_dma_fn(void *context, struct cdk2_xhci_dma *dma);
typedef EFI_STATUS cdk2_xhci_map_buffer_fn(void *context, void *buffer,
	UINTN length, BOOLEAN device_writes, struct cdk2_xhci_mapping *mapping);
typedef void cdk2_xhci_unmap_buffer_fn(void *context,
	struct cdk2_xhci_mapping *mapping);

struct cdk2_xhci_controller_services {
	void *context;
	cdk2_xhci_read32_fn *read32;
	cdk2_xhci_write32_fn *write32;
	cdk2_xhci_write64_fn *write64;
	cdk2_xhci_flush_fn *flush;
	cdk2_xhci_delay_fn *delay;
	cdk2_xhci_allocate_dma_fn *allocate_dma;
	cdk2_xhci_release_dma_fn *release_dma;
	cdk2_xhci_map_buffer_fn *map_buffer;
	cdk2_xhci_unmap_buffer_fn *unmap_buffer;
};

struct cdk2_xhci_controller {
	struct cdk2_xhci_controller_services services;
	struct cdk2_xhci_capabilities capability;
	struct cdk2_xhci_dma dcbaa, command_dma, event_dma, erst_dma;
	struct cdk2_xhci_dma scratchpad_array;
	struct cdk2_xhci_dma scratchpads[CDK2_XHCI_MAX_SCRATCHPADS];
	struct cdk2_xhci_ring command_ring;
	struct cdk2_xhci_event_ring event_ring;
	struct cdk2_xhci_trb pending_events[32];
	UINT8 pending_count;
	UINT16 scratchpads_owned;
	BOOLEAN running;
};

struct cdk2_xhci_endpoint {
	struct cdk2_xhci_dma dma;
	struct cdk2_xhci_ring ring;
	UINT16 maximum_packet;
	UINT8 dci, type;
	BOOLEAN enabled;
};

struct cdk2_xhci_device {
	struct cdk2_xhci_controller *controller;
	struct cdk2_xhci_dma input_context, device_context, endpoint_dma;
	struct cdk2_xhci_ring endpoint_ring;
	struct cdk2_xhci_endpoint endpoints[31];
	UINT8 slot, root_port, speed;
	BOOLEAN enabled;
};

struct cdk2_xhci_async_transfer {
	struct cdk2_xhci_device *device;
	struct cdk2_xhci_dma dma;
	UINT64 last_address;
	UINTN length, actual;
	UINT8 endpoint, dci;
	BOOLEAN active, submitted;
};

#define CDK2_XHCI_PCI_ALLOCATIONS 32U
struct cdk2_xhci_pci_allocation {
	void *host, *mapping;
	UINTN pages;
};
struct cdk2_xhci_pci_adapter {
	struct cdk2_efi_pci_io_protocol *pci;
	struct cdk2_xhci_pci_allocation allocations[CDK2_XHCI_PCI_ALLOCATIONS];
	void *delay_context;
	cdk2_xhci_delay_fn *delay;
	UINT64 original_attributes;
	UINT8 bar;
	BOOLEAN attributes_owned;
};

#define CDK2_USB_NOERROR 0U
#define CDK2_USB_ERR_SYSTEM 0x20U

struct cdk2_usb_port_status {
	UINT16 status, change;
};

struct cdk2_usb2_hc_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_get_capability_fn(
	struct cdk2_usb2_hc_protocol *this, UINT8 *maximum_speed,
	UINT8 *port_count, UINT8 *is_64bit);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_reset_fn(
	struct cdk2_usb2_hc_protocol *this, UINT16 attributes);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_get_state_fn(
	struct cdk2_usb2_hc_protocol *this, UINTN *state);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_set_state_fn(
	struct cdk2_usb2_hc_protocol *this, UINTN state);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_control_fn(
	struct cdk2_usb2_hc_protocol *this, UINT8 address, UINT8 speed,
	UINTN maximum_packet, struct cdk2_usb_request *request, UINTN direction,
	void *data, UINTN *length, UINTN timeout, void *translator, UINT32 *result);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_bulk_fn(
	struct cdk2_usb2_hc_protocol *this, UINT8 address, UINT8 endpoint,
	UINT8 speed, UINTN maximum_packet, UINT8 buffers, void **data,
	UINTN *length, UINT8 *toggle, UINTN timeout, void *translator,
	UINT32 *result);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_async_interrupt_fn(
	struct cdk2_usb2_hc_protocol *this, UINT8 address, UINT8 endpoint,
	UINT8 speed, UINTN maximum_packet, BOOLEAN new_transfer, UINT8 *toggle,
	UINTN interval, UINTN length, void *translator, void *callback,
	void *context);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_async_callback_fn(void *data,
	UINTN length, void *context, UINT32 result);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_stub_fn(void);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_get_port_fn(
	struct cdk2_usb2_hc_protocol *this, UINT8 port,
	struct cdk2_usb_port_status *status);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb2_port_feature_fn(
	struct cdk2_usb2_hc_protocol *this, UINT8 port, UINTN feature);

struct cdk2_usb2_hc_protocol {
	cdk2_usb2_get_capability_fn *get_capability;
	cdk2_usb2_reset_fn *reset;
	cdk2_usb2_get_state_fn *get_state;
	cdk2_usb2_set_state_fn *set_state;
	cdk2_usb2_control_fn *control_transfer;
	cdk2_usb2_bulk_fn *bulk_transfer;
	cdk2_usb2_async_interrupt_fn *async_interrupt_transfer;
	cdk2_usb2_bulk_fn *sync_interrupt_transfer;
	cdk2_usb2_stub_fn *isochronous_transfer;
	cdk2_usb2_stub_fn *async_isochronous_transfer;
	cdk2_usb2_get_port_fn *get_root_hub_port_status;
	cdk2_usb2_port_feature_fn *set_root_hub_port_feature;
	cdk2_usb2_port_feature_fn *clear_root_hub_port_feature;
	UINT16 major_revision, minor_revision;
};

struct cdk2_xhci_usb2 {
	struct cdk2_usb2_hc_protocol protocol;
	struct cdk2_xhci_controller *controller;
	struct cdk2_xhci_device devices[256];
	UINT8 current_port, current_speed;
	UINTN state;
	struct {
		struct cdk2_xhci_async_transfer transfer;
		cdk2_usb2_async_callback_fn *callback;
		void *context;
		UINT8 address, endpoint;
		BOOLEAN active;
	} async[8];
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
EFI_STATUS cdk2_xhci_command_enqueue(struct cdk2_xhci_ring *ring, UINT8 type,
	UINT8 slot, UINT64 parameter, UINT64 *command_address);
EFI_STATUS cdk2_xhci_command_completion(struct cdk2_xhci_event_ring *ring,
	UINT64 command_address, UINT8 *completion_code, UINT8 *slot);
EFI_STATUS cdk2_xhci_build_control_transfer(struct cdk2_xhci_ring *ring,
	const struct cdk2_usb_request *request, UINT64 data_device, UINT32 data_length,
	BOOLEAN data_in, UINT16 *first, UINT16 *count);
EFI_STATUS cdk2_xhci_build_bulk_transfer(struct cdk2_xhci_ring *ring,
	const struct cdk2_xhci_segment *segments, UINTN segment_count,
	UINT16 *first, UINT16 *count);
EFI_STATUS cdk2_xhci_decode_port(UINT32 portsc,
	struct cdk2_xhci_port_status *status);
EFI_STATUS cdk2_xhci_build_address_context(void *input_context,
	UINTN input_size, void *device_context, UINTN device_size, BOOLEAN context_64,
	UINT8 speed, UINT8 root_port, UINT16 maximum_packet, UINT64 endpoint_ring);
EFI_STATUS cdk2_xhci_controller_init(struct cdk2_xhci_controller *controller,
	const struct cdk2_xhci_controller_services *services,
	const struct cdk2_xhci_capabilities *capability);
void cdk2_xhci_controller_destroy(struct cdk2_xhci_controller *controller);
EFI_STATUS cdk2_xhci_controller_command(struct cdk2_xhci_controller *controller,
	UINT8 type, UINT8 slot, UINT64 parameter, UINT8 *result_slot);
EFI_STATUS cdk2_xhci_device_enable(struct cdk2_xhci_controller *controller,
	UINT8 root_port, UINT8 speed, UINT16 maximum_packet,
	struct cdk2_xhci_device *device);
EFI_STATUS cdk2_xhci_device_disable(struct cdk2_xhci_device *device);
EFI_STATUS cdk2_xhci_controller_get_port(struct cdk2_xhci_controller *controller,
	UINT8 port, struct cdk2_xhci_port_status *status);
EFI_STATUS cdk2_xhci_controller_set_port(struct cdk2_xhci_controller *controller,
	UINT8 port, enum cdk2_xhci_port_feature feature, BOOLEAN set);
EFI_STATUS cdk2_xhci_control_transfer(struct cdk2_xhci_device *device,
	const struct cdk2_usb_request *request, void *buffer, UINTN *length,
	BOOLEAN data_in);
EFI_STATUS cdk2_xhci_device_configure_endpoint(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, UINT8 transfer_type, UINT16 maximum_packet);
EFI_STATUS cdk2_xhci_bulk_transfer(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, void *buffer, UINTN *length);
EFI_STATUS cdk2_xhci_interrupt_transfer(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, void *buffer, UINTN *length, UINT16 maximum_packet);
EFI_STATUS cdk2_xhci_async_interrupt_start(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, UINTN length, UINT16 maximum_packet,
	struct cdk2_xhci_async_transfer *transfer);
EFI_STATUS cdk2_xhci_async_interrupt_poll(
	struct cdk2_xhci_async_transfer *transfer);
EFI_STATUS cdk2_xhci_async_interrupt_rearm(
	struct cdk2_xhci_async_transfer *transfer);
EFI_STATUS cdk2_xhci_async_interrupt_stop(
	struct cdk2_xhci_async_transfer *transfer);
EFI_STATUS cdk2_xhci_pci_adapter_init(struct cdk2_xhci_pci_adapter *adapter,
	struct cdk2_efi_pci_io_protocol *pci, UINT8 bar, void *delay_context,
	cdk2_xhci_delay_fn *delay);
void cdk2_xhci_pci_controller_services(struct cdk2_xhci_pci_adapter *adapter,
	struct cdk2_xhci_controller_services *services);
EFI_STATUS cdk2_xhci_pci_adapter_release(struct cdk2_xhci_pci_adapter *adapter);
EFI_STATUS cdk2_xhci_usb2_init(struct cdk2_xhci_usb2 *usb2,
	struct cdk2_xhci_controller *controller);
EFI_STATUS cdk2_xhci_usb2_release(struct cdk2_xhci_usb2 *usb2);
void cdk2_xhci_usb2_poll(struct cdk2_xhci_usb2 *usb2);

#endif
