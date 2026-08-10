/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/xhci.h>

#include <string.h>

#define XHCI_USBCMD 0x00U
#define XHCI_USBSTS 0x04U
#define XHCI_CRCR 0x18U
#define XHCI_DCBAAP 0x30U
#define XHCI_CONFIG 0x38U
#define XHCI_IMAN 0x20U
#define XHCI_ERSTSZ 0x28U
#define XHCI_ERSTBA 0x30U
#define XHCI_ERDP 0x38U
#define XHCI_PORTSC 0x400U

static EFI_STATUS wait_mask(struct cdk2_xhci_controller *controller,
	UINT32 offset, UINT32 mask, UINT32 expected)
{
	UINT32 value;
	EFI_STATUS status;

	for (UINTN retry = 0; retry < 1000U; retry++) {
		status = controller->services.read32(controller->services.context, offset,
			&value);
		if (EFI_ERROR(status) || (value & mask) == expected)
			return status;
		controller->services.delay(controller->services.context, 1000U);
	}
	return EFI_TIMEOUT;
}

static void release_dma(struct cdk2_xhci_controller *controller,
	struct cdk2_xhci_dma *dma)
{
	if (dma->host != NULL)
		controller->services.release_dma(controller->services.context, dma);
	memset(dma, 0, sizeof(*dma));
}

void cdk2_xhci_controller_destroy(struct cdk2_xhci_controller *controller)
{
	if (controller == NULL || controller->services.release_dma == NULL)
		return;
	if (controller->running) {
		(void)controller->services.write32(controller->services.context,
			controller->capability.capability_length + XHCI_USBCMD, 0U);
		controller->running = FALSE;
	}
	while (controller->scratchpads_owned != 0U)
		release_dma(controller,
			&controller->scratchpads[--controller->scratchpads_owned]);
	release_dma(controller, &controller->scratchpad_array);
	release_dma(controller, &controller->erst_dma);
	release_dma(controller, &controller->event_dma);
	release_dma(controller, &controller->command_dma);
	release_dma(controller, &controller->dcbaa);
}

EFI_STATUS cdk2_xhci_controller_init(struct cdk2_xhci_controller *controller,
	const struct cdk2_xhci_controller_services *services,
	const struct cdk2_xhci_capabilities *capability)
{
	struct cdk2_xhci_erst_entry *erst;
	UINT64 *dcbaa;
	UINT64 *scratchpads;
	UINT32 operational;
	EFI_STATUS status;

	if (controller == NULL || services == NULL || capability == NULL ||
	    services->read32 == NULL || services->write32 == NULL ||
	    services->write64 == NULL || services->flush == NULL ||
	    services->delay == NULL ||
	    services->allocate_dma == NULL || services->release_dma == NULL ||
	    services->map_buffer == NULL || services->unmap_buffer == NULL)
		return EFI_INVALID_PARAMETER;
	memset(controller, 0, sizeof(*controller));
	controller->services = *services;
	controller->capability = *capability;
	operational = capability->capability_length;
	status = services->write32(services->context, operational + XHCI_USBCMD, 0U);
	if (EFI_ERROR(status))
		goto fail;
	status = wait_mask(controller, operational + XHCI_USBSTS, 1U, 1U);
	if (EFI_ERROR(status))
		goto fail;
	status = services->write32(services->context, operational + XHCI_USBCMD, 2U);
	if (EFI_ERROR(status))
		goto fail;
	status = wait_mask(controller, operational + XHCI_USBCMD, 2U, 0U);
	if (EFI_ERROR(status))
		goto fail;
	status = wait_mask(controller, operational + XHCI_USBSTS, 1U << 11, 0U);
	if (EFI_ERROR(status))
		goto fail;
	status = services->allocate_dma(services->context,
		(capability->maximum_slots + 1U) * sizeof(UINT64), 64U,
		&controller->dcbaa);
	if (EFI_ERROR(status))
		goto fail;
	status = services->allocate_dma(services->context, 4096U, 64U,
		&controller->command_dma);
	if (EFI_ERROR(status))
		goto fail;
	status = services->allocate_dma(services->context, 4096U, 64U,
		&controller->event_dma);
	if (EFI_ERROR(status))
		goto fail;
	status = services->allocate_dma(services->context,
		sizeof(struct cdk2_xhci_erst_entry), 64U, &controller->erst_dma);
	if (EFI_ERROR(status))
		goto fail;
	memset(controller->dcbaa.host, 0, controller->dcbaa.size);
	dcbaa = controller->dcbaa.host;
	if (capability->scratchpad_count != 0U) {
		status = services->allocate_dma(services->context,
			capability->scratchpad_count * sizeof(UINT64), 64U,
			&controller->scratchpad_array);
		if (EFI_ERROR(status))
			goto fail;
		scratchpads = controller->scratchpad_array.host;
		for (UINT16 index = 0; index < capability->scratchpad_count; index++) {
			status = services->allocate_dma(services->context,
				capability->page_size, capability->page_size,
				&controller->scratchpads[index]);
			if (EFI_ERROR(status))
				goto fail;
			scratchpads[index] = controller->scratchpads[index].device;
			controller->scratchpads_owned++;
		}
		dcbaa[0] = controller->scratchpad_array.device;
	}
	status = cdk2_xhci_ring_init(&controller->command_ring,
		controller->command_dma.host, controller->command_dma.device);
	if (EFI_ERROR(status))
		goto fail;
	memset(controller->event_dma.host, 0, controller->event_dma.size);
	status = cdk2_xhci_event_ring_init(&controller->event_ring,
		controller->event_dma.host, 256U);
	if (EFI_ERROR(status))
		goto fail;
	erst = controller->erst_dma.host;
	*erst = (struct cdk2_xhci_erst_entry) { controller->event_dma.device, 256U, 0 };
	status = services->write64(services->context, operational + XHCI_DCBAAP,
		controller->dcbaa.device);
	if (!EFI_ERROR(status))
		status = services->write64(services->context, operational + XHCI_CRCR,
			controller->command_dma.device | 1U);
	if (!EFI_ERROR(status))
		status = services->write32(services->context, operational + XHCI_CONFIG,
			capability->maximum_slots);
	if (!EFI_ERROR(status))
		status = services->write32(services->context,
			capability->runtime_offset + XHCI_ERSTSZ, 1U);
	if (!EFI_ERROR(status))
		status = services->write64(services->context,
			capability->runtime_offset + XHCI_ERSTBA, controller->erst_dma.device);
	if (!EFI_ERROR(status))
		status = services->write64(services->context,
			capability->runtime_offset + XHCI_ERDP, controller->event_dma.device);
	if (!EFI_ERROR(status))
		status = services->write32(services->context,
			capability->runtime_offset + XHCI_IMAN, 2U);
	if (!EFI_ERROR(status))
		status = services->write32(services->context, operational + XHCI_USBCMD, 5U);
	if (EFI_ERROR(status))
		goto fail;
	controller->running = TRUE;
	return EFI_SUCCESS;
fail:
	cdk2_xhci_controller_destroy(controller);
	return status;
}

static EFI_STATUS next_event(struct cdk2_xhci_controller *controller,
	struct cdk2_xhci_trb *event)
{
	EFI_STATUS status = controller->services.flush(controller->services.context);

	if (EFI_ERROR(status))
		return status;
	status = cdk2_xhci_event_ring_dequeue(&controller->event_ring, event);
	if (EFI_ERROR(status))
		return status;
	return controller->services.write64(controller->services.context,
		controller->capability.runtime_offset + XHCI_ERDP,
		(controller->event_dma.device +
		 controller->event_ring.dequeue * sizeof(struct cdk2_xhci_trb)) | 8U);
}

EFI_STATUS cdk2_xhci_controller_command(struct cdk2_xhci_controller *controller,
	UINT8 type, UINT8 slot, UINT64 parameter, UINT8 *result_slot)
{
	struct cdk2_xhci_trb event;
	UINT64 command_address;
	UINT8 completion;
	EFI_STATUS status;

	if (controller == NULL || !controller->running || result_slot == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_xhci_command_enqueue(&controller->command_ring, type, slot,
		parameter, &command_address);
	if (!EFI_ERROR(status))
		status = controller->services.flush(controller->services.context);
	if (!EFI_ERROR(status))
		status = controller->services.write32(controller->services.context,
			controller->capability.doorbell_offset, 0U);
	if (EFI_ERROR(status))
		return status;
	for (UINTN retry = 0; retry < 1000U; retry++) {
		status = next_event(controller, &event);
		if (status == EFI_NOT_READY) {
			controller->services.delay(controller->services.context, 1000U);
			continue;
		}
		if (EFI_ERROR(status))
			return status;
		if ((event.control >> 10 & 0x3fU) != 33U ||
		    (event.parameter & ~0xfULL) != (command_address & ~0xfULL)) {
			if (controller->pending_count == 32U)
				return EFI_OUT_OF_RESOURCES;
			controller->pending_events[controller->pending_count++] = event;
			continue;
		}
		completion = event.status >> 24;
		*result_slot = event.control >> 24;
		return completion == 1U ? EFI_SUCCESS : EFI_DEVICE_ERROR;
	}
	return EFI_TIMEOUT;
}

static void release_device_dma(struct cdk2_xhci_device *device)
{
	struct cdk2_xhci_controller *controller = device->controller;

	for (UINTN index = 0U; index < 31U; index++)
		if (device->endpoints[index].dma.host != NULL)
			controller->services.release_dma(controller->services.context,
				&device->endpoints[index].dma);
	if (device->endpoint_dma.host != NULL)
		controller->services.release_dma(controller->services.context,
			&device->endpoint_dma);
	if (device->device_context.host != NULL)
		controller->services.release_dma(controller->services.context,
			&device->device_context);
	if (device->input_context.host != NULL)
		controller->services.release_dma(controller->services.context,
			&device->input_context);
}

EFI_STATUS cdk2_xhci_device_enable(struct cdk2_xhci_controller *controller,
	UINT8 root_port, UINT8 speed, UINT16 maximum_packet,
	struct cdk2_xhci_device *device)
{
	UINTN context_size;
	UINT8 result_slot;
	EFI_STATUS status;

	if (controller == NULL || device == NULL || !controller->running ||
	    root_port == 0U || root_port > controller->capability.maximum_ports ||
	    speed == 0U || speed > 5U || maximum_packet == 0U)
		return EFI_INVALID_PARAMETER;
	memset(device, 0, sizeof(*device));
	device->controller = controller;
	device->root_port = root_port;
	device->speed = speed;
	context_size = controller->capability.context_64 ? 64U : 32U;
	status = controller->services.allocate_dma(controller->services.context,
		context_size * 33U, 64U, &device->input_context);
	if (!EFI_ERROR(status))
		status = controller->services.allocate_dma(controller->services.context,
			context_size * 32U, 64U, &device->device_context);
	if (!EFI_ERROR(status))
		status = controller->services.allocate_dma(controller->services.context,
			sizeof(struct cdk2_xhci_trb) * CDK2_XHCI_RING_TRBS, 64U,
			&device->endpoint_dma);
	if (!EFI_ERROR(status))
		status = cdk2_xhci_ring_init(&device->endpoint_ring,
			device->endpoint_dma.host, device->endpoint_dma.device);
	if (!EFI_ERROR(status))
		status = cdk2_xhci_build_address_context(device->input_context.host,
			device->input_context.size, device->device_context.host,
			device->device_context.size, controller->capability.context_64,
			speed, root_port, maximum_packet, device->endpoint_dma.device);
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_xhci_controller_command(controller, 9U, 0U, 0U,
		&result_slot);
	if (EFI_ERROR(status))
		goto fail;
	if (result_slot == 0U || result_slot > controller->capability.maximum_slots) {
		status = EFI_COMPROMISED_DATA;
		goto fail;
	}
	device->slot = result_slot;
	((UINT64 *)controller->dcbaa.host)[device->slot] = device->device_context.device;
	status = controller->services.flush(controller->services.context);
	if (!EFI_ERROR(status))
		status = cdk2_xhci_controller_command(controller, 11U, device->slot,
			device->input_context.device, &result_slot);
	if (EFI_ERROR(status)) {
		cdk2_xhci_controller_command(controller, 10U, device->slot, 0U,
			&result_slot);
		((UINT64 *)controller->dcbaa.host)[device->slot] = 0U;
		goto fail;
	}
	device->enabled = TRUE;
	return EFI_SUCCESS;
fail:
	release_device_dma(device);
	memset(device, 0, sizeof(*device));
	return status;
}

EFI_STATUS cdk2_xhci_device_disable(struct cdk2_xhci_device *device)
{
	struct cdk2_xhci_controller *controller;
	UINT8 result_slot;
	EFI_STATUS status;

	if (device == NULL || !device->enabled || device->controller == NULL)
		return EFI_INVALID_PARAMETER;
	controller = device->controller;
	status = cdk2_xhci_controller_command(controller, 10U, device->slot, 0U,
		&result_slot);
	if (EFI_ERROR(status))
		return status;
	((UINT64 *)controller->dcbaa.host)[device->slot] = 0U;
	controller->services.flush(controller->services.context);
	release_device_dma(device);
	memset(device, 0, sizeof(*device));
	return EFI_SUCCESS;
}

static UINT32 port_offset(const struct cdk2_xhci_controller *controller,
	UINT8 port)
{
	return controller->capability.capability_length + XHCI_PORTSC +
		(UINT32)(port - 1U) * 0x10U;
}

EFI_STATUS cdk2_xhci_controller_get_port(struct cdk2_xhci_controller *controller,
	UINT8 port, struct cdk2_xhci_port_status *status)
{
	UINT32 value;
	EFI_STATUS result;

	if (controller == NULL || status == NULL || !controller->running ||
	    port == 0U || port > controller->capability.maximum_ports)
		return EFI_INVALID_PARAMETER;
	result = controller->services.read32(controller->services.context,
		port_offset(controller, port), &value);
	return EFI_ERROR(result) ? result : cdk2_xhci_decode_port(value, status);
}

EFI_STATUS cdk2_xhci_controller_set_port(struct cdk2_xhci_controller *controller,
	UINT8 port, enum cdk2_xhci_port_feature feature, BOOLEAN set)
{
	UINT32 offset;
	UINT32 value;
	UINT32 change;
	UINT32 bit;
	EFI_STATUS status;

	if (controller == NULL || !controller->running || port == 0U ||
	    port > controller->capability.maximum_ports)
		return EFI_INVALID_PARAMETER;
	offset = port_offset(controller, port);
	status = controller->services.read32(controller->services.context, offset,
		&value);
	if (EFI_ERROR(status))
		return status;
	change = 0U;
	switch (feature) {
	case CDK2_XHCI_PORT_ENABLE:
		bit = 1U << 1;
		break;
	case CDK2_XHCI_PORT_RESET:
		bit = 1U << 4;
		break;
	case CDK2_XHCI_PORT_POWER:
		bit = 1U << 9;
		break;
	case CDK2_XHCI_PORT_CONNECT_CHANGE:
		bit = 0U;
		change = 1U << 17;
		break;
	case CDK2_XHCI_PORT_ENABLE_CHANGE:
		bit = 0U;
		change = 1U << 18;
		break;
	case CDK2_XHCI_PORT_RESET_CHANGE:
		bit = 0U;
		change = 1U << 21;
		break;
	default:
		return EFI_UNSUPPORTED;
	}
	if (change != 0U && set)
		return EFI_INVALID_PARAMETER;
	value &= ~((UINT32)0x7fU << 17);
	if (change != 0U)
		value |= change;
	else if (set)
		value |= bit;
	else
		value &= ~bit;
	status = controller->services.write32(controller->services.context, offset,
		value);
	if (EFI_ERROR(status) || feature != CDK2_XHCI_PORT_RESET || !set)
		return status;
	for (UINTN retry = 0U; retry < 100U; retry++) {
		controller->services.delay(controller->services.context, 1000U);
		status = controller->services.read32(controller->services.context,
			offset, &value);
		if (EFI_ERROR(status) || (value & bit) == 0U)
			return status;
	}
	return EFI_TIMEOUT;
}

EFI_STATUS cdk2_xhci_control_transfer(struct cdk2_xhci_device *device,
	const struct cdk2_usb_request *request, void *buffer, UINTN *length,
	BOOLEAN data_in)
{
	struct cdk2_xhci_controller *controller;
	struct cdk2_xhci_mapping mapping;
	struct cdk2_xhci_trb event;
	UINT64 last_address;
	UINT16 first, count;
	EFI_STATUS status;

	if (device == NULL || !device->enabled || request == NULL || length == NULL ||
	    *length > UINT32_MAX || request->length != *length ||
	    (*length != 0U && buffer == NULL))
		return EFI_INVALID_PARAMETER;
	controller = device->controller;
	memset(&mapping, 0, sizeof(mapping));
	if (*length != 0U) {
		status = controller->services.map_buffer(controller->services.context,
			buffer, *length, data_in, &mapping);
		if (EFI_ERROR(status))
			return status;
		if (mapping.count != 1U) {
			controller->services.unmap_buffer(controller->services.context,
				&mapping);
			return EFI_BAD_BUFFER_SIZE;
		}
	}
	status = cdk2_xhci_build_control_transfer(&device->endpoint_ring, request,
		*length == 0U ? 0U : mapping.segments[0].device, *length, data_in,
		&first, &count);
	if (!EFI_ERROR(status))
		status = controller->services.flush(controller->services.context);
	if (!EFI_ERROR(status))
		status = controller->services.write32(controller->services.context,
			controller->capability.doorbell_offset + (UINT32)device->slot * 4U, 1U);
	last_address = device->endpoint_ring.device_address +
		((first + count - 1U) % (CDK2_XHCI_RING_TRBS - 1U)) * 16U;
	for (UINTN retry = 0U; !EFI_ERROR(status) && retry < 1000U; retry++) {
		status = next_event(controller, &event);
		if (status == EFI_NOT_READY) {
			controller->services.delay(controller->services.context, 1000U);
			status = EFI_SUCCESS;
			continue;
		}
		if (!EFI_ERROR(status) && (event.control >> 10 & 0x3fU) == 32U &&
		    (event.parameter & ~0xfULL) == last_address) {
			UINT32 residual = event.status & 0xffffffU;

			status = (event.status >> 24) == 1U ? EFI_SUCCESS : EFI_DEVICE_ERROR;
			*length = residual <= *length ? *length - residual : 0U;
			break;
		}
		if (!EFI_ERROR(status))
			status = EFI_NOT_READY;
	}
	if (status == EFI_NOT_READY)
		status = EFI_TIMEOUT;
	if (mapping.count != 0U)
		controller->services.unmap_buffer(controller->services.context, &mapping);
	return status;
}

EFI_STATUS cdk2_xhci_device_configure_endpoint(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, UINT8 transfer_type, UINT16 maximum_packet)
{
	struct cdk2_xhci_controller *controller;
	struct cdk2_xhci_endpoint *endpoint;
	UINTN context_size;
	UINT32 *control;
	UINT32 *slot_context;
	UINT32 *context;
	UINT8 number = endpoint_address & 0xfU;
	UINT8 dci = number * 2U + ((endpoint_address & 0x80U) != 0U ? 1U : 0U);
	UINT8 xhci_type;
	UINT8 result_slot;
	EFI_STATUS status;

	if (device == NULL || !device->enabled || number == 0U || dci > 31U ||
	    maximum_packet == 0U || transfer_type < 2U || transfer_type > 3U)
		return EFI_INVALID_PARAMETER;
	xhci_type = transfer_type == 2U ?
		((endpoint_address & 0x80U) != 0U ? 6U : 2U) :
		((endpoint_address & 0x80U) != 0U ? 7U : 3U);
	controller = device->controller;
	endpoint = &device->endpoints[dci - 1U];
	if (endpoint->enabled)
		return endpoint->maximum_packet == maximum_packet &&
			endpoint->type == xhci_type ? EFI_ALREADY_STARTED : EFI_UNSUPPORTED;
	status = controller->services.allocate_dma(controller->services.context,
		sizeof(struct cdk2_xhci_trb) * CDK2_XHCI_RING_TRBS, 64U, &endpoint->dma);
	if (!EFI_ERROR(status))
		status = cdk2_xhci_ring_init(&endpoint->ring, endpoint->dma.host,
			endpoint->dma.device);
	if (EFI_ERROR(status))
		return status;
	context_size = controller->capability.context_64 ? 64U : 32U;
	memset(device->input_context.host, 0, device->input_context.size);
	control = device->input_context.host;
	control[1] = 1U | 1U << dci;
	slot_context = (void *)((UINT8 *)device->input_context.host + context_size);
	memcpy(slot_context, device->device_context.host, context_size);
	if ((slot_context[0] >> 27 & 0x1fU) < dci)
		slot_context[0] = (slot_context[0] & ~(0x1fU << 27)) |
			(UINT32)dci << 27;
	context = (void *)((UINT8 *)device->input_context.host +
		context_size * (dci + 1U));
	context[1] = (UINT32)xhci_type << 3 | (UINT32)maximum_packet << 16;
	context[2] = (UINT32)endpoint->dma.device | 1U;
	context[3] = endpoint->dma.device >> 32;
	context[4] = maximum_packet;
	status = controller->services.flush(controller->services.context);
	if (!EFI_ERROR(status))
		status = cdk2_xhci_controller_command(controller, 12U, device->slot,
			device->input_context.device, &result_slot);
	if (EFI_ERROR(status)) {
		controller->services.release_dma(controller->services.context,
			&endpoint->dma);
		memset(endpoint, 0, sizeof(*endpoint));
		return status;
	}
	endpoint->maximum_packet = maximum_packet;
	endpoint->dci = dci;
	endpoint->type = xhci_type;
	endpoint->enabled = TRUE;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_bulk_transfer(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, void *buffer, UINTN *length)
{
	struct cdk2_xhci_controller *controller;
	struct cdk2_xhci_mapping mapping;
	struct cdk2_xhci_endpoint *endpoint;
	struct cdk2_xhci_trb event;
	UINT64 last_address;
	UINT16 first, count;
	UINT8 dci;
	EFI_STATUS status;

	if (device == NULL || !device->enabled || buffer == NULL || length == NULL ||
	    *length == 0U)
		return EFI_INVALID_PARAMETER;
	dci = (endpoint_address & 0xfU) * 2U +
		((endpoint_address & 0x80U) != 0U ? 1U : 0U);
	if (dci == 0U || dci > 31U || !device->endpoints[dci - 1U].enabled)
		return EFI_NOT_FOUND;
	controller = device->controller;
	endpoint = &device->endpoints[dci - 1U];
	status = controller->services.map_buffer(controller->services.context,
		buffer, *length, (endpoint_address & 0x80U) != 0U, &mapping);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_xhci_build_bulk_transfer(&endpoint->ring, mapping.segments,
		mapping.count, &first, &count);
	if (!EFI_ERROR(status))
		status = controller->services.flush(controller->services.context);
	if (!EFI_ERROR(status))
		status = controller->services.write32(controller->services.context,
			controller->capability.doorbell_offset + (UINT32)device->slot * 4U, dci);
	last_address = endpoint->ring.device_address +
		((first + count - 1U) % (CDK2_XHCI_RING_TRBS - 1U)) * 16U;
	for (UINTN retry = 0U; !EFI_ERROR(status) && retry < 1000U; retry++) {
		status = next_event(controller, &event);
		if (status == EFI_NOT_READY) {
			controller->services.delay(controller->services.context, 1000U);
			status = EFI_SUCCESS;
			continue;
		}
		if (!EFI_ERROR(status) && (event.control >> 10 & 0x3fU) == 32U &&
		    (event.parameter & ~0xfULL) == last_address) {
			UINT32 residual = event.status & 0xffffffU;

			status = (event.status >> 24) == 1U ? EFI_SUCCESS : EFI_DEVICE_ERROR;
			*length = residual <= *length ? *length - residual : 0U;
			break;
		}
		if (!EFI_ERROR(status))
			status = EFI_NOT_READY;
	}
	if (status == EFI_NOT_READY)
		status = EFI_TIMEOUT;
	controller->services.unmap_buffer(controller->services.context, &mapping);
	return status;
}

EFI_STATUS cdk2_xhci_interrupt_transfer(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, void *buffer, UINTN *length, UINT16 maximum_packet)
{
	EFI_STATUS status;

	status = cdk2_xhci_device_configure_endpoint(device, endpoint_address, 3U,
		maximum_packet);
	if (status == EFI_ALREADY_STARTED)
		status = EFI_SUCCESS;
	return EFI_ERROR(status) ? status : cdk2_xhci_bulk_transfer(device,
		endpoint_address, buffer, length);
}

static EFI_STATUS endpoint_command(struct cdk2_xhci_device *device, UINT8 type,
	UINT8 dci)
{
	struct cdk2_xhci_controller *controller = device->controller;
	struct cdk2_xhci_trb event;
	UINT64 address;
	UINT16 index;
	EFI_STATUS status;

	status = cdk2_xhci_ring_enqueue(&controller->command_ring, 0U, 0U,
		(UINT32)type << 10 | (UINT32)dci << 16 |
		(UINT32)device->slot << 24, &index);
	if (EFI_ERROR(status))
		return status;
	address = controller->command_ring.device_address + index * 16U;
	if (!EFI_ERROR(status))
		status = controller->services.flush(controller->services.context);
	if (!EFI_ERROR(status))
		status = controller->services.write32(controller->services.context,
			controller->capability.doorbell_offset, 0U);
	for (UINTN retry = 0U; !EFI_ERROR(status) && retry < 1000U; retry++) {
		status = next_event(controller, &event);
		if (status == EFI_NOT_READY) {
			controller->services.delay(controller->services.context, 1000U);
			status = EFI_SUCCESS;
			continue;
		}
		if (!EFI_ERROR(status) && (event.control >> 10 & 0x3fU) == 33U &&
		    (event.parameter & ~0xfULL) == address)
			return (event.status >> 24) == 1U ? EFI_SUCCESS : EFI_DEVICE_ERROR;
		if (!EFI_ERROR(status))
			status = EFI_NOT_READY;
	}
	return status == EFI_NOT_READY ? EFI_TIMEOUT : status;
}

static EFI_STATUS submit_async(struct cdk2_xhci_async_transfer *transfer)
{
	struct cdk2_xhci_controller *controller = transfer->device->controller;
	struct cdk2_xhci_endpoint *endpoint =
		&transfer->device->endpoints[transfer->dci - 1U];
	struct cdk2_xhci_segment segment = { transfer->dma.device, transfer->length };
	UINT16 first, count;
	EFI_STATUS status;

	status = cdk2_xhci_build_bulk_transfer(&endpoint->ring, &segment, 1U,
		&first, &count);
	if (!EFI_ERROR(status))
		status = controller->services.flush(controller->services.context);
	if (!EFI_ERROR(status))
		status = controller->services.write32(controller->services.context,
			controller->capability.doorbell_offset +
			(UINT32)transfer->device->slot * 4U, transfer->dci);
	if (!EFI_ERROR(status)) {
		transfer->last_address = endpoint->ring.device_address +
			((first + count - 1U) % (CDK2_XHCI_RING_TRBS - 1U)) * 16U;
		transfer->submitted = TRUE;
	}
	return status;
}

EFI_STATUS cdk2_xhci_async_interrupt_start(struct cdk2_xhci_device *device,
	UINT8 endpoint_address, UINTN length, UINT16 maximum_packet,
	struct cdk2_xhci_async_transfer *transfer)
{
	UINT8 dci;
	EFI_STATUS status;

	if (device == NULL || transfer == NULL || !device->enabled || length == 0U ||
	    length > 0x1ffffU || (endpoint_address & 0x80U) == 0U)
		return EFI_INVALID_PARAMETER;
	dci = (endpoint_address & 0xfU) * 2U + 1U;
	status = cdk2_xhci_device_configure_endpoint(device, endpoint_address, 3U,
		maximum_packet);
	if (status == EFI_ALREADY_STARTED)
		status = EFI_SUCCESS;
	if (EFI_ERROR(status))
		return status;
	memset(transfer, 0, sizeof(*transfer));
	transfer->device = device;
	transfer->endpoint = endpoint_address;
	transfer->dci = dci;
	transfer->length = length;
	status = device->controller->services.allocate_dma(
		device->controller->services.context, length, 64U, &transfer->dma);
	if (EFI_ERROR(status))
		return status;
	transfer->active = TRUE;
	status = submit_async(transfer);
	if (EFI_ERROR(status)) {
		device->controller->services.release_dma(
			device->controller->services.context, &transfer->dma);
		memset(transfer, 0, sizeof(*transfer));
	}
	return status;
}

EFI_STATUS cdk2_xhci_async_interrupt_poll(
	struct cdk2_xhci_async_transfer *transfer)
{
	struct cdk2_xhci_controller *controller;
	struct cdk2_xhci_trb event;
	EFI_STATUS status;

	if (transfer == NULL || !transfer->active || !transfer->submitted)
		return EFI_INVALID_PARAMETER;
	controller = transfer->device->controller;
	for (UINTN index = 0U; index < controller->pending_count; index++)
		if ((controller->pending_events[index].control >> 10 & 0x3fU) == 32U &&
		    (controller->pending_events[index].parameter & ~0xfULL) ==
		    transfer->last_address) {
			event = controller->pending_events[index];
			controller->pending_events[index] =
				controller->pending_events[--controller->pending_count];
			goto complete;
		}
	status = next_event(controller, &event);
	if (EFI_ERROR(status))
		return status;
	if ((event.control >> 10 & 0x3fU) != 32U ||
	    (event.parameter & ~0xfULL) != transfer->last_address) {
		if (controller->pending_count == 32U)
			return EFI_OUT_OF_RESOURCES;
		controller->pending_events[controller->pending_count++] = event;
		return EFI_NOT_READY;
	}
complete:
	transfer->submitted = FALSE;
	transfer->actual = (event.status & 0xffffffU) <= transfer->length ?
		transfer->length - (event.status & 0xffffffU) : 0U;
	return (event.status >> 24) == 1U ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS cdk2_xhci_async_interrupt_rearm(
	struct cdk2_xhci_async_transfer *transfer)
{
	if (transfer == NULL || !transfer->active || transfer->submitted)
		return EFI_INVALID_PARAMETER;
	transfer->actual = 0U;
	return submit_async(transfer);
}

EFI_STATUS cdk2_xhci_async_interrupt_stop(
	struct cdk2_xhci_async_transfer *transfer)
{
	struct cdk2_xhci_controller *controller;
	EFI_STATUS status = EFI_SUCCESS;

	if (transfer == NULL || !transfer->active)
		return EFI_INVALID_PARAMETER;
	controller = transfer->device->controller;
	if (transfer->submitted)
		status = endpoint_command(transfer->device, 15U, transfer->dci);
	if (EFI_ERROR(status))
		return status;
	controller->services.release_dma(controller->services.context, &transfer->dma);
	memset(transfer, 0, sizeof(*transfer));
	return EFI_SUCCESS;
}
