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
	    services->write64 == NULL || services->delay == NULL ||
	    services->allocate_dma == NULL || services->release_dma == NULL)
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
