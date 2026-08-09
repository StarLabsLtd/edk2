/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/sata_controller.h>

#include <string.h>

EFI_STATUS cdk2_sata_geometry(UINT8 base_class, UINT8 sub_class,
	UINT32 cap, UINT32 ports, struct cdk2_sata_geometry *geometry)
{
	UINT8 channels;

	if (geometry == NULL || base_class != 1U ||
	    (sub_class != 1U && sub_class != 6U))
		return EFI_UNSUPPORTED;
	if (sub_class == 1U) {
		*geometry = (struct cdk2_sata_geometry){ 2U, 2U, FALSE };
		return EFI_SUCCESS;
	}
	if (ports == 0U)
		return EFI_DEVICE_ERROR;
	channels = 32U;
	while (channels > 1U && (ports & (1U << (channels - 1U))) == 0U)
		channels--;
	*geometry = (struct cdk2_sata_geometry){ channels,
		(cap & (1U << 17)) != 0U ? 15U : 1U, TRUE };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_best_pio(const struct cdk2_ata_identify *identify,
	const UINT16 *disqualified, UINT16 *selected)
{
	UINT16 mode, advanced, bit, minimum;

	if (identify == NULL || selected == NULL)
		return EFI_INVALID_PARAMETER;
	mode = (UINT16)(identify->pio_cycle_timing >> 8);
	if ((identify->field_validity & 2U) != 0U) {
		advanced = identify->advanced_pio_modes;
		for (bit = 0; bit < 8U; bit++)
			if ((advanced & (1U << bit)) != 0U)
				mode = (UINT16)(bit + 3U);
		if (mode > 4U)
			mode = 4U;
		minimum = identify->min_pio_cycle_time;
		if (minimum > 240U)
			mode = 0U;
		else if (minimum > 180U && mode > 2U)
			mode = 2U;
		else if (minimum > 120U && mode > 3U)
			mode = 3U;
		if (disqualified != NULL && *disqualified < 2U)
			return EFI_UNSUPPORTED;
		if (disqualified != NULL && mode >= *disqualified)
			mode = (UINT16)(*disqualified - 1U);
		*selected = mode < 2U ? 1U : mode;
	} else {
		if (disqualified != NULL && *disqualified < 2U)
			return EFI_UNSUPPORTED;
		if (disqualified != NULL && mode == *disqualified)
			mode--;
		*selected = mode < 2U ? 1U : 2U;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_best_udma(const struct cdk2_ata_identify *identify,
	const UINT16 *disqualified, UINT16 *selected)
{
	UINT16 mask, mode = 0;
	if (identify == NULL || selected == NULL)
		return EFI_INVALID_PARAMETER;
	if ((identify->field_validity & 4U) == 0U)
		return EFI_UNSUPPORTED;
	mask = identify->ultra_dma_mode & 0x3fU;
	while ((mask >>= 1) != 0U)
		mode++;
	if (disqualified != NULL && *disqualified == 0U) {
		*selected = 0; return EFI_UNSUPPORTED;
	}
	if (disqualified != NULL && mode >= *disqualified)
		mode = (UINT16)(*disqualified - 1U);
	*selected = mode; return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_calculate_mode(const struct cdk2_ata_identify *identify,
	const struct cdk2_ata_mode *bad, struct cdk2_ata_mode *selected)
{
	EFI_STATUS status;
	if (selected == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_sata_best_pio(identify,
		bad == NULL || !bad->pio_valid ? NULL : &bad->pio_mode,
		&selected->pio_mode);
	selected->pio_valid = !EFI_ERROR(status);
	status = cdk2_sata_best_udma(identify,
		bad == NULL || !bad->udma_valid ? NULL : &bad->udma_mode,
		&selected->udma_mode);
	selected->udma_valid = !EFI_ERROR(status);
	return selected->pio_valid || selected->udma_valid ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

static EFI_STATUS index_of(const struct cdk2_sata_controller *controller,
	UINT8 channel, UINT8 device, UINTN *index)
{
	if (controller == NULL || index == NULL ||
	    channel >= controller->geometry.channels ||
	    device >= controller->geometry.devices)
		return EFI_INVALID_PARAMETER;
	*index = (UINTN)channel * controller->geometry.devices + device;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_controller_init(struct cdk2_sata_controller *controller,
	const struct cdk2_sata_geometry *geometry)
{
	if (controller == NULL || geometry == NULL || geometry->channels == 0U ||
	    geometry->channels > CDK2_SATA_MAX_CHANNELS || geometry->devices == 0U ||
	    geometry->devices > CDK2_SATA_MAX_DEVICES)
		return EFI_INVALID_PARAMETER;
	memset(controller, 0, sizeof(*controller)); controller->geometry = *geometry;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_get_channel(const struct cdk2_sata_controller *controller,
	UINT8 channel, BOOLEAN *enabled, UINT8 *devices)
{
	if (controller == NULL || enabled == NULL || devices == NULL)
		return EFI_INVALID_PARAMETER;
	if (channel >= controller->geometry.channels) {
		*enabled = FALSE; return EFI_INVALID_PARAMETER;
	}
	*enabled = TRUE; *devices = controller->geometry.devices; return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_submit(struct cdk2_sata_controller *controller, UINT8 channel,
	UINT8 device, const struct cdk2_ata_identify *identify)
{
	UINTN index = 0; EFI_STATUS status = index_of(controller, channel, device, &index);
	if (EFI_ERROR(status))
		return status;
	controller->identify_valid[index] = identify != NULL;
	if (identify != NULL)
		controller->identify[index] = *identify;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_disqualify(struct cdk2_sata_controller *controller, UINT8 channel,
	UINT8 device, const struct cdk2_ata_mode *bad)
{
	UINTN index; EFI_STATUS status;
	if (bad == NULL)
		return EFI_INVALID_PARAMETER;
	status = index_of(controller, channel, device, &index);
	if (!EFI_ERROR(status)) {
		controller->bad[index] = *bad;
		controller->bad_valid[index] = TRUE;
	}
	return status;
}

EFI_STATUS cdk2_sata_mode(struct cdk2_sata_controller *controller, UINT8 channel,
	UINT8 device, struct cdk2_ata_mode *selected)
{
	UINTN index = 0; EFI_STATUS status = index_of(controller, channel, device, &index);
	if (EFI_ERROR(status) || selected == NULL)
		return EFI_INVALID_PARAMETER;
	if (!controller->identify_valid[index])
		return EFI_NOT_READY;
	return cdk2_sata_calculate_mode(&controller->identify[index],
		controller->bad_valid[index] ? &controller->bad[index] : NULL, selected);
}
