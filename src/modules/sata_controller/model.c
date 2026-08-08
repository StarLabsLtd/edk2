/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/sata_controller.h>

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
	channels = (UINT8)((cap & 0x1fU) + 1U);
	if (channels > CDK2_SATA_MAX_CHANNELS ||
	    (channels != 32U && (ports >> channels) != 0U))
		return EFI_DEVICE_ERROR;
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
		if (mode > 4U) mode = 4U;
		minimum = identify->min_pio_cycle_time;
		if (minimum > 240U) mode = 0U;
		else if (minimum > 180U && mode > 2U) mode = 2U;
		else if (minimum > 120U && mode > 3U) mode = 3U;
		if (disqualified != NULL && *disqualified < 2U)
			return EFI_UNSUPPORTED;
		if (disqualified != NULL && mode >= *disqualified)
			mode = (UINT16)(*disqualified - 1U);
		*selected = mode < 2U ? 1U : mode;
	} else {
		if (disqualified != NULL && *disqualified < 2U)
			return EFI_UNSUPPORTED;
		if (disqualified != NULL && mode == *disqualified) mode--;
		*selected = mode < 2U ? 1U : 2U;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_sata_best_udma(const struct cdk2_ata_identify *identify,
	const UINT16 *disqualified, UINT16 *selected)
{
	UINT16 mask, mode = 0;
	if (identify == NULL || selected == NULL) return EFI_INVALID_PARAMETER;
	if ((identify->field_validity & 4U) == 0U) return EFI_UNSUPPORTED;
	mask = identify->ultra_dma_mode & 0x3fU;
	while ((mask >>= 1) != 0U) mode++;
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
	if (selected == NULL) return EFI_INVALID_PARAMETER;
	status = cdk2_sata_best_pio(identify, bad == NULL ? NULL : &bad->pio_mode,
		&selected->pio_mode);
	if (EFI_ERROR(status)) return status;
	status = cdk2_sata_best_udma(identify,
		bad == NULL || !bad->udma_valid ? NULL : &bad->udma_mode,
		&selected->udma_mode);
	selected->udma_valid = !EFI_ERROR(status);
	return EFI_SUCCESS;
}
