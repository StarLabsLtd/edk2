/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/sata_controller.h>
#include <stdio.h>

static int check(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "sata: %s\n", message);
	return !condition;
}

int main(void)
{
	struct cdk2_sata_geometry geometry;
	struct cdk2_ata_identify identify = { 2U << 8, 6, 3, 120, 0x3f };
	struct cdk2_ata_mode mode;
	struct cdk2_ata_mode bad = { 4, 5, TRUE, TRUE };
	struct cdk2_sata_controller controller;
	UINT16 disqualified = 2;
	UINT16 selected;
	BOOLEAN enabled;
	UINT8 devices;
	int failures = 0;

	failures += check(cdk2_sata_geometry(1, 1, 0, 0, &geometry) == EFI_SUCCESS &&
		geometry.channels == 2 && geometry.devices == 2, "IDE geometry");
	failures += check(cdk2_sata_geometry(1, 6, 3, 0xf, &geometry) == EFI_SUCCESS &&
		geometry.channels == 4 && geometry.devices == 1, "AHCI geometry");
	failures += check(cdk2_sata_geometry(1, 6, 0, 0x10, &geometry) == EFI_SUCCESS &&
		geometry.channels == 5, "sparse PI highest port");
	failures += check(cdk2_sata_geometry(1, 6, 0, 0, &geometry) == EFI_DEVICE_ERROR,
		"empty PI rejected");
	failures += check(cdk2_sata_best_pio(&identify, NULL, &selected) == EFI_SUCCESS &&
		selected == 4, "best PIO4");
	failures += check(cdk2_sata_best_pio(&identify, &disqualified, &selected) ==
		EFI_SUCCESS && selected == 1, "PIO disqualification");
	failures += check(cdk2_sata_calculate_mode(&identify, &bad, &mode) == EFI_SUCCESS &&
		mode.pio_mode == 3 && mode.udma_mode == 4 && mode.udma_valid,
		"collective mode");
	identify.field_validity = 2;
	failures += check(cdk2_sata_calculate_mode(&identify, NULL, &mode) == EFI_SUCCESS &&
		!mode.udma_valid && mode.pio_valid, "PIO validity is independent of UDMA");
	bad.pio_valid = FALSE;
	bad.udma_valid = TRUE;
	bad.udma_mode = 2;
	identify.field_validity = 6;
	failures += check(cdk2_sata_calculate_mode(&identify, &bad, &mode) == EFI_SUCCESS &&
		mode.pio_mode == 4 && mode.udma_mode == 1,
		"independent disqualification validity");
	bad.pio_valid = TRUE;
	bad.pio_mode = 4;
	bad.udma_valid = TRUE;
	bad.udma_mode = 5;
	failures += check(cdk2_sata_controller_init(&controller, &geometry) == EFI_SUCCESS &&
		cdk2_sata_get_channel(&controller, 3, &enabled, &devices) == EFI_SUCCESS &&
		enabled && devices == 1, "channel ABI");
	failures += check(cdk2_sata_mode(&controller, 0, 0, &mode) == EFI_NOT_READY,
		"identify required");
	identify.field_validity = 6;
	failures += check(cdk2_sata_submit(&controller, 0, 0, &identify) == EFI_SUCCESS &&
		cdk2_sata_disqualify(&controller, 0, 0, &bad) == EFI_SUCCESS &&
		cdk2_sata_mode(&controller, 0, 0, &mode) == EFI_SUCCESS &&
		mode.pio_mode == 3, "submit disqualify calculate lifecycle");
	failures += check(cdk2_sata_submit(&controller, 32, 0, &identify) ==
		EFI_INVALID_PARAMETER, "channel bounds");
	return failures != 0;
}
