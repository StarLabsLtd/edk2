/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SATA_CONTROLLER_H_
#define CDK2_SATA_CONTROLLER_H_

#include <stdint.h>
#include <uefi.h>

#define CDK2_SATA_MAX_CHANNELS 32U
#define CDK2_SATA_MAX_DEVICES 15U

struct cdk2_ata_identify {
	uint16_t pio_cycle_timing;
	uint16_t field_validity;
	uint16_t advanced_pio_modes;
	uint16_t min_pio_cycle_time;
	uint16_t ultra_dma_mode;
};
struct cdk2_ata_mode {
	uint16_t pio_mode, udma_mode;
	BOOLEAN pio_valid, udma_valid;
};
struct cdk2_sata_geometry { uint8_t channels, devices; BOOLEAN ahci; };
struct cdk2_sata_controller {
	struct cdk2_sata_geometry geometry;
	struct cdk2_ata_identify identify[CDK2_SATA_MAX_CHANNELS * CDK2_SATA_MAX_DEVICES];
	struct cdk2_ata_mode bad[CDK2_SATA_MAX_CHANNELS * CDK2_SATA_MAX_DEVICES];
	BOOLEAN bad_valid[CDK2_SATA_MAX_CHANNELS * CDK2_SATA_MAX_DEVICES];
	BOOLEAN identify_valid[CDK2_SATA_MAX_CHANNELS * CDK2_SATA_MAX_DEVICES];
};

EFI_STATUS cdk2_sata_geometry(UINT8 base_class, UINT8 sub_class,
	UINT32 ahci_cap, UINT32 ports_implemented, struct cdk2_sata_geometry *geometry);
EFI_STATUS cdk2_sata_best_pio(const struct cdk2_ata_identify *identify,
	const UINT16 *disqualified, UINT16 *selected);
EFI_STATUS cdk2_sata_best_udma(const struct cdk2_ata_identify *identify,
	const UINT16 *disqualified, UINT16 *selected);
EFI_STATUS cdk2_sata_calculate_mode(const struct cdk2_ata_identify *identify,
	const struct cdk2_ata_mode *bad, struct cdk2_ata_mode *selected);
EFI_STATUS cdk2_sata_controller_init(struct cdk2_sata_controller *controller,
	const struct cdk2_sata_geometry *geometry);
EFI_STATUS cdk2_sata_get_channel(const struct cdk2_sata_controller *controller,
	UINT8 channel, BOOLEAN *enabled, UINT8 *devices);
EFI_STATUS cdk2_sata_submit(struct cdk2_sata_controller *controller, UINT8 channel,
	UINT8 device, const struct cdk2_ata_identify *identify);
EFI_STATUS cdk2_sata_disqualify(struct cdk2_sata_controller *controller, UINT8 channel,
	UINT8 device, const struct cdk2_ata_mode *bad);
EFI_STATUS cdk2_sata_mode(struct cdk2_sata_controller *controller, UINT8 channel,
	UINT8 device, struct cdk2_ata_mode *selected);

#endif
