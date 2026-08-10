/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_ATA_BUS_H
#define CDK2_ATA_BUS_H

#include <cdk2/ata_atapi_pass_thru.h>
#include <cdk2/disk_io.h>
#include <cdk2/partition.h>

#define CDK2_ATA_BUS_MAX_CONTROLLERS 8U
#define CDK2_ATA_BUS_MAX_CHILDREN 32U
#define CDK2_EFI_NO_MEDIA EFIERR(12)

struct cdk2_ata_bus_disk_info;
typedef EFI_STATUS CDK2_MS_ABI cdk2_disk_info_inquiry_fn(
	struct cdk2_ata_bus_disk_info *, void *, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_disk_info_identify_fn(
	struct cdk2_ata_bus_disk_info *, void *, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_disk_info_sense_fn(
	struct cdk2_ata_bus_disk_info *, void *, UINT32 *, UINT8 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_disk_info_which_ide_fn(
	struct cdk2_ata_bus_disk_info *, UINT32 *, UINT32 *);
struct cdk2_ata_bus_disk_info {
	const EFI_GUID *interface;
	cdk2_disk_info_inquiry_fn *inquiry;
	cdk2_disk_info_identify_fn *identify;
	cdk2_disk_info_sense_fn *sense_data;
	cdk2_disk_info_which_ide_fn *which_ide;
};

struct cdk2_ata_bus_security;
typedef EFI_STATUS CDK2_MS_ABI cdk2_security_receive_fn(
	struct cdk2_ata_bus_security *, UINT32, UINT64, UINT8, UINT16, UINTN,
	void *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_security_send_fn(
	struct cdk2_ata_bus_security *, UINT32, UINT64, UINT8, UINT16, UINTN,
	const void *);
struct cdk2_ata_bus_security {
	cdk2_security_receive_fn *receive_data;
	cdk2_security_send_fn *send_data;
};

struct cdk2_ata_bus_media {
	UINT64 blocks;
	UINT32 block_size, io_align, logical_blocks_per_physical_block;
	UINT32 optimal_transfer_granularity;
	UINT64 lowest_aligned_lba;
	BOOLEAN removable, read_only, write_caching, lba48, trusted;
};

struct cdk2_ata_bus_child {
	void *controller;
	UINT16 port, multiplier;
	enum cdk2_ata_device_type type;
	struct cdk2_ata_bus_media geometry;
	UINT8 identify[512];
	UINT8 device_path[16];
	UINTN device_path_size;
};

struct cdk2_ata_bus_controller {
	void *handle;
	struct cdk2_ata_pass_thru_protocol *pass_thru;
	UINTN first_child, child_count;
};

struct cdk2_ata_bus {
	struct cdk2_ata_bus_controller controllers[CDK2_ATA_BUS_MAX_CONTROLLERS];
	struct cdk2_ata_bus_child children[CDK2_ATA_BUS_MAX_CHILDREN];
	UINTN controller_count, child_count;
};

EFI_STATUS cdk2_ata_bus_parse_identify(const UINT8 identify[512],
	struct cdk2_ata_bus_media *media);
EFI_STATUS cdk2_ata_bus_add_controller(struct cdk2_ata_bus *bus,
	void *handle, struct cdk2_ata_pass_thru_protocol *pass_thru,
	void (*release_path)(void *));
EFI_STATUS cdk2_ata_bus_remove_controller(struct cdk2_ata_bus *bus, void *handle);

#endif
