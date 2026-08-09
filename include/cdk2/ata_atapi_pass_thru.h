/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_ATA_ATAPI_PASS_THRU_H_
#define CDK2_ATA_ATAPI_PASS_THRU_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_ATA_MAX_DEVICES 64U
#define CDK2_ATA_MAX_CONTROLLERS 8U
#define CDK2_ATA_NO_PORT_MULTIPLIER 0xffffU
#define CDK2_ATA_PASS_THRU_ATTRIBUTES_PHYSICAL 0x0001U
#define CDK2_ATA_PASS_THRU_ATTRIBUTES_LOGICAL 0x0002U
#define CDK2_ATA_PASS_THRU_ATTRIBUTES_NONBLOCKIO 0x0004U

enum cdk2_ata_mode { CDK2_ATA_IDE, CDK2_ATA_AHCI };
enum cdk2_ata_device_type { CDK2_ATA_DISK, CDK2_ATAPI_DEVICE, CDK2_PORT_MULTIPLIER };

struct cdk2_ata_device {
	UINT16 port, multiplier;
	enum cdk2_ata_device_type type;
};
struct cdk2_ata_topology {
	enum cdk2_ata_mode mode;
	struct cdk2_ata_device devices[CDK2_ATA_MAX_DEVICES];
	size_t count;
	UINT16 previous_port, previous_multiplier;
};

#pragma pack(push, 1)
struct cdk2_device_path_header { UINT8 type, subtype; UINT8 length[2]; };
struct cdk2_atapi_device_path {
	struct cdk2_device_path_header header;
	UINT8 primary_secondary, slave_master;
	UINT16 lun;
};
struct cdk2_sata_device_path {
	struct cdk2_device_path_header header;
	UINT16 hba_port, multiplier, lun;
};
#pragma pack(pop)

struct cdk2_ata_pass_thru_mode { UINT32 attributes, io_align; };
struct cdk2_ata_command_block {
	UINT8 reserved1[2], command, features, sector_number, cylinder_low;
	UINT8 cylinder_high, device_head, sector_number_exp, cylinder_low_exp;
	UINT8 cylinder_high_exp, features_exp, sector_count, sector_count_exp;
	UINT8 reserved2[6];
};
struct cdk2_ata_status_block {
	UINT8 reserved1[2], status, error, sector_number, cylinder_low;
	UINT8 cylinder_high, device_head, sector_number_exp, cylinder_low_exp;
	UINT8 cylinder_high_exp, reserved2, sector_count, sector_count_exp;
	UINT8 reserved3[6];
};
struct cdk2_ata_command_packet {
	struct cdk2_ata_status_block *asb;
	struct cdk2_ata_command_block *acb;
	UINT64 timeout;
	void *in_data, *out_data;
	UINT32 in_length, out_length;
	UINT8 protocol, length;
};
struct cdk2_ata_pass_thru_protocol {
	struct cdk2_ata_pass_thru_mode *mode;
	void *pass_thru, *get_next_port, *get_next_device, *build_device_path;
	void *get_device, *reset_port, *reset_device;
};

EFI_STATUS cdk2_ata_topology_init(struct cdk2_ata_topology *topology,
	enum cdk2_ata_mode mode);
EFI_STATUS cdk2_ata_add_device(struct cdk2_ata_topology *topology, UINT16 port,
	UINT16 multiplier, enum cdk2_ata_device_type type);
EFI_STATUS cdk2_ata_get_next_port(struct cdk2_ata_topology *topology, UINT16 *port);
EFI_STATUS cdk2_ata_get_next_device(struct cdk2_ata_topology *topology, UINT16 port,
	UINT16 *multiplier);
EFI_STATUS cdk2_ata_build_device_path(const struct cdk2_ata_topology *topology,
	UINT16 port, UINT16 multiplier, void *path, size_t *path_size);
EFI_STATUS cdk2_ata_get_device(const struct cdk2_ata_topology *topology,
	const void *path, size_t path_size, UINT16 *port, UINT16 *multiplier);
EFI_STATUS cdk2_ata_validate_transfer(UINT8 protocol, UINT8 length,
	const void *in_buffer, UINT32 in_length, const void *out_buffer,
	UINT32 out_length, UINT32 io_align);

struct cdk2_ata_binding_services {
	void *context;
	EFI_STATUS (*open_path)(void *context, void *controller);
	EFI_STATUS (*close_path)(void *context, void *controller);
	EFI_STATUS (*open_ide)(void *context, void *controller, void **ide);
	EFI_STATUS (*close_ide)(void *context, void *controller);
	EFI_STATUS (*get_pci)(void *context, void *controller, void **pci);
	EFI_STATUS (*read_class)(void *context, void *pci, UINT8 code[3]);
	EFI_STATUS (*get_attributes)(void *context, void *pci, UINT64 *original,
		UINT64 *supported);
	EFI_STATUS (*enable_attributes)(void *context, void *pci, UINT64 attributes);
	EFI_STATUS (*restore_attributes)(void *context, void *pci, UINT64 attributes);
	EFI_STATUS (*discover_ide)(void *context, void *pci, void *ide,
		struct cdk2_ata_topology *topology);
	EFI_STATUS (*discover_ahci)(void *context, void *pci, UINT32 *capability,
		UINT32 *ports_implemented, struct cdk2_ata_topology *topology);
	EFI_STATUS (*install)(void *context, void *controller,
		struct cdk2_ata_topology *topology);
	EFI_STATUS (*uninstall)(void *context, void *controller,
		struct cdk2_ata_topology *topology);
};
struct cdk2_ata_controller {
	void *handle, *pci, *ide;
	struct cdk2_ata_topology topology;
	UINT64 original_attributes, enabled_attributes;
	UINT32 ahci_capability, ports_implemented;
	UINT8 started, protocols_installed;
};
struct cdk2_ata_binding {
	struct cdk2_ata_binding_services services;
	struct cdk2_ata_controller controllers[CDK2_ATA_MAX_CONTROLLERS];
	size_t count;
};

EFI_STATUS cdk2_ata_binding_init(struct cdk2_ata_binding *binding,
	const struct cdk2_ata_binding_services *services);
EFI_STATUS cdk2_ata_binding_supported(struct cdk2_ata_binding *binding,
	void *controller);
EFI_STATUS cdk2_ata_binding_start(struct cdk2_ata_binding *binding, void *controller);
EFI_STATUS cdk2_ata_binding_stop(struct cdk2_ata_binding *binding, void *controller);

#endif
