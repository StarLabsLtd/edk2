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
#define CDK2_EXT_SCSI_TARGET_BYTES 16U
#define CDK2_EXT_SCSI_DIRECTION_READ 0U
#define CDK2_EXT_SCSI_DIRECTION_WRITE 1U
#define CDK2_EXT_SCSI_DIRECTION_BIDIRECTIONAL 2U

enum cdk2_ata_mode { CDK2_ATA_IDE, CDK2_ATA_AHCI };
enum cdk2_ata_device_type { CDK2_ATA_DISK, CDK2_ATAPI_DEVICE, CDK2_PORT_MULTIPLIER };

struct cdk2_ata_device {
	UINT16 port, multiplier;
	enum cdk2_ata_device_type type;
	UINT32 block_size, alignment;
};
struct cdk2_ata_topology {
	enum cdk2_ata_mode mode;
	struct cdk2_ata_device devices[CDK2_ATA_MAX_DEVICES];
	size_t count;
	UINT16 previous_port, previous_multiplier;
	UINT16 multiplier_port;
	UINT8 multiplier_enumerating;
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
struct cdk2_ata_pass_thru_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_pass_thru_fn(
	struct cdk2_ata_pass_thru_protocol *, UINT16, UINT16,
	struct cdk2_ata_command_packet *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_next_port_fn(
	struct cdk2_ata_pass_thru_protocol *, UINT16 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_next_device_fn(
	struct cdk2_ata_pass_thru_protocol *, UINT16, UINT16 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_build_path_fn(
	struct cdk2_ata_pass_thru_protocol *, UINT16, UINT16, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_get_device_fn(
	struct cdk2_ata_pass_thru_protocol *, void *, UINT16 *, UINT16 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_reset_port_fn(
	struct cdk2_ata_pass_thru_protocol *, UINT16);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_reset_device_fn(
	struct cdk2_ata_pass_thru_protocol *, UINT16, UINT16);
struct cdk2_ata_pass_thru_protocol {
	struct cdk2_ata_pass_thru_mode *mode;
	cdk2_ata_pass_thru_fn *pass_thru;
	cdk2_ata_next_port_fn *get_next_port;
	cdk2_ata_next_device_fn *get_next_device;
	cdk2_ata_build_path_fn *build_device_path;
	cdk2_ata_get_device_fn *get_device;
	cdk2_ata_reset_port_fn *reset_port;
	cdk2_ata_reset_device_fn *reset_device;
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

struct cdk2_ata_controller;
struct cdk2_ata_protocol_bundle;
struct cdk2_ahci_engine;
struct cdk2_ide_engine;
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
	EFI_STATUS (*discover_ide)(void *context, struct cdk2_ata_controller *controller,
		struct cdk2_ata_topology *topology);
	EFI_STATUS (*discover_ahci)(void *context, struct cdk2_ata_controller *controller,
		UINT32 *capability,
		UINT32 *ports_implemented, struct cdk2_ata_topology *topology);
	EFI_STATUS (*prepare_engines)(void *context, struct cdk2_ata_controller *controller);
	void (*release_engines)(void *context, struct cdk2_ata_controller *controller);
	EFI_STATUS (*create_protocols)(void *context,
		struct cdk2_ata_controller *controller,
		struct cdk2_ata_protocol_bundle **protocols);
	void (*destroy_protocols)(void *context,
		struct cdk2_ata_protocol_bundle *protocols);
	EFI_STATUS (*install)(void *context, void *controller,
		struct cdk2_ata_protocol_bundle *protocols);
	EFI_STATUS (*uninstall)(void *context, void *controller,
		struct cdk2_ata_protocol_bundle *protocols);
};
struct cdk2_ata_controller {
	void *handle, *pci, *ide;
	struct cdk2_ata_topology topology;
	UINT64 original_attributes, enabled_attributes;
	UINT32 ahci_capability, ports_implemented;
	UINT8 started, protocols_installed;
	struct cdk2_ahci_engine *ahci;
	struct cdk2_ide_engine *ide_engine;
	struct cdk2_ata_protocol_bundle *protocols;
	void *backend;
};
struct cdk2_ata_binding {
	struct cdk2_ata_binding_services services;
	struct cdk2_ata_controller controllers[CDK2_ATA_MAX_CONTROLLERS];
	size_t count;
};

struct cdk2_ata_protocol_services {
	void *context;
	EFI_STATUS (*allocate)(void *context, size_t size, void **buffer);
	void (*release)(void *context, void *buffer);
};
struct cdk2_ata_protocol_instance {
	struct cdk2_ata_pass_thru_protocol protocol;
	struct cdk2_ata_pass_thru_mode mode;
	struct cdk2_ata_controller *controller;
	struct cdk2_ata_protocol_services services;
};
EFI_STATUS cdk2_ata_protocol_init(struct cdk2_ata_protocol_instance *instance,
	struct cdk2_ata_controller *controller,
	const struct cdk2_ata_protocol_services *services, UINT32 io_align);

struct cdk2_ext_scsi_mode { UINT32 adapter_id, attributes, io_align; };
struct cdk2_ext_scsi_packet {
	UINT64 timeout;
	void *in_data, *out_data, *sense_data, *cdb;
	UINT32 in_length, out_length;
	UINT8 cdb_length, direction, host_status, target_status, sense_length;
};
struct cdk2_ext_scsi_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_scsi_pass_fn(
	struct cdk2_ext_scsi_protocol *, UINT8 *, UINT64,
	struct cdk2_ext_scsi_packet *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_scsi_next_lun_fn(
	struct cdk2_ext_scsi_protocol *, UINT8 **, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_scsi_build_path_fn(
	struct cdk2_ext_scsi_protocol *, UINT8 *, UINT64, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_scsi_get_lun_fn(
	struct cdk2_ext_scsi_protocol *, void *, UINT8 **, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_scsi_reset_channel_fn(
	struct cdk2_ext_scsi_protocol *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_scsi_reset_target_fn(
	struct cdk2_ext_scsi_protocol *, UINT8 *, UINT64);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ext_scsi_next_target_fn(
	struct cdk2_ext_scsi_protocol *, UINT8 **);
struct cdk2_ext_scsi_protocol {
	struct cdk2_ext_scsi_mode *mode;
	cdk2_ext_scsi_pass_fn *pass_thru;
	cdk2_ext_scsi_next_lun_fn *get_next_target_lun;
	cdk2_ext_scsi_build_path_fn *build_device_path;
	cdk2_ext_scsi_get_lun_fn *get_target_lun;
	cdk2_ext_scsi_reset_channel_fn *reset_channel;
	cdk2_ext_scsi_reset_target_fn *reset_target_lun;
	cdk2_ext_scsi_next_target_fn *get_next_target;
};
struct cdk2_ext_scsi_instance {
	struct cdk2_ext_scsi_protocol protocol;
	struct cdk2_ext_scsi_mode mode;
	struct cdk2_ata_controller *controller;
	struct cdk2_ata_protocol_services services;
	UINT8 target[CDK2_EXT_SCSI_TARGET_BYTES];
	UINT8 previous[CDK2_EXT_SCSI_TARGET_BYTES];
	UINT64 previous_lun;
	UINT8 enumerated;
};
struct cdk2_ata_protocol_bundle {
	struct cdk2_ata_protocol_instance ata;
	struct cdk2_ext_scsi_instance ext_scsi;
};
EFI_STATUS cdk2_ext_scsi_init(struct cdk2_ext_scsi_instance *instance,
	struct cdk2_ata_controller *controller,
	const struct cdk2_ata_protocol_services *services, UINT32 io_align);

EFI_STATUS cdk2_ata_binding_init(struct cdk2_ata_binding *binding,
	const struct cdk2_ata_binding_services *services);
EFI_STATUS cdk2_ata_binding_supported(struct cdk2_ata_binding *binding,
	void *controller);
EFI_STATUS cdk2_ata_binding_start(struct cdk2_ata_binding *binding, void *controller);
EFI_STATUS cdk2_ata_binding_stop(struct cdk2_ata_binding *binding, void *controller);

#define CDK2_AHCI_MAX_SLOTS 32U
#define CDK2_AHCI_MAX_PRDT 64U
#define CDK2_AHCI_PRDT_MAX_BYTES 0x400000U
enum cdk2_ahci_dma_operation { CDK2_AHCI_BUS_MASTER_READ, CDK2_AHCI_BUS_MASTER_WRITE };
struct cdk2_ahci_prdt { UINT64 address; UINT32 bytes; UINT8 interrupt; };
struct cdk2_ahci_command {
	UINT8 fis[20], atapi[16];
	struct cdk2_ahci_prdt prdt[CDK2_AHCI_MAX_PRDT];
	UINT16 prdt_count;
	UINT8 atapi_command, write;
};
struct cdk2_ahci_dma_services {
	void *context;
	EFI_STATUS (*allocate)(void *context, size_t size, size_t alignment,
		void **host, UINT64 *device);
	EFI_STATUS (*release)(void *context, void *host, size_t size);
	EFI_STATUS (*map)(void *context, enum cdk2_ahci_dma_operation operation,
		void *host, size_t *size, UINT64 *device, void **mapping);
	EFI_STATUS (*unmap)(void *context, void *mapping);
	EFI_STATUS (*flush)(void *context);
	UINT32 (*read)(void *context, UINT16 port, UINT16 register_offset);
	EFI_STATUS (*write)(void *context, UINT16 port, UINT16 register_offset,
		UINT32 value);
	UINT64 (*time)(void *context);
	void (*delay)(void *context, UINTN microseconds);
};
struct cdk2_ahci_allocation { void *host; UINT64 device; size_t size; };
struct cdk2_ahci_engine {
	struct cdk2_ahci_dma_services services;
	struct cdk2_ahci_allocation command_list, received_fis;
	struct cdk2_ahci_allocation command_tables[CDK2_AHCI_MAX_SLOTS];
	UINT32 capability, ports_implemented, active_slots;
	UINT32 original_command[32], original_clb[32], original_clbu[32];
	UINT32 original_fb[32], original_fbu[32], configured_ports;
	UINT16 active_port;
	UINT8 slots, initialized;
};

EFI_STATUS cdk2_ahci_engine_init(struct cdk2_ahci_engine *engine,
	const struct cdk2_ahci_dma_services *services, UINT32 capability,
	UINT32 ports_implemented);
void cdk2_ahci_engine_destroy(struct cdk2_ahci_engine *engine);
EFI_STATUS cdk2_ahci_reset_controller(struct cdk2_ahci_engine *engine,
	UINT64 timeout);
EFI_STATUS cdk2_ahci_reset_port(struct cdk2_ahci_engine *engine, UINT16 port,
	UINT64 timeout);
EFI_STATUS cdk2_ahci_build_command(const struct cdk2_ata_command_packet *packet,
	UINT16 multiplier, const UINT8 *atapi, size_t atapi_size,
	struct cdk2_ahci_command *command);
EFI_STATUS cdk2_ahci_execute(struct cdk2_ahci_engine *engine, UINT16 port,
	struct cdk2_ata_command_packet *packet, const UINT8 *atapi, size_t atapi_size,
	UINT64 timeout);

#define CDK2_IDE_MAX_PRD 64U
struct cdk2_ide_channel { UINT16 command, control, bus_master; };
struct cdk2_ide_prd { UINT32 address; UINT16 count, end; };
struct cdk2_ide_services {
	void *context;
	UINT8 (*read8)(void *context, UINT16 port);
	UINT16 (*read16)(void *context, UINT16 port);
	EFI_STATUS (*write8)(void *context, UINT16 port, UINT8 value);
	EFI_STATUS (*write16)(void *context, UINT16 port, UINT16 value);
	EFI_STATUS (*write32)(void *context, UINT16 port, UINT32 value);
	EFI_STATUS (*map)(void *context, enum cdk2_ahci_dma_operation operation,
		void *host, size_t *size, UINT64 *device, void **mapping);
	EFI_STATUS (*unmap)(void *context, void *mapping);
	EFI_STATUS (*flush)(void *context);
	EFI_STATUS (*set_timing)(void *context, UINT8 channel, UINT8 device);
	UINT64 (*time)(void *context);
	void (*delay)(void *context, UINTN microseconds);
};
struct cdk2_ide_engine {
	struct cdk2_ide_services services;
	struct cdk2_ide_channel channels[2];
	struct cdk2_ide_prd prd[CDK2_IDE_MAX_PRD];
	UINT8 channel_count, initialized;
};

EFI_STATUS cdk2_ide_engine_init(struct cdk2_ide_engine *engine,
	const struct cdk2_ide_services *services, const struct cdk2_ide_channel *channels,
	UINT8 channel_count);
EFI_STATUS cdk2_ide_reset(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT64 timeout);
EFI_STATUS cdk2_ide_execute(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT8 device, struct cdk2_ata_command_packet *packet, UINT64 timeout);
EFI_STATUS cdk2_ide_atapi_execute(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT8 device, struct cdk2_ata_command_packet *packet, const UINT8 *cdb,
	size_t cdb_size, UINT64 timeout);

#endif
