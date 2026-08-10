/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_ATA_BUS_H
#define CDK2_ATA_BUS_H

#include <cdk2/ata_atapi_pass_thru.h>
#include <cdk2/disk_io.h>
#include <cdk2/partition.h>

#define CDK2_ATA_BUS_MAX_CONTROLLERS 8U
#define CDK2_ATA_BUS_MAX_CHILDREN 32U
#define CDK2_ATA_BUS_QUEUE_DEPTH 64U
#define CDK2_EFI_NO_MEDIA EFIERR(12)
#define CDK2_EFI_MEDIA_CHANGED EFIERR(13)
#define CDK2_EFI_WRITE_PROTECTED EFIERR(8)
#define CDK2_EFI_ABORTED EFIERR(21)

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
	BOOLEAN removable, read_only, write_caching, lba48, trusted, udma;
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

enum cdk2_ata_bus_operation {
	CDK2_ATA_BUS_READ, CDK2_ATA_BUS_WRITE, CDK2_ATA_BUS_FLUSH
};

struct cdk2_ata_bus_scheduler;
struct cdk2_ata_bus_request {
	struct cdk2_ata_bus_child *child;
	enum cdk2_ata_bus_operation operation;
	struct cdk2_block_io2_token *token;
	UINT32 media_id;
	UINT64 lba;
	UINTN bytes;
	void *buffer;
};

typedef EFI_STATUS cdk2_ata_bus_execute_fn(void *context,
	struct cdk2_ata_bus_child *child, struct cdk2_ata_command_packet *packet);
typedef void cdk2_ata_bus_complete_fn(void *context, EFI_STATUS status);
typedef EFI_STATUS cdk2_ata_bus_submit_fn(void *context,
	struct cdk2_ata_bus_child *child, struct cdk2_ata_command_packet *packet,
	cdk2_ata_bus_complete_fn *complete, void *complete_context);
typedef EFI_STATUS cdk2_ata_bus_wait_fn(void *context,
	struct cdk2_ata_bus_scheduler *scheduler);
typedef EFI_STATUS cdk2_ata_bus_reset_fn(void *context,
	struct cdk2_ata_bus_child *child, BOOLEAN extended_verification);
typedef void cdk2_ata_bus_signal_fn(void *context, void *event);

struct cdk2_ata_bus_transport {
	void *context;
	cdk2_ata_bus_execute_fn *execute;
	cdk2_ata_bus_submit_fn *submit;
	cdk2_ata_bus_wait_fn *wait;
	cdk2_ata_bus_reset_fn *reset;
	cdk2_ata_bus_signal_fn *signal;
};

struct cdk2_ata_bus_scheduler {
	struct cdk2_ata_bus_transport transport;
	struct cdk2_ata_bus_request queue[CDK2_ATA_BUS_QUEUE_DEPTH];
	UINTN head, count;
	struct cdk2_ata_bus_request active;
	struct cdk2_ata_command_block active_acb;
	struct cdk2_ata_status_block active_asb;
	struct cdk2_ata_command_packet active_packet;
	UINT64 active_lba;
	UINT8 *active_buffer;
	UINTN active_remaining;
	EFI_STATUS active_status;
	struct cdk2_block_io2_token *initial_token;
	EFI_STATUS initial_token_status;
	BOOLEAN stopping, worker_active, deferred, parent_active;
	BOOLEAN dispatching, completion_pending, abort_active, resetting;
};

struct cdk2_ata_bus_block_instance;
typedef EFI_STATUS cdk2_ata_bus_defer_fn(void *context,
	struct cdk2_ata_bus_block_instance *instance);
struct cdk2_ata_bus_block_instance {
	struct cdk2_block_io block;
	struct cdk2_block_io2 block2;
	struct cdk2_block_media media;
	struct cdk2_ata_bus_child *child;
	struct cdk2_ata_bus_scheduler *scheduler;
	void *defer_context;
	cdk2_ata_bus_defer_fn *defer;
};

struct cdk2_ata_bus_binding;
struct cdk2_ata_bus_bound_child;
typedef EFI_STATUS cdk2_ata_bus_parent_fn(void *context, void *controller,
	BOOLEAN by_driver, struct cdk2_ata_pass_thru_protocol **protocol);
typedef EFI_STATUS cdk2_ata_bus_close_parent_fn(void *context, void *controller,
	BOOLEAN by_driver);
typedef EFI_STATUS cdk2_ata_bus_marker_fn(void *context, void *controller,
	BOOLEAN install);
typedef EFI_STATUS cdk2_ata_bus_allocate_fn(void *context, UINTN size,
	void **buffer);
typedef void cdk2_ata_bus_release_fn(void *context, void *buffer);
typedef EFI_STATUS cdk2_ata_bus_child_protocol_fn(void *context, void **handle,
	struct cdk2_ata_bus_bound_child *child, BOOLEAN security);
typedef EFI_STATUS cdk2_ata_bus_uninstall_protocol_fn(void *context, void *handle,
	struct cdk2_ata_bus_bound_child *child, BOOLEAN security);
typedef EFI_STATUS cdk2_ata_bus_child_link_fn(void *context, void *controller,
	void *child, BOOLEAN open);
struct cdk2_ata_bus_bound_child {
	void *handle;
	struct cdk2_ata_bus_child model;
	struct cdk2_ata_bus_block_instance block;
	struct cdk2_ata_bus_disk_info disk_info;
	struct cdk2_ata_bus_security security;
	void *full_device_path;
	UINTN full_device_path_size;
	struct cdk2_ata_bus_transport transport;
	void *service_context;
	cdk2_ata_bus_allocate_fn *allocate;
	cdk2_ata_bus_release_fn *release;
	BOOLEAN installed, by_child;
};
struct cdk2_ata_bus_bound_controller {
	void *handle;
	struct cdk2_ata_pass_thru_protocol *pass_thru;
	struct cdk2_ata_bus_scheduler scheduler;
	struct cdk2_ata_bus_bound_child *children[CDK2_ATA_BUS_MAX_CHILDREN];
	UINTN child_count;
	BOOLEAN marker, parent_open, path_open;
};
struct cdk2_ata_bus_binding_services {
	void *context;
	cdk2_ata_bus_parent_fn *open_parent;
	cdk2_ata_bus_close_parent_fn *close_parent;
	cdk2_ata_bus_marker_fn *marker;
	cdk2_ata_bus_allocate_fn *allocate;
	cdk2_ata_bus_release_fn *release;
	cdk2_ata_bus_child_protocol_fn *install_child;
	cdk2_ata_bus_uninstall_protocol_fn *uninstall_child;
	cdk2_ata_bus_child_link_fn *child_link;
	cdk2_ata_bus_defer_fn *defer;
	struct cdk2_ata_bus_transport transport;
};
struct cdk2_ata_bus_binding {
	struct cdk2_ata_bus_binding_services services;
	struct cdk2_ata_bus_bound_controller *controllers[CDK2_ATA_BUS_MAX_CONTROLLERS];
	UINTN controller_count;
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
	void (*release_path)(void *, void *), void *release_context);
EFI_STATUS cdk2_ata_bus_remove_controller(struct cdk2_ata_bus *bus, void *handle);
EFI_STATUS cdk2_ata_bus_scheduler_init(struct cdk2_ata_bus_scheduler *scheduler,
	const struct cdk2_ata_bus_transport *transport);
EFI_STATUS cdk2_ata_bus_submit(struct cdk2_ata_bus_scheduler *scheduler,
	const struct cdk2_ata_bus_request *request);
EFI_STATUS cdk2_ata_bus_execute_sync(struct cdk2_ata_bus_scheduler *scheduler,
	const struct cdk2_ata_bus_request *request);
EFI_STATUS cdk2_ata_bus_worker(struct cdk2_ata_bus_scheduler *scheduler);
EFI_STATUS cdk2_ata_bus_reset(struct cdk2_ata_bus_scheduler *scheduler,
	struct cdk2_ata_bus_child *child, BOOLEAN extended_verification);
EFI_STATUS cdk2_ata_bus_stop_scheduler(struct cdk2_ata_bus_scheduler *scheduler);
EFI_STATUS cdk2_ata_bus_drain_scheduler(struct cdk2_ata_bus_scheduler *scheduler);
EFI_STATUS cdk2_ata_bus_cancel_token(struct cdk2_ata_bus_scheduler *scheduler,
	struct cdk2_block_io2_token *token);
EFI_STATUS cdk2_ata_bus_block_init(struct cdk2_ata_bus_block_instance *instance,
	struct cdk2_ata_bus_child *child, struct cdk2_ata_bus_scheduler *scheduler,
	cdk2_ata_bus_defer_fn *defer, void *defer_context);
EFI_STATUS cdk2_ata_bus_block_worker(struct cdk2_ata_bus_block_instance *instance);
EFI_STATUS cdk2_ata_bus_disk_security_init(struct cdk2_ata_bus_bound_child *child,
	const struct cdk2_ata_bus_binding_services *services);
EFI_STATUS cdk2_ata_bus_binding_init(struct cdk2_ata_bus_binding *binding,
	const struct cdk2_ata_bus_binding_services *services);
EFI_STATUS cdk2_ata_bus_binding_supported(struct cdk2_ata_bus_binding *binding,
	void *controller, void *remaining_device_path);
EFI_STATUS cdk2_ata_bus_binding_start(struct cdk2_ata_bus_binding *binding,
	void *controller, void *remaining_device_path);
EFI_STATUS cdk2_ata_bus_binding_stop(struct cdk2_ata_bus_binding *binding,
	void *controller, UINTN child_count, void **children);

#endif
