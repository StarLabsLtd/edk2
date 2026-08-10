/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_SCSI_DISK_H_
#define CDK2_SCSI_DISK_H_

#include <cdk2/partition.h>
#include <uefi.h>

#define CDK2_SCSI_DISK_CDB_MAX 16U
#define CDK2_SCSI_DISK_ASYNC_DEPTH 16U
#define CDK2_SCSI_DISK_MAX_CONTROLLERS 16U
#ifndef EFI_WRITE_PROTECTED
#define EFI_WRITE_PROTECTED EFIERR(8)
#endif
#ifndef EFI_NO_MEDIA
#define EFI_NO_MEDIA EFIERR(12)
#endif
#ifndef EFI_MEDIA_CHANGED
#define EFI_MEDIA_CHANGED EFIERR(13)
#endif
#ifndef EFI_ABORTED
#define EFI_ABORTED EFIERR(21)
#endif

struct cdk2_scsi_disk_media {
	UINT32 media_id;
	BOOLEAN removable;
	BOOLEAN present;
	BOOLEAN read_only;
	UINT32 block_size;
	UINT32 io_align;
	UINT64 last_block;
};

struct cdk2_scsi_disk_command {
	UINT8 cdb[CDK2_SCSI_DISK_CDB_MAX];
	UINT8 cdb_length;
	UINT32 blocks;
};

typedef EFI_STATUS cdk2_scsi_disk_execute_fn(void *context,
	struct cdk2_scsi_disk_command *command, void *buffer, UINT32 bytes,
	BOOLEAN write, UINT8 *host, UINT8 *target);
typedef void cdk2_scsi_disk_complete_fn(void *context, EFI_STATUS status,
	UINT8 host, UINT8 target);
typedef EFI_STATUS cdk2_scsi_disk_submit_fn(void *context,
	struct cdk2_scsi_disk_command *command, void *buffer, UINT32 bytes,
	BOOLEAN write, cdk2_scsi_disk_complete_fn *complete, void *complete_context);
typedef EFI_STATUS cdk2_scsi_disk_simple_fn(void *context);

struct cdk2_scsi_disk_transport {
	void *context;
	cdk2_scsi_disk_execute_fn *execute;
	cdk2_scsi_disk_submit_fn *submit;
	cdk2_scsi_disk_simple_fn *cancel;
	cdk2_scsi_disk_simple_fn *wait;
};

struct cdk2_scsi_disk_async_task {
	struct cdk2_block_io2_token *token;
	UINT8 *buffer;
	UINT64 lba, remaining;
	UINT32 maximum;
	BOOLEAN write, accepted, flush;
};

typedef EFI_STATUS cdk2_scsi_disk_signal_fn(void *context, void *event);
typedef UINTN cdk2_scsi_disk_lock_fn(void *context);
typedef void cdk2_scsi_disk_unlock_fn(void *context, UINTN state);

struct cdk2_scsi_disk_async {
	struct cdk2_scsi_disk *disk;
	struct cdk2_scsi_disk_async_task queue[CDK2_SCSI_DISK_ASYNC_DEPTH];
	void *signal_context;
	cdk2_scsi_disk_signal_fn *signal;
	void *lock_context;
	cdk2_scsi_disk_lock_fn *lock;
	cdk2_scsi_disk_unlock_fn *unlock;
	UINTN head, count;
	BOOLEAN parent_active, dispatching, completion_pending, stopping, aborting;
	BOOLEAN sync_busy;
	EFI_STATUS submission_status;
	EFI_STATUS completion_status;
	UINT8 completion_host, completion_target;
};

struct cdk2_scsi_disk {
	struct cdk2_scsi_disk_media media;
	struct cdk2_scsi_disk_transport transport;
	UINT8 inquiry[36];
	UINT8 sense[18];
	UINT8 sense_length;
	BOOLEAN cdb16;
};

struct cdk2_scsi_disk_info;
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_info_inquiry_fn(
	struct cdk2_scsi_disk_info *, void *, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_info_identify_fn(
	struct cdk2_scsi_disk_info *, void *, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_info_sense_fn(
	struct cdk2_scsi_disk_info *, void *, UINT32 *, UINT8 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_scsi_disk_info_which_ide_fn(
	struct cdk2_scsi_disk_info *, UINT32 *, UINT32 *);
struct cdk2_scsi_disk_info {
	EFI_GUID interface;
	cdk2_scsi_disk_info_inquiry_fn *inquiry;
	cdk2_scsi_disk_info_identify_fn *identify;
	cdk2_scsi_disk_info_sense_fn *sense_data;
	cdk2_scsi_disk_info_which_ide_fn *which_ide;
};

struct cdk2_scsi_disk_block {
	struct cdk2_block_io block;
	struct cdk2_block_io2 block2;
	struct cdk2_block_media media;
	struct cdk2_scsi_disk *disk;
	struct cdk2_scsi_disk_async *async;
};

struct cdk2_scsi_disk_bound_controller {
	void *handle;
	void *scsi_io;
	struct cdk2_scsi_disk_backend *backend;
	struct cdk2_scsi_disk disk;
	struct cdk2_scsi_disk_async async;
	struct cdk2_scsi_disk_block block;
	struct cdk2_scsi_disk_info disk_info;
	BOOLEAN parent_open, installed;
};

struct cdk2_scsi_disk_binding_services {
	void *context;
	EFI_STATUS (*open_parent)(void *context, void *controller, void **scsi_io);
	EFI_STATUS (*close_parent)(void *context, void *controller);
	EFI_STATUS (*probe)(void *context,
		struct cdk2_scsi_disk_bound_controller *bound);
	EFI_STATUS (*install)(void *context, void *controller,
		struct cdk2_scsi_disk_bound_controller *bound);
	EFI_STATUS (*uninstall)(void *context, void *controller,
		struct cdk2_scsi_disk_bound_controller *bound);
	EFI_STATUS (*signal)(void *context, void *event);
	UINTN (*lock)(void *context);
	void (*unlock)(void *context, UINTN state);
	EFI_STATUS (*allocate)(void *context, UINTN size, void **buffer);
	void (*release)(void *context, void *buffer);
};

struct cdk2_scsi_disk_binding {
	struct cdk2_scsi_disk_binding_services services;
	struct cdk2_scsi_disk_bound_controller *controllers[
		CDK2_SCSI_DISK_MAX_CONTROLLERS];
	UINTN count;
};

struct cdk2_scsi_io;
typedef EFI_STATUS cdk2_scsi_disk_allocate_fn(void *context, UINTN size,
	void **buffer);
typedef void cdk2_scsi_disk_release_fn(void *context, void *buffer);
typedef void CDK2_MS_ABI cdk2_scsi_disk_notify_fn(void *event, void *context);
typedef EFI_STATUS cdk2_scsi_disk_create_event_fn(void *context,
	cdk2_scsi_disk_notify_fn *notify, void *notify_context, void **event);
typedef EFI_STATUS cdk2_scsi_disk_event_fn(void *context, void *event);
struct cdk2_scsi_disk_backend_services {
	void *context;
	cdk2_scsi_disk_allocate_fn *allocate;
	cdk2_scsi_disk_release_fn *release;
	cdk2_scsi_disk_create_event_fn *create_event;
	cdk2_scsi_disk_event_fn *close_event;
	cdk2_scsi_disk_event_fn *wait_event;
};

struct cdk2_scsi_disk_backend {
	struct cdk2_scsi_io *io;
	struct cdk2_scsi_disk_backend_services services;
	void *active_event;
};

EFI_STATUS cdk2_scsi_disk_parse_capacity10(const UINT8 response[8],
	UINT64 *last_block, UINT32 *block_size, BOOLEAN *needs_capacity16);
EFI_STATUS cdk2_scsi_disk_parse_capacity16(const UINT8 response[32],
	UINT64 *last_block, UINT32 *block_size);
EFI_STATUS cdk2_scsi_disk_build_rw(BOOLEAN write, UINT64 lba, UINT32 blocks,
	BOOLEAN cdb16, struct cdk2_scsi_disk_command *command);
EFI_STATUS cdk2_scsi_disk_validate(const struct cdk2_scsi_disk_media *media,
	UINT32 media_id, UINT64 lba, UINTN size, const void *buffer, BOOLEAN write);
EFI_STATUS cdk2_scsi_disk_read(struct cdk2_scsi_disk *disk, UINT32 media_id,
	UINT64 lba, UINTN size, void *buffer);
EFI_STATUS cdk2_scsi_disk_write(struct cdk2_scsi_disk *disk, UINT32 media_id,
	UINT64 lba, UINTN size, const void *buffer);
EFI_STATUS cdk2_scsi_disk_async_init(struct cdk2_scsi_disk_async *async,
	struct cdk2_scsi_disk *disk, void *signal_context,
	EFI_STATUS (*signal)(void *, void *));
EFI_STATUS cdk2_scsi_disk_async_set_lock(struct cdk2_scsi_disk_async *async,
	void *context, UINTN (*lock)(void *), void (*unlock)(void *, UINTN));
EFI_STATUS cdk2_scsi_disk_async_submit(struct cdk2_scsi_disk_async *async,
	UINT32 media_id, UINT64 lba, UINTN size, void *buffer, BOOLEAN write,
	struct cdk2_block_io2_token *token);
EFI_STATUS cdk2_scsi_disk_async_flush(struct cdk2_scsi_disk_async *async,
	struct cdk2_block_io2_token *token);
EFI_STATUS cdk2_scsi_disk_async_reset(struct cdk2_scsi_disk_async *async);
EFI_STATUS cdk2_scsi_disk_async_stop(struct cdk2_scsi_disk_async *async);
EFI_STATUS cdk2_scsi_disk_async_read(struct cdk2_scsi_disk_async *async,
	UINT32 media_id, UINT64 lba, UINTN size, void *buffer);
EFI_STATUS cdk2_scsi_disk_async_write(struct cdk2_scsi_disk_async *async,
	UINT32 media_id, UINT64 lba, UINTN size, const void *buffer);
EFI_STATUS cdk2_scsi_disk_async_drain(struct cdk2_scsi_disk_async *async);
EFI_STATUS cdk2_scsi_disk_block_init(struct cdk2_scsi_disk_block *instance,
	struct cdk2_scsi_disk *disk, struct cdk2_scsi_disk_async *async);
EFI_STATUS cdk2_scsi_disk_info_init(
	struct cdk2_scsi_disk_bound_controller *bound);
EFI_STATUS cdk2_scsi_disk_binding_init(struct cdk2_scsi_disk_binding *binding,
	const struct cdk2_scsi_disk_binding_services *services);
EFI_STATUS cdk2_scsi_disk_binding_start(struct cdk2_scsi_disk_binding *binding,
	void *controller);
EFI_STATUS cdk2_scsi_disk_binding_stop(struct cdk2_scsi_disk_binding *binding,
	void *controller);
EFI_STATUS cdk2_scsi_disk_backend_init(struct cdk2_scsi_disk_backend *backend,
	struct cdk2_scsi_io *io,
	const struct cdk2_scsi_disk_backend_services *services,
	struct cdk2_scsi_disk *disk);

#endif
