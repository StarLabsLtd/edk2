/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_SCSI_DISK_H_
#define CDK2_SCSI_DISK_H_

#include <uefi.h>

#define CDK2_SCSI_DISK_CDB_MAX 16U
#define CDK2_SCSI_DISK_ASYNC_DEPTH 16U
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

struct cdk2_scsi_disk_transport {
	void *context;
	EFI_STATUS (*execute)(void *, struct cdk2_scsi_disk_command *, void *, UINT32,
		BOOLEAN, UINT8 *, UINT8 *);
	EFI_STATUS (*submit)(void *, struct cdk2_scsi_disk_command *, void *, UINT32,
		BOOLEAN, void (*)(void *, EFI_STATUS, UINT8, UINT8), void *);
	EFI_STATUS (*cancel)(void *context);
};

struct cdk2_scsi_disk_token {
	void *event;
	EFI_STATUS status;
};

struct cdk2_scsi_disk_async_task {
	struct cdk2_scsi_disk_token *token;
	UINT8 *buffer;
	UINT64 lba, remaining;
	UINT32 maximum;
	BOOLEAN write, accepted;
};

struct cdk2_scsi_disk_async {
	struct cdk2_scsi_disk *disk;
	struct cdk2_scsi_disk_async_task queue[CDK2_SCSI_DISK_ASYNC_DEPTH];
	void *signal_context;
	EFI_STATUS (*signal)(void *context, void *event);
	UINTN head, count;
	BOOLEAN parent_active, dispatching, completion_pending, stopping, aborting;
	EFI_STATUS submission_status;
	EFI_STATUS completion_status;
	UINT8 completion_host, completion_target;
};

struct cdk2_scsi_disk {
	struct cdk2_scsi_disk_media media;
	struct cdk2_scsi_disk_transport transport;
	BOOLEAN cdb16;
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
EFI_STATUS cdk2_scsi_disk_async_submit(struct cdk2_scsi_disk_async *async,
	UINT32 media_id, UINT64 lba, UINTN size, void *buffer, BOOLEAN write,
	struct cdk2_scsi_disk_token *token);
EFI_STATUS cdk2_scsi_disk_async_reset(struct cdk2_scsi_disk_async *async);
EFI_STATUS cdk2_scsi_disk_async_stop(struct cdk2_scsi_disk_async *async);

#endif
