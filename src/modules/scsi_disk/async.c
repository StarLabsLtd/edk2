/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_disk.h>

#include <string.h>

static void dispatch(struct cdk2_scsi_disk_async *async);

static void finish_head(struct cdk2_scsi_disk_async *async, EFI_STATUS status)
{
	struct cdk2_scsi_disk_async_task *task = &async->queue[async->head];

	task->token->transaction_status = status;
	(void)async->signal(async->signal_context, task->token->event);
	memset(task, 0, sizeof(*task));
	async->head = (async->head + 1U) % CDK2_SCSI_DISK_ASYNC_DEPTH;
	async->count--;
}

static void parent_complete(void *opaque, EFI_STATUS status, UINT8 host_status,
	UINT8 target_status)
{
	struct cdk2_scsi_disk_async *async = opaque;

	async->parent_active = FALSE;
	async->completion_status = status;
	async->completion_host = host_status;
	async->completion_target = target_status;
	async->completion_pending = TRUE;
	if (!async->dispatching && !async->aborting)
		dispatch(async);
}

static EFI_STATUS submit_chunk(struct cdk2_scsi_disk_async *async)
{
	struct cdk2_scsi_disk_async_task *task = &async->queue[async->head];
	struct cdk2_scsi_disk_command command;
	UINT32 blocks = task->remaining > task->maximum ? task->maximum :
		(UINT32)task->remaining;
	UINT32 bytes = blocks * async->disk->media.block_size;
	EFI_STATUS status;

	status = cdk2_scsi_disk_build_rw(task->write, task->lba, blocks,
		async->disk->cdb16, &command);
	if (EFI_ERROR(status))
		return status;
	async->parent_active = TRUE;
	status = async->disk->transport.submit(async->disk->transport.context,
		&command, task->buffer, bytes, task->write, parent_complete, async);
	if (EFI_ERROR(status) && async->parent_active)
		async->parent_active = FALSE;
	return status;
}

static void dispatch(struct cdk2_scsi_disk_async *async)
{
	if (async->dispatching || async->aborting)
		return;
	async->dispatching = TRUE;
	while (async->count != 0U && !async->parent_active) {
		struct cdk2_scsi_disk_async_task *task = &async->queue[async->head];
		EFI_STATUS status;
		if (task->flush || task->remaining == 0U) {
			finish_head(async, EFI_SUCCESS);
			continue;
		}

		if (async->completion_pending) {
			UINT32 blocks = task->remaining > task->maximum ? task->maximum :
				(UINT32)task->remaining;
			UINT32 bytes = blocks * async->disk->media.block_size;

			status = async->completion_status;
			if (!EFI_ERROR(status) &&
			    (async->completion_host != 0U || async->completion_target != 0U))
				status = EFI_DEVICE_ERROR;
			async->completion_pending = FALSE;
			if (EFI_ERROR(status)) {
				finish_head(async, status);
				continue;
			}
			task->buffer += bytes;
			task->lba += blocks;
			task->remaining -= blocks;
			if (task->remaining == 0U) {
				finish_head(async, EFI_SUCCESS);
				continue;
			}
		}
		status = submit_chunk(async);
		if (EFI_ERROR(status)) {
			if (!task->accepted) {
				async->submission_status = status;
				memset(task, 0, sizeof(*task));
				async->head = (async->head + 1U) %
					CDK2_SCSI_DISK_ASYNC_DEPTH;
				async->count--;
			} else {
				finish_head(async, status);
			}
		} else {
			task->accepted = TRUE;
		}
		if (async->parent_active)
			break;
	}
	async->dispatching = FALSE;
	if (async->completion_pending && !async->parent_active)
		dispatch(async);
}

EFI_STATUS cdk2_scsi_disk_async_init(struct cdk2_scsi_disk_async *async,
	struct cdk2_scsi_disk *disk, void *signal_context,
	EFI_STATUS (*signal)(void *, void *))
{
	if (async == NULL || disk == NULL || disk->transport.submit == NULL ||
	    signal == NULL)
		return EFI_INVALID_PARAMETER;
	memset(async, 0, sizeof(*async));
	async->disk = disk;
	async->signal_context = signal_context;
	async->signal = signal;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_async_submit(struct cdk2_scsi_disk_async *async,
	UINT32 media_id, UINT64 lba, UINTN size, void *buffer, BOOLEAN write,
	struct cdk2_block_io2_token *token)
{
	struct cdk2_scsi_disk_async_task *task;
	UINT32 maximum;
	EFI_STATUS original_status;
	EFI_STATUS status;

	if (async == NULL || token == NULL || token->event == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_scsi_disk_validate(&async->disk->media, media_id, lba, size,
		buffer, write);
	if (EFI_ERROR(status))
		return status;
	if (async->stopping)
		return EFI_NOT_READY;
	if (async->count == CDK2_SCSI_DISK_ASYNC_DEPTH)
		return EFI_OUT_OF_RESOURCES;
	for (UINTN index = 0; index < async->count; index++)
		if (async->queue[(async->head + index) %
		    CDK2_SCSI_DISK_ASYNC_DEPTH].token == token)
			return EFI_ALREADY_STARTED;
	maximum = async->disk->cdb16 ? UINT32_MAX : UINT16_MAX;
	if (maximum > UINT32_MAX / async->disk->media.block_size)
		maximum = UINT32_MAX / async->disk->media.block_size;
	if (maximum == 0U)
		return EFI_BAD_BUFFER_SIZE;
	task = &async->queue[(async->head + async->count) %
		CDK2_SCSI_DISK_ASYNC_DEPTH];
	*task = (struct cdk2_scsi_disk_async_task) { .token = token,
		.buffer = buffer, .lba = lba,
		.remaining = size / async->disk->media.block_size,
		.maximum = maximum, .write = write };
	original_status = token->transaction_status;
	token->transaction_status = EFI_NOT_READY;
	async->submission_status = EFI_SUCCESS;
	async->count++;
	if (async->count == 1U)
		dispatch(async);
	if (EFI_ERROR(async->submission_status))
		token->transaction_status = original_status;
	return async->submission_status;
}

EFI_STATUS cdk2_scsi_disk_async_flush(struct cdk2_scsi_disk_async *async,
	struct cdk2_block_io2_token *token)
{
	struct cdk2_scsi_disk_async_task *task;

	if (async == NULL || token == NULL || token->event == NULL)
		return EFI_INVALID_PARAMETER;
	if (async->stopping)
		return EFI_NOT_READY;
	if (async->count == CDK2_SCSI_DISK_ASYNC_DEPTH)
		return EFI_OUT_OF_RESOURCES;
	for (UINTN index = 0; index < async->count; index++)
		if (async->queue[(async->head + index) %
		    CDK2_SCSI_DISK_ASYNC_DEPTH].token == token)
			return EFI_ALREADY_STARTED;
	task = &async->queue[(async->head + async->count) %
		CDK2_SCSI_DISK_ASYNC_DEPTH];
	*task = (struct cdk2_scsi_disk_async_task) { .token = token, .flush = TRUE,
		.accepted = TRUE };
	token->transaction_status = EFI_NOT_READY;
	async->count++;
	if (async->count == 1U)
		dispatch(async);
	return EFI_SUCCESS;
}

static EFI_STATUS abort_all(struct cdk2_scsi_disk_async *async, BOOLEAN stop)
{
	EFI_STATUS status = EFI_SUCCESS;

	if (async == NULL || async->disk == NULL)
		return EFI_INVALID_PARAMETER;
	if (async->dispatching)
		return EFI_NOT_READY;
	async->aborting = TRUE;
	if (async->parent_active) {
		if (async->disk->transport.cancel == NULL) {
			async->aborting = FALSE;
			return EFI_UNSUPPORTED;
		}
		status = async->disk->transport.cancel(async->disk->transport.context);
		if (EFI_ERROR(status)) {
			async->aborting = FALSE;
			return status;
		}
		async->parent_active = FALSE;
	}
	async->completion_pending = FALSE;
	while (async->count != 0U)
		finish_head(async, EFI_ABORTED);
	async->aborting = FALSE;
	async->stopping = stop;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_async_reset(struct cdk2_scsi_disk_async *async)
{
	return abort_all(async, FALSE);
}

EFI_STATUS cdk2_scsi_disk_async_stop(struct cdk2_scsi_disk_async *async)
{
	return abort_all(async, TRUE);
}
