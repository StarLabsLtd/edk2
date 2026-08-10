/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <string.h>

#define CDK2_ASYNC_ABORTED EFIERR(21)

EFI_STATUS cdk2_ata_async_init(struct cdk2_ata_async_controller *async,
	struct cdk2_ata_controller *controller,
	const struct cdk2_ata_async_services *services)
{
	if (async == NULL || controller == NULL || services == NULL ||
	    services->begin == NULL || services->poll == NULL ||
	    services->abort == NULL || services->arm == NULL || services->signal == NULL)
		return EFI_INVALID_PARAMETER;
	memset(async, 0, sizeof(*async)); async->controller = controller;
	async->services = *services;
	return EFI_SUCCESS;
}

static EFI_STATUS submit(struct cdk2_ata_async_controller *async,
	UINT16 port, UINT16 multiplier, struct cdk2_ata_command_packet *packet,
	const UINT8 *cdb, UINT8 cdb_size, void *event)
{
	struct cdk2_ata_async_task *task;
	EFI_STATUS status;

	if (async == NULL || packet == NULL || event == NULL ||
	    (cdb_size != 0U && (cdb == NULL ||
	     (cdb_size > 12U && cdb_size != 16U))))
		return EFI_INVALID_PARAMETER;
	if (async->stopping)
		return EFI_NOT_READY;
	if (async->count == CDK2_ATA_ASYNC_DEPTH)
		return EFI_OUT_OF_RESOURCES;
	task = &async->queue[(async->head + async->count) % CDK2_ATA_ASYNC_DEPTH];
	*task = (struct cdk2_ata_async_task) {
		.packet = packet, .event = event, .port = port, .multiplier = multiplier,
		.status = EFI_NOT_READY, .atapi = cdb_size != 0U,
		.cdb_size = cdb_size > 12U ? 16U : cdb_size == 0U ? 0U : 12U };
	if (cdb_size != 0U)
		memcpy(task->cdb, cdb, cdb_size);
	async->count++;
	if (async->armed)
		return EFI_SUCCESS;
	async->armed = 1;
	status = async->services.arm(async->services.context, async->controller);
	if (EFI_ERROR(status)) {
		async->armed = 0; async->count--; memset(task, 0, sizeof(*task));
	}
	return status;
}

EFI_STATUS cdk2_ata_async_submit(struct cdk2_ata_async_controller *async,
	UINT16 port, UINT16 multiplier, struct cdk2_ata_command_packet *packet,
	void *event)
{
	return submit(async, port, multiplier, packet, NULL, 0U, event);
}

EFI_STATUS cdk2_ata_async_submit_atapi(struct cdk2_ata_async_controller *async,
	UINT16 port, UINT16 multiplier, struct cdk2_ata_command_packet *packet,
	const UINT8 *cdb, UINT8 cdb_size, void *event)
{
	return submit(async, port, multiplier, packet, cdb, cdb_size, event);
}

static BOOLEAN finish(struct cdk2_ata_async_controller *async,
	struct cdk2_ata_async_task *task, EFI_STATUS status)
{
	if (!task->completed && EFI_ERROR(status) && task->packet != NULL) {
		task->packet->in_length = 0;
		task->packet->out_length = 0;
		if (task->packet->asb != NULL) {
			task->packet->asb->status = 0x41U;
			task->packet->asb->error = 0x04U;
		}
	}
	task->status = status; task->completed = 1;
	if (!task->signaled) {
		if (EFI_ERROR(async->services.signal(async->services.context, task->event)))
			return 0;
		task->signaled = 1;
	}
	memset(task, 0, sizeof(*task));
	async->head = (async->head + 1U) % CDK2_ATA_ASYNC_DEPTH;
	async->count--;
	return 1;
}

EFI_STATUS cdk2_ata_async_poll(struct cdk2_ata_async_controller *async)
{
	struct cdk2_ata_async_task *task;
	EFI_STATUS status;
	BOOLEAN complete = 0;
	BOOLEAN attempted_finish = 0;

	if (async == NULL)
		return EFI_INVALID_PARAMETER;
	if (async->polling)
		return EFI_ALREADY_STARTED;
	async->armed = 0;
	if (async->count == 0U)
		return EFI_NOT_READY;
	async->polling = 1; task = &async->queue[async->head];
	if (task->completed) {
		attempted_finish = 1;
		status = finish(async, task, task->status) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
	} else if (task->issued) {
		status = async->services.abort(async->services.context, async->controller,
			task);
		if (status == EFI_NOT_READY)
			status = EFI_SUCCESS;
		else {
			status = task->status;
			complete = 1;
		}
	} else if (!task->active) {
		status = async->services.begin(async->services.context, async->controller, task);
		if (!EFI_ERROR(status))
			task->active = 1;
	} else {
		status = async->services.poll(async->services.context, async->controller,
			task, &complete);
	}
	if (!attempted_finish && (EFI_ERROR(status) || complete) &&
	    !finish(async, task, status))
		status = EFI_NOT_READY;
	async->polling = 0;
	if (async->count != 0U && !async->stopping) {
		while (async->count != 0U) {
			EFI_STATUS arm_status;

			async->armed = 1;
			arm_status = async->services.arm(async->services.context,
				async->controller);
			if (!EFI_ERROR(arm_status))
				break;
			async->armed = 0;
			if (!EFI_ERROR(status))
				status = arm_status;
			if (async->queue[async->head].active) {
				struct cdk2_ata_async_task *head = &async->queue[async->head];
				EFI_STATUS abort_status;

				head->status = arm_status; head->issued = 1;
				abort_status = async->services.abort(async->services.context,
					async->controller, head);
				if (abort_status == EFI_NOT_READY)
					break;
				if (!finish(async, head, arm_status))
					break;
			} else if (!finish(async, &async->queue[async->head], arm_status)) {
				async->armed = 1;
				(void)async->services.arm(async->services.context,
					async->controller);
				break;
			}
		}
	}
	return status;
}

EFI_STATUS cdk2_ata_async_rearm(struct cdk2_ata_async_controller *async)
{
	EFI_STATUS result = EFI_SUCCESS;

	if (async == NULL || async->polling || async->stopping)
		return EFI_INVALID_PARAMETER;
	while (async->count != 0U) {
		EFI_STATUS status;
		struct cdk2_ata_async_task *task = &async->queue[async->head];

		if (task->issued) {
			status = async->services.abort(async->services.context,
				async->controller, task);
			if (status == EFI_NOT_READY)
				return status;
			if (!finish(async, task, task->status))
				return EFI_NOT_READY;
			continue;
		}

		async->armed = 1;
		status = async->services.arm(async->services.context, async->controller);
		if (!EFI_ERROR(status))
			return result;
		async->armed = 0;
		if (!EFI_ERROR(result))
			result = status;
		if (!finish(async, &async->queue[async->head], status))
			return result;
	}
	return result;
}

EFI_STATUS cdk2_ata_async_stop(struct cdk2_ata_async_controller *async)
{
	EFI_STATUS first = EFI_SUCCESS;

	if (async == NULL || async->polling)
		return EFI_INVALID_PARAMETER;
	async->stopping = 1; async->armed = 0;
	while (async->count != 0U) {
		struct cdk2_ata_async_task *task = &async->queue[async->head];
		EFI_STATUS status;

		if (task->completed) {
			if (!finish(async, task, task->status)) {
				async->stopping = 0;
				return EFI_DEVICE_ERROR;
			}
			continue;
		}
		status = task->active ? async->services.abort(
			async->services.context, async->controller, task) : EFI_SUCCESS;

		if (status == EFI_NOT_READY) {
			async->stopping = 0;
			return status;
		}
		if (EFI_ERROR(status) && !EFI_ERROR(first))
			first = status;
		if (!finish(async, task, CDK2_ASYNC_ABORTED)) {
			async->stopping = 0;
			return EFI_DEVICE_ERROR;
		}
	}
	return first;
}

EFI_STATUS cdk2_ata_async_cancel(struct cdk2_ata_async_controller *async,
	UINT16 port, UINT16 multiplier, BOOLEAN match_multiplier)
{
	if (async == NULL || async->polling)
		return EFI_INVALID_PARAMETER;
	for (UINTN offset = 0; offset < async->count; offset++) {
		struct cdk2_ata_async_task *task =
			&async->queue[(async->head + offset) % CDK2_ATA_ASYNC_DEPTH];

		if (task->port != port || (match_multiplier &&
		    task->multiplier != multiplier))
			continue;
		if (task->active) {
			EFI_STATUS status = async->services.abort(async->services.context,
				async->controller, task);

			if (status == EFI_NOT_READY)
				return status;
			if (EFI_ERROR(status))
				return status;
		}
		task->status = CDK2_ASYNC_ABORTED;
		task->completed = 1;
	}
	return EFI_SUCCESS;
}
