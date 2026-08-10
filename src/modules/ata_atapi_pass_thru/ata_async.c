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

EFI_STATUS cdk2_ata_async_submit(struct cdk2_ata_async_controller *async,
	UINT16 port, UINT16 multiplier, struct cdk2_ata_command_packet *packet,
	void *event)
{
	struct cdk2_ata_async_task *task;
	EFI_STATUS status;

	if (async == NULL || packet == NULL || event == NULL)
		return EFI_INVALID_PARAMETER;
	if (async->stopping)
		return EFI_NOT_READY;
	if (async->count == CDK2_ATA_ASYNC_DEPTH)
		return EFI_OUT_OF_RESOURCES;
	task = &async->queue[(async->head + async->count) % CDK2_ATA_ASYNC_DEPTH];
	*task = (struct cdk2_ata_async_task) {
		packet, event, port, multiplier, EFI_NOT_READY, 0, 0, 0, 0 };
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

static BOOLEAN finish(struct cdk2_ata_async_controller *async,
	struct cdk2_ata_async_task *task, EFI_STATUS status)
{
	BOOLEAN signaled = 1;

	task->status = status; task->completed = 1;
	if (!task->signaled) {
		if (EFI_ERROR(async->services.signal(async->services.context, task->event)))
			signaled = 0;
		else
			task->signaled = 1;
	}
	memset(task, 0, sizeof(*task));
	async->head = (async->head + 1U) % CDK2_ATA_ASYNC_DEPTH;
	async->count--;
	return signaled;
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
		EFI_STATUS arm_status;

		async->armed = 1;
		arm_status = async->services.arm(async->services.context, async->controller);
		if (EFI_ERROR(arm_status)) {
			async->armed = 0;
			finish(async, &async->queue[async->head], arm_status);
			if (!EFI_ERROR(status))
				status = arm_status;
		}
	}
	return status;
}

EFI_STATUS cdk2_ata_async_stop(struct cdk2_ata_async_controller *async)
{
	EFI_STATUS first = EFI_SUCCESS;

	if (async == NULL || async->polling)
		return EFI_INVALID_PARAMETER;
	async->stopping = 1; async->armed = 0;
	while (async->count != 0U) {
		struct cdk2_ata_async_task *task = &async->queue[async->head];
		EFI_STATUS status = task->active ? async->services.abort(
			async->services.context, async->controller, task) : EFI_SUCCESS;

		if (EFI_ERROR(status) && !EFI_ERROR(first))
			first = status;
		if (!finish(async, task, CDK2_ASYNC_ABORTED)) {
			if (!EFI_ERROR(first))
				first = EFI_DEVICE_ERROR;
		}
	}
	return first;
}
