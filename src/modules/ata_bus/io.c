/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_bus.h>

#include <string.h>

static EFI_STATUS validate(const struct cdk2_ata_bus_request *request)
{
	const struct cdk2_ata_bus_media *media;
	UINT64 blocks;

	if (request == NULL || request->child == NULL)
		return EFI_INVALID_PARAMETER;
	media = &request->child->geometry;
	if (request->operation > CDK2_ATA_BUS_FLUSH)
		return EFI_INVALID_PARAMETER;
	if (request->operation == CDK2_ATA_BUS_FLUSH)
		return request->bytes == 0U && request->buffer == NULL ? EFI_SUCCESS :
			EFI_INVALID_PARAMETER;
	if (request->media_id != 0U)
		return CDK2_EFI_MEDIA_CHANGED;
	if (request->buffer == NULL)
		return EFI_INVALID_PARAMETER;
	if (request->bytes == 0U)
		return EFI_SUCCESS;
	if (media->block_size == 0U || request->bytes % media->block_size != 0U)
		return EFI_BAD_BUFFER_SIZE;
	if (media->io_align > 1U &&
	    (UINTN)request->buffer % media->io_align != 0U)
		return EFI_INVALID_PARAMETER;
	if (request->operation == CDK2_ATA_BUS_WRITE && media->read_only)
		return CDK2_EFI_WRITE_PROTECTED;
	blocks = request->bytes / media->block_size;
	if (request->lba >= media->blocks || blocks > media->blocks - request->lba)
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}

static void encode_lba(struct cdk2_ata_command_block *acb, UINT64 lba,
	UINT32 blocks, BOOLEAN lba48, BOOLEAN udma, BOOLEAN write)
{
	memset(acb, 0, sizeof(*acb));
	acb->command = lba48 ? (write ? (udma ? 0x35U : 0x34U) :
		(udma ? 0x25U : 0x24U)) : (write ? (udma ? 0xcaU : 0x30U) :
		(udma ? 0xc8U : 0x20U));
	acb->sector_number = (UINT8)lba;
	acb->cylinder_low = (UINT8)(lba >> 8);
	acb->cylinder_high = (UINT8)(lba >> 16);
	acb->device_head = 0xe0U | (lba48 ? 0U : (UINT8)((lba >> 24) & 0xfU));
	acb->sector_count = (UINT8)blocks;
	if (lba48) {
		acb->sector_number_exp = (UINT8)(lba >> 24);
		acb->cylinder_low_exp = (UINT8)(lba >> 32);
		acb->cylinder_high_exp = (UINT8)(lba >> 40);
		acb->sector_count_exp = (UINT8)(blocks >> 8);
	}
}

static EFI_STATUS execute_request(struct cdk2_ata_bus_scheduler *scheduler,
	const struct cdk2_ata_bus_request *request)
{
	struct cdk2_ata_command_block acb;
	struct cdk2_ata_status_block asb;
	struct cdk2_ata_command_packet packet = { .asb = &asb, .acb = &acb,
		.timeout = 300000000U, .protocol = 0x0aU, .length = 0x20U };
	UINT64 lba = request->lba;
	UINT8 *buffer = request->buffer;
	UINTN remaining = request->bytes;
	EFI_STATUS status;

	status = validate(request);
	if (EFI_ERROR(status))
		return status;
	if (request->operation == CDK2_ATA_BUS_FLUSH) {
		return EFI_SUCCESS;
	}
	if (remaining == 0U)
		return EFI_SUCCESS;
	while (remaining != 0U) {
		UINT32 maximum = request->child->geometry.lba48 ? 0x10000U : 0x100U;
		UINT64 blocks = remaining / request->child->geometry.block_size;
		UINT32 chunk = blocks > maximum ? maximum : (UINT32)blocks;
		UINTN bytes = (UINTN)chunk * request->child->geometry.block_size;
		encode_lba(&acb, lba, chunk, request->child->geometry.lba48,
			request->child->geometry.udma,
			request->operation == CDK2_ATA_BUS_WRITE);
		packet.in_data = request->operation == CDK2_ATA_BUS_READ ? buffer : NULL;
		packet.out_data = request->operation == CDK2_ATA_BUS_WRITE ? buffer : NULL;
		packet.in_length = request->operation == CDK2_ATA_BUS_READ ? chunk : 0U;
		packet.out_length = request->operation == CDK2_ATA_BUS_WRITE ? chunk : 0U;
		packet.protocol = request->child->geometry.udma ?
			(request->operation == CDK2_ATA_BUS_READ ? 0x0aU : 0x0bU) :
			(request->operation == CDK2_ATA_BUS_READ ? 4U : 5U);
		status = scheduler->transport.execute(scheduler->transport.context,
			request->child, &packet);
		if (EFI_ERROR(status))
			return status;
		buffer += bytes; remaining -= bytes; lba += chunk;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_scheduler_init(struct cdk2_ata_bus_scheduler *scheduler,
	const struct cdk2_ata_bus_transport *transport)
{
	if (scheduler == NULL || transport == NULL || transport->execute == NULL ||
	    transport->reset == NULL || transport->signal == NULL)
		return EFI_INVALID_PARAMETER;
	memset(scheduler, 0, sizeof(*scheduler)); scheduler->transport = *transport;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_submit(struct cdk2_ata_bus_scheduler *scheduler,
	const struct cdk2_ata_bus_request *request)
{
	EFI_STATUS status;
	if (scheduler == NULL || request == NULL || request->token == NULL ||
	    request->token->event == NULL)
		return EFI_INVALID_PARAMETER;
	status = validate(request);
	if (EFI_ERROR(status))
		return status;
	if (scheduler->stopping)
		return EFI_NOT_READY;
	for (UINTN index = 0; index < scheduler->count; index++)
		if (scheduler->queue[(scheduler->head + index) % CDK2_ATA_BUS_QUEUE_DEPTH].token ==
		    request->token)
			return EFI_ALREADY_STARTED;
	if (scheduler->count == CDK2_ATA_BUS_QUEUE_DEPTH)
		return EFI_OUT_OF_RESOURCES;
	scheduler->queue[(scheduler->head + scheduler->count) % CDK2_ATA_BUS_QUEUE_DEPTH] =
		*request;
	request->token->transaction_status = EFI_NOT_READY;
	scheduler->count++;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_worker(struct cdk2_ata_bus_scheduler *scheduler)
{
	struct cdk2_ata_bus_request request;
	EFI_STATUS status;
	if (scheduler == NULL)
		return EFI_INVALID_PARAMETER;
	if (scheduler->worker_active)
		return EFI_ALREADY_STARTED;
	if (scheduler->count == 0U)
		return EFI_NOT_READY;
	scheduler->worker_active = 1; request = scheduler->queue[scheduler->head];
	status = execute_request(scheduler, &request);
	scheduler->head = (scheduler->head + 1U) % CDK2_ATA_BUS_QUEUE_DEPTH;
	scheduler->count--; request.token->transaction_status = status;
	scheduler->transport.signal(scheduler->transport.context, request.token->event);
	scheduler->worker_active = 0;
	return status;
}

EFI_STATUS cdk2_ata_bus_execute_sync(struct cdk2_ata_bus_scheduler *scheduler,
	const struct cdk2_ata_bus_request *request)
{
	EFI_STATUS status;
	if (scheduler == NULL || request == NULL || request->token != NULL)
		return EFI_INVALID_PARAMETER;
	while (scheduler->count != 0U) {
		status = cdk2_ata_bus_worker(scheduler);
		if (status == EFI_ALREADY_STARTED || status == EFI_INVALID_PARAMETER)
			return status;
	}
	return execute_request(scheduler, request);
}

EFI_STATUS cdk2_ata_bus_reset(struct cdk2_ata_bus_scheduler *scheduler,
	struct cdk2_ata_bus_child *child, BOOLEAN extended_verification)
{
	struct cdk2_ata_bus_request retained[CDK2_ATA_BUS_QUEUE_DEPTH];
	UINTN retained_count = 0;
	if (scheduler == NULL || child == NULL)
		return EFI_INVALID_PARAMETER;
	while (scheduler->count != 0U) {
		struct cdk2_ata_bus_request request = scheduler->queue[scheduler->head];
		scheduler->head = (scheduler->head + 1U) % CDK2_ATA_BUS_QUEUE_DEPTH;
		scheduler->count--;
		if (request.child != child) {
			retained[retained_count++] = request;
			continue;
		}
		request.token->transaction_status = CDK2_EFI_ABORTED;
		scheduler->transport.signal(scheduler->transport.context,
			request.token->event);
	}
	memcpy(scheduler->queue, retained, retained_count * sizeof(retained[0]));
	scheduler->head = 0; scheduler->count = retained_count;
	return scheduler->transport.reset(scheduler->transport.context, child,
		extended_verification);
}

EFI_STATUS cdk2_ata_bus_stop_scheduler(struct cdk2_ata_bus_scheduler *scheduler)
{
	if (scheduler == NULL)
		return EFI_INVALID_PARAMETER;
	scheduler->stopping = 1;
	return cdk2_ata_bus_drain_scheduler(scheduler);
}

EFI_STATUS cdk2_ata_bus_drain_scheduler(struct cdk2_ata_bus_scheduler *scheduler)
{
	EFI_STATUS first = EFI_SUCCESS;

	if (scheduler == NULL)
		return EFI_INVALID_PARAMETER;
	while (scheduler->count != 0U) {
		EFI_STATUS status = cdk2_ata_bus_worker(scheduler);

		if (EFI_ERROR(status) && !EFI_ERROR(first))
			first = status;
	}
	return first;
}

EFI_STATUS cdk2_ata_bus_cancel_token(struct cdk2_ata_bus_scheduler *scheduler,
	struct cdk2_block_io2_token *token)
{
	struct cdk2_ata_bus_request retained[CDK2_ATA_BUS_QUEUE_DEPTH];
	UINTN retained_count = 0;
	BOOLEAN found = 0;
	if (scheduler == NULL || token == NULL || scheduler->worker_active)
		return EFI_INVALID_PARAMETER;
	while (scheduler->count != 0U) {
		struct cdk2_ata_bus_request request = scheduler->queue[scheduler->head];
		scheduler->head = (scheduler->head + 1U) % CDK2_ATA_BUS_QUEUE_DEPTH;
		scheduler->count--;
		if (request.token == token && !found) {
			found = 1;
			continue;
		}
		retained[retained_count++] = request;
	}
	memcpy(scheduler->queue, retained, retained_count * sizeof(retained[0]));
	scheduler->head = 0; scheduler->count = retained_count;
	return found ? EFI_SUCCESS : EFI_NOT_FOUND;
}
