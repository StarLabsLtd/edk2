/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <string.h>

#define ATA_FEATURE 1U
#define ATA_COUNT 2U
#define ATA_LBA_LOW 3U
#define ATA_LBA_MID 4U
#define ATA_LBA_HIGH 5U
#define ATA_DEVICE 6U
#define ATA_STATUS 7U
#define ATA_ST_ERR 0x01U
#define ATA_ST_DRQ 0x08U
#define ATA_ST_DF 0x20U
#define ATA_ST_BSY 0x80U
#define ATA_CTL_SRST 0x04U
#define BM_COMMAND 0U
#define BM_STATUS 2U
#define BM_PRDT 4U
#define BM_START 0x01U
#define BM_READ 0x08U
#define BM_ERROR 0x02U
#define BM_INTERRUPT 0x04U
#define EFI_ABORTED EFIERR(21)

static int timed_out(struct cdk2_ide_async_request *request)
{
	return request->deadline != 0U && request->engine->services.time(
		request->engine->services.context) >= request->deadline;
}

static void capture_status(struct cdk2_ide_async_request *request)
{
	struct cdk2_ata_status_block *asb = request->packet->asb;
	struct cdk2_ide_engine *engine = request->engine;
	UINT16 base = engine->channels[request->channel].command;

	if (asb == NULL)
		return;
	memset(asb, 0, sizeof(*asb));
	asb->status = engine->services.read8(engine->services.context, base + ATA_STATUS);
	asb->error = engine->services.read8(engine->services.context, base + ATA_FEATURE);
	asb->sector_count = engine->services.read8(engine->services.context,
		base + ATA_COUNT);
	asb->sector_number = engine->services.read8(engine->services.context,
		base + ATA_LBA_LOW);
	asb->cylinder_low = engine->services.read8(engine->services.context,
		base + ATA_LBA_MID);
	asb->cylinder_high = engine->services.read8(engine->services.context,
		base + ATA_LBA_HIGH);
	asb->device_head = engine->services.read8(engine->services.context,
		base + ATA_DEVICE);
}

static EFI_STATUS fail(struct cdk2_ide_async_request *request, EFI_STATUS status)
{
	request->terminal_status = status;
	request->reset_deadline = request->engine->services.time(
		request->engine->services.context) + request->reset_timeout;
	request->phase = CDK2_IDE_ASYNC_RESET_ASSERT;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ide_async_prepare(struct cdk2_ide_async_request *request,
	struct cdk2_ide_engine *engine, UINT8 channel, UINT8 device,
	struct cdk2_ata_command_packet *packet, UINT64 timeout)
{
	if (request == NULL || engine == NULL || !engine->initialized || packet == NULL ||
	    packet->acb == NULL || channel >= engine->channel_count || device > 1U ||
	    (packet->protocol != 2U && packet->protocol != 4U &&
	     packet->protocol != 5U && packet->protocol != 6U &&
	     packet->protocol != 0x0aU && packet->protocol != 0x0bU) ||
	    (packet->in_length != 0U && packet->out_length != 0U))
		return EFI_INVALID_PARAMETER;
	memset(request, 0, sizeof(*request));
	request->engine = engine; request->packet = packet;
	request->channel = channel; request->device = device;
	request->buffer = packet->out_length != 0U ? packet->out_data : packet->in_data;
	request->remaining = packet->out_length != 0U ? packet->out_length :
		packet->in_length;
	request->total = request->remaining; request->write = packet->out_length != 0U;
	request->dma = packet->protocol == 6U || packet->protocol == 0x0aU ||
		packet->protocol == 0x0bU;
	if (request->dma && request->remaining == 0U)
		return EFI_INVALID_PARAMETER;
	request->bm_command = BM_START | (packet->in_length != 0U ? BM_READ : 0U);
	request->deadline = timeout == 0U ? 0U : engine->services.time(
		engine->services.context) + timeout;
	request->reset_timeout = timeout == 0U ? 5000000U : timeout;
	request->terminal_status = EFI_SUCCESS;
	request->phase = request->dma ? CDK2_IDE_ASYNC_MAP : CDK2_IDE_ASYNC_READY;
	return EFI_SUCCESS;
}

static EFI_STATUS map_data(struct cdk2_ide_async_request *request)
{
	struct cdk2_ide_engine *engine = request->engine;
	size_t mapped = request->remaining;
	EFI_STATUS status;

	if (request->mapping_count == CDK2_IDE_MAX_PRD)
		return fail(request, EFI_BAD_BUFFER_SIZE);
	status = engine->services.map(engine->services.context,
		request->packet->out_length != 0U ? CDK2_AHCI_BUS_MASTER_READ :
		CDK2_AHCI_BUS_MASTER_WRITE, request->buffer, &mapped,
		&request->mapped_device, &request->mappings[request->mapping_count]);
	if (EFI_ERROR(status) || mapped == 0U || request->mapped_device > 0xffffffffU)
		return fail(request, EFI_DEVICE_ERROR);
	request->mapping_count++; request->mapped_remaining = mapped;
	request->buffer += mapped; request->remaining -= mapped;
	request->phase = CDK2_IDE_ASYNC_BUILD_PRD;
	return EFI_SUCCESS;
}

static EFI_STATUS build_prd(struct cdk2_ide_async_request *request)
{
	struct cdk2_ide_engine *engine = request->engine;
	size_t boundary, chunk;

	if (request->entries == CDK2_IDE_MAX_PRD)
		return fail(request, EFI_BAD_BUFFER_SIZE);
	boundary = 0x10000U - ((UINT32)request->mapped_device & 0xffffU);
	chunk = request->mapped_remaining < boundary ? request->mapped_remaining : boundary;
	engine->prd[request->entries++] = (struct cdk2_ide_prd) {
		(UINT32)request->mapped_device, chunk == 0x10000U ? 0U : (UINT16)chunk, 0U };
	request->mapped_device += chunk; request->mapped_remaining -= chunk;
	if (request->mapped_remaining == 0U)
		request->phase = request->remaining == 0U ? CDK2_IDE_ASYNC_MAP_PRD :
			CDK2_IDE_ASYNC_MAP;
	return EFI_SUCCESS;
}

static EFI_STATUS cleanup_step(struct cdk2_ide_async_request *request,
	BOOLEAN *complete)
{
	struct cdk2_ide_engine *engine = request->engine;
	struct cdk2_ide_channel *channel = &engine->channels[request->channel];
	EFI_STATUS status;

	switch (request->phase) {
	case CDK2_IDE_ASYNC_STOP:
		request->phase = CDK2_IDE_ASYNC_UNMAP_PRD;
		if (!request->started)
			return EFI_SUCCESS;
		request->started = 0;
		status = engine->services.write8(engine->services.context,
			channel->bus_master + BM_COMMAND, 0U);
		if (EFI_ERROR(status) && !EFI_ERROR(request->terminal_status))
			request->terminal_status = EFI_DEVICE_ERROR;
		return EFI_SUCCESS;
	case CDK2_IDE_ASYNC_UNMAP_PRD:
		request->phase = CDK2_IDE_ASYNC_UNMAP_DATA;
		if (request->prd_mapping == NULL)
			return EFI_SUCCESS;
		status = engine->services.unmap(engine->services.context,
			request->prd_mapping); request->prd_mapping = NULL;
		if (EFI_ERROR(status) && !EFI_ERROR(request->terminal_status))
			request->terminal_status = EFI_DEVICE_ERROR;
		return EFI_SUCCESS;
	case CDK2_IDE_ASYNC_UNMAP_DATA:
		if (request->mapping_count != 0U) {
			request->mapping_count--;
			status = engine->services.unmap(engine->services.context,
				request->mappings[request->mapping_count]);
			if (EFI_ERROR(status) && !EFI_ERROR(request->terminal_status))
				request->terminal_status = EFI_DEVICE_ERROR;
			return EFI_SUCCESS;
		}
		request->phase = CDK2_IDE_ASYNC_FINAL_FLUSH;
		return EFI_SUCCESS;
	case CDK2_IDE_ASYNC_FINAL_FLUSH:
		status = engine->services.flush(engine->services.context);
		if (EFI_ERROR(status) && !EFI_ERROR(request->terminal_status))
			request->terminal_status = EFI_DEVICE_ERROR;
		capture_status(request);
		if (!request->dma) {
			if (request->write)
				request->packet->out_length = (UINT32)request->transferred;
			else
				request->packet->in_length = (UINT32)request->transferred;
		}
		request->cleaned = 1;
		request->phase = CDK2_IDE_ASYNC_DONE; *complete = 1;
		return request->terminal_status;
	default:
		return EFI_INVALID_PARAMETER;
	}
}

static EFI_STATUS pio_words(struct cdk2_ide_async_request *request)
{
	struct cdk2_ide_engine *engine = request->engine;
	UINT16 data = engine->channels[request->channel].command;
	size_t budget = 128U;

	while (request->remaining != 0U && budget-- != 0U) {
		size_t bytes = request->remaining < 2U ? request->remaining : 2U;
		UINT16 value;

		if (request->write) {
			value = request->buffer[0];
			if (bytes == 2U)
				value |= (UINT16)request->buffer[1] << 8;
			if (EFI_ERROR(engine->services.write16(engine->services.context,
				data, value)))
				return fail(request, EFI_DEVICE_ERROR);
		} else {
			value = engine->services.read16(engine->services.context, data);
			request->buffer[0] = (UINT8)value;
			if (bytes == 2U)
				request->buffer[1] = (UINT8)(value >> 8);
		}
		request->buffer += bytes; request->remaining -= bytes;
		request->transferred += bytes;
	}
	if (request->remaining == 0U)
		request->phase = CDK2_IDE_ASYNC_COMMAND_WAIT;
	else
		request->phase = CDK2_IDE_ASYNC_PIO_WAIT;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ide_async_step(struct cdk2_ide_async_request *request,
	BOOLEAN *complete)
{
	struct cdk2_ide_engine *engine;
	struct cdk2_ide_channel *channel;
	struct cdk2_ata_command_block *acb;
	UINT16 base;
	UINT8 value;
	EFI_STATUS status = EFI_SUCCESS;

	if (request == NULL || complete == NULL || request->engine == NULL ||
	    request->cleaned)
		return EFI_INVALID_PARAMETER;
	*complete = 0; engine = request->engine;
	channel = &engine->channels[request->channel];
	base = channel->command; acb = request->packet->acb;
	if (request->phase >= CDK2_IDE_ASYNC_STOP)
		return cleanup_step(request, complete);
	if (request->phase < CDK2_IDE_ASYNC_RESET_ASSERT && timed_out(request))
		return fail(request, EFI_TIMEOUT);
	switch (request->phase) {
	case CDK2_IDE_ASYNC_MAP:
		return map_data(request);
	case CDK2_IDE_ASYNC_BUILD_PRD:
		return build_prd(request);
	case CDK2_IDE_ASYNC_MAP_PRD: {
		size_t size = request->entries * sizeof(engine->prd[0]);
		UINT64 device;

		engine->prd[request->entries - 1U].end = 0x8000U;
		status = engine->services.map(engine->services.context,
			CDK2_AHCI_BUS_MASTER_READ, engine->prd, &size, &device,
			&request->prd_mapping);
		if (EFI_ERROR(status) || size != request->entries * sizeof(engine->prd[0]) ||
		    device > 0xffffffffU)
			return fail(request, EFI_DEVICE_ERROR);
		request->mapped_device = device; request->phase = CDK2_IDE_ASYNC_FLUSH;
		break;
	}
	case CDK2_IDE_ASYNC_FLUSH:
		status = engine->services.flush(engine->services.context);
		request->phase = CDK2_IDE_ASYNC_WRITE_PRDT;
		break;
	case CDK2_IDE_ASYNC_WRITE_PRDT:
		status = engine->services.write32(engine->services.context,
			channel->bus_master + BM_PRDT, (UINT32)request->mapped_device);
		request->phase = CDK2_IDE_ASYNC_CLEAR_STATUS;
		break;
	case CDK2_IDE_ASYNC_CLEAR_STATUS:
		status = engine->services.write8(engine->services.context,
			channel->bus_master + BM_STATUS, BM_ERROR | BM_INTERRUPT);
		request->phase = CDK2_IDE_ASYNC_READY;
		break;
	case CDK2_IDE_ASYNC_READY:
		value = engine->services.read8(engine->services.context, base + ATA_STATUS);
		if ((value & (ATA_ST_ERR | ATA_ST_DF)) != 0U)
			return fail(request, EFI_DEVICE_ERROR);
		if ((value & (ATA_ST_BSY | ATA_ST_DRQ)) == 0U)
			request->phase = CDK2_IDE_ASYNC_TIMING;
		break;
	case CDK2_IDE_ASYNC_TIMING:
		status = engine->services.set_timing(engine->services.context,
			request->channel, request->device);
		request->phase = CDK2_IDE_ASYNC_TASKFILE;
		break;
	case CDK2_IDE_ASYNC_TASKFILE: {
		static const UINT8 offsets[] = { ATA_DEVICE, ATA_FEATURE, ATA_COUNT,
			ATA_LBA_LOW, ATA_LBA_MID, ATA_LBA_HIGH, ATA_STATUS };
		UINT8 values[] = { (UINT8)((request->device != 0U ? 0xb0U : 0xa0U) |
			(acb->device_head & 0x4fU)), acb->features, acb->sector_count,
			acb->sector_number, acb->cylinder_low, acb->cylinder_high, acb->command };

		status = engine->services.write8(engine->services.context,
			base + offsets[request->task_index], values[request->task_index]);
		if (++request->task_index == sizeof(offsets)) {
			if (request->dma)
				request->phase = CDK2_IDE_ASYNC_BM_START;
			else if (request->remaining != 0U)
				request->phase = CDK2_IDE_ASYNC_PIO_WAIT;
			else
				request->phase = CDK2_IDE_ASYNC_COMMAND_WAIT;
		}
		break;
	}
	case CDK2_IDE_ASYNC_BM_START:
		status = engine->services.write8(engine->services.context,
			channel->bus_master + BM_COMMAND, request->bm_command);
		request->started = 1; request->phase = CDK2_IDE_ASYNC_POLL;
		break;
	case CDK2_IDE_ASYNC_POLL:
		value = engine->services.read8(engine->services.context,
			channel->bus_master + BM_STATUS);
		if ((value & BM_ERROR) != 0U)
			return fail(request, EFI_DEVICE_ERROR);
		if ((value & BM_INTERRUPT) != 0U)
			request->phase = CDK2_IDE_ASYNC_STOP;
		break;
	case CDK2_IDE_ASYNC_PIO_WAIT:
		value = engine->services.read8(engine->services.context, base + ATA_STATUS);
		if ((value & (ATA_ST_ERR | ATA_ST_DF)) != 0U)
			return fail(request, EFI_DEVICE_ERROR);
		if ((value & ATA_ST_BSY) == 0U && (value & ATA_ST_DRQ) != 0U)
			request->phase = CDK2_IDE_ASYNC_PIO_TRANSFER;
		break;
	case CDK2_IDE_ASYNC_PIO_TRANSFER:
		return pio_words(request);
	case CDK2_IDE_ASYNC_COMMAND_WAIT:
		value = engine->services.read8(engine->services.context, base + ATA_STATUS);
		if ((value & (ATA_ST_ERR | ATA_ST_DF)) != 0U)
			return fail(request, EFI_DEVICE_ERROR);
		if ((value & (ATA_ST_BSY | ATA_ST_DRQ)) == 0U)
			request->phase = CDK2_IDE_ASYNC_STOP;
		break;
	case CDK2_IDE_ASYNC_RESET_ASSERT:
		status = engine->services.write8(engine->services.context, channel->control,
			ATA_CTL_SRST); request->phase = CDK2_IDE_ASYNC_RESET_DEASSERT;
		break;
	case CDK2_IDE_ASYNC_RESET_DEASSERT:
		status = engine->services.write8(engine->services.context, channel->control,
			0U); request->phase = CDK2_IDE_ASYNC_RESET_WAIT;
		break;
	case CDK2_IDE_ASYNC_RESET_WAIT:
		value = engine->services.read8(engine->services.context, base + ATA_STATUS);
		if ((value & ATA_ST_BSY) == 0U || engine->services.time(
			engine->services.context) >= request->reset_deadline)
			request->phase = CDK2_IDE_ASYNC_STOP;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}
	if (EFI_ERROR(status))
		return fail(request, EFI_DEVICE_ERROR);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ide_async_abort(struct cdk2_ide_async_request *request,
	BOOLEAN *complete)
{
	if (request == NULL || complete == NULL || request->cleaned)
		return EFI_INVALID_PARAMETER;
	if (request->phase < CDK2_IDE_ASYNC_RESET_ASSERT) {
		request->terminal_status = EFI_ABORTED;
		request->reset_deadline = request->engine->services.time(
			request->engine->services.context) + request->reset_timeout;
		request->phase = CDK2_IDE_ASYNC_RESET_ASSERT;
	}
	return request->phase >= CDK2_IDE_ASYNC_STOP ? cleanup_step(request, complete) :
		cdk2_ide_async_step(request, complete);
}
