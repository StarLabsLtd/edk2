/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <string.h>

#define PX_CLB 0x00U
#define PX_CLBU 0x04U
#define PX_FB 0x08U
#define PX_FBU 0x0cU
#define PX_IS 0x10U
#define PX_CMD 0x18U
#define PX_TFD 0x20U
#define PX_SERR 0x30U
#define PX_CI 0x38U
#define CMD_ST 0x01U
#define CMD_FRE 0x10U
#define CMD_FR 0x4000U
#define CMD_CR 0x8000U
#define TFD_DRQ 0x08U
#define TFD_BUSY 0x80U
#define ASYNC_ABORTED EFIERR(21)

static void put32(UINT8 *buffer, UINT32 value)
{
	buffer[0] = (UINT8)value; buffer[1] = (UINT8)(value >> 8);
	buffer[2] = (UINT8)(value >> 16); buffer[3] = (UINT8)(value >> 24);
}

static EFI_STATUS cleanup(struct cdk2_ahci_async_request *request,
	EFI_STATUS status)
{
	while (request->mapping_count != 0U) {
		request->mapping_count--;
		if (EFI_ERROR(request->engine->services.unmap(
		    request->engine->services.context,
		    request->mappings[request->mapping_count])) && !EFI_ERROR(status))
			status = EFI_DEVICE_ERROR;
	}
	if (EFI_ERROR(request->engine->services.flush(
	    request->engine->services.context)) && !EFI_ERROR(status))
		status = EFI_DEVICE_ERROR;
	request->engine->active_slots &= ~(1U << request->slot);
	request->cleaned = 1; request->phase = CDK2_AHCI_ASYNC_DONE;
	return status;
}

static EFI_STATUS expired(struct cdk2_ahci_async_request *request)
{
	return request->deadline != 0U && request->engine->services.time(
		request->engine->services.context) >= request->deadline;
}

EFI_STATUS cdk2_ahci_async_prepare(struct cdk2_ahci_async_request *request,
	struct cdk2_ahci_engine *engine, UINT16 port,
	struct cdk2_ata_command_packet *packet, UINT64 timeout)
{
	void *buffer;
	size_t remaining;
	enum cdk2_ahci_dma_operation operation;
	EFI_STATUS status;

	if (request == NULL || engine == NULL || !engine->initialized || packet == NULL ||
	    port >= 32U || (engine->ports_implemented & (1U << port)) == 0U)
		return EFI_INVALID_PARAMETER;
	memset(request, 0, sizeof(*request)); request->engine = engine;
	request->packet = packet; request->port = port;
	status = cdk2_ahci_build_command(packet, 0, NULL, 0, &request->command);
	if (EFI_ERROR(status))
		return status;
	for (request->slot = 0; request->slot < engine->slots; request->slot++)
		if ((engine->active_slots & (1U << request->slot)) == 0U)
			break;
	if (request->slot == engine->slots)
		return EFI_NOT_READY;
	engine->active_slots |= 1U << request->slot;
	buffer = packet->out_length != 0U ? packet->out_data : packet->in_data;
	remaining = packet->out_length != 0U ? packet->out_length : packet->in_length;
	operation = packet->out_length != 0U ? CDK2_AHCI_BUS_MASTER_READ :
		CDK2_AHCI_BUS_MASTER_WRITE;
	while (remaining != 0U) {
		size_t mapped = remaining;
		UINT64 device;

		if (request->mapping_count == CDK2_AHCI_MAX_PRDT) {
			status = EFI_BAD_BUFFER_SIZE;
			goto fail;
		}
		status = engine->services.map(engine->services.context, operation, buffer,
			&mapped, &device, &request->mappings[request->mapping_count]);
		if (EFI_ERROR(status) || mapped == 0U) {
			status = EFI_DEVICE_ERROR;
			goto fail;
		}
		request->mapping_count++;
		while (mapped != 0U) {
			size_t chunk = mapped > CDK2_AHCI_PRDT_MAX_BYTES ?
				CDK2_AHCI_PRDT_MAX_BYTES : mapped;

			if (request->command.prdt_count == CDK2_AHCI_MAX_PRDT) {
				status = EFI_BAD_BUFFER_SIZE;
				goto fail;
			}
			request->command.prdt[request->command.prdt_count++] =
				(struct cdk2_ahci_prdt) { device, (UINT32)chunk, 0 };
			device += chunk; mapped -= chunk; remaining -= chunk;
			buffer = (UINT8 *)buffer + chunk;
		}
	}
	if (request->command.prdt_count != 0U)
		request->command.prdt[request->command.prdt_count - 1U].interrupt = 1;
	{
		UINT8 *table = engine->command_tables[request->slot].host;
		UINT8 *header = (UINT8 *)engine->command_list.host + request->slot * 32U;
		UINT32 flags = 5U | (request->command.write ? 0x40U : 0U) |
			((UINT32)request->command.prdt_count << 16);

		memset(table, 0, engine->command_tables[request->slot].size);
		memset(header, 0, 32); memcpy(table, request->command.fis, 20);
		put32(header, flags);
		put32(header + 8U, (UINT32)engine->command_tables[request->slot].device);
		put32(header + 12U,
			(UINT32)(engine->command_tables[request->slot].device >> 32));
		for (UINT16 index = 0; index < request->command.prdt_count; index++) {
			UINT8 *entry = table + 0x80U + index * 16U;

			put32(entry, (UINT32)request->command.prdt[index].address);
			put32(entry + 4U, (UINT32)(request->command.prdt[index].address >> 32));
			put32(entry + 12U, (request->command.prdt[index].bytes - 1U) |
				(request->command.prdt[index].interrupt ? 0x80000000U : 0U));
		}
	}
	status = engine->services.flush(engine->services.context);
	if (EFI_ERROR(status))
		goto fail;
	request->original_command = engine->services.read(engine->services.context,
		port, PX_CMD);
	request->deadline = timeout == 0U ? 0U : engine->services.time(
		engine->services.context) + timeout;
	request->phase = engine->active_port == port ? CDK2_AHCI_ASYNC_TFD :
		CDK2_AHCI_ASYNC_CONFIG_STOP;
	return EFI_SUCCESS;
fail:
	return cleanup(request, status);
}

static EFI_STATUS program_port(struct cdk2_ahci_async_request *request)
{
	static const UINT16 offsets[] = { PX_CLB, PX_CLBU, PX_FB, PX_FBU, PX_IS,
		PX_SERR, PX_CMD, PX_CMD };
	UINT64 clb = request->engine->command_list.device;
	UINT64 fb = request->engine->received_fis.device;
	UINT32 values[] = { (UINT32)clb, (UINT32)(clb >> 32), (UINT32)fb,
		(UINT32)(fb >> 32), 0xffffffffU, 0xffffffffU,
		(request->original_command & ~(CMD_ST | CMD_FRE)) | CMD_FRE,
		request->original_command | CMD_FRE | CMD_ST };
	EFI_STATUS status = request->engine->services.write(
		request->engine->services.context, request->port,
		offsets[request->program_index], values[request->program_index]);

	if (!EFI_ERROR(status) && ++request->program_index == 8U) {
		request->engine->active_port = request->port;
		request->phase = CDK2_AHCI_ASYNC_TFD;
	}
	return status;
}

static EFI_STATUS finalize(struct cdk2_ahci_async_request *request)
{
	UINT32 tfd = request->engine->services.read(request->engine->services.context,
		request->port, PX_TFD);
	const UINT8 *header = (const UINT8 *)request->engine->command_list.host +
		request->slot * 32U;
	UINT32 transferred = header[4] | ((UINT32)header[5] << 8) |
		((UINT32)header[6] << 16) | ((UINT32)header[7] << 24);
	EFI_STATUS status = (tfd & 1U) != 0U ? EFI_DEVICE_ERROR : EFI_SUCCESS;
	if (request->packet->in_length != 0U && transferred <= request->packet->in_length)
		request->packet->in_length = transferred;
	if (request->packet->out_length != 0U && transferred <= request->packet->out_length)
		request->packet->out_length = transferred;

	if (request->packet->asb != NULL) {
		const UINT8 *fis = (const UINT8 *)request->engine->received_fis.host + 0x40U;

		memset(request->packet->asb, 0, sizeof(*request->packet->asb));
		request->packet->asb->status = fis[2]; request->packet->asb->error = fis[3];
	}
	return cleanup(request, status);
}

EFI_STATUS cdk2_ahci_async_step(struct cdk2_ahci_async_request *request,
	BOOLEAN *complete)
{
	struct cdk2_ahci_engine *engine;
	UINT32 value;
	EFI_STATUS status = EFI_SUCCESS;

	if (request == NULL || complete == NULL || request->engine == NULL)
		return EFI_INVALID_PARAMETER;
	*complete = 0; engine = request->engine;
	if (expired(request)) {
		request->aborting = 1; request->terminal_status = EFI_TIMEOUT;
		request->phase = CDK2_AHCI_ASYNC_ABORT_STOP;
		return EFI_SUCCESS;
	}
	switch (request->phase) {
	case CDK2_AHCI_ASYNC_CONFIG_STOP:
		status = engine->services.write(engine->services.context, request->port,
			PX_CMD, request->original_command & ~CMD_ST);
		request->phase = CDK2_AHCI_ASYNC_WAIT_CR;
		break;
	case CDK2_AHCI_ASYNC_WAIT_CR:
		value = engine->services.read(engine->services.context, request->port, PX_CMD);
		if ((value & CMD_CR) == 0U)
			request->phase = CDK2_AHCI_ASYNC_CONFIG_FRE_STOP;
		break;
	case CDK2_AHCI_ASYNC_CONFIG_FRE_STOP:
		status = engine->services.write(engine->services.context, request->port,
			PX_CMD, request->original_command & ~(CMD_ST | CMD_FRE));
		request->phase = CDK2_AHCI_ASYNC_WAIT_FR;
		break;
	case CDK2_AHCI_ASYNC_WAIT_FR:
		value = engine->services.read(engine->services.context, request->port, PX_CMD);
		if ((value & CMD_FR) == 0U)
			request->phase = CDK2_AHCI_ASYNC_PROGRAM;
		break;
	case CDK2_AHCI_ASYNC_PROGRAM:
		status = program_port(request);
		break;
	case CDK2_AHCI_ASYNC_TFD:
		value = engine->services.read(engine->services.context, request->port, PX_TFD);
		if ((value & (TFD_BUSY | TFD_DRQ)) == 0U)
			request->phase = CDK2_AHCI_ASYNC_ISSUE;
		break;
	case CDK2_AHCI_ASYNC_ISSUE:
		status = engine->services.write(engine->services.context, request->port,
			PX_IS, 0xffffffffU);
		if (!EFI_ERROR(status))
			status = engine->services.write(engine->services.context, request->port,
				PX_CI, 1U << request->slot);
		if (!EFI_ERROR(status)) {
			request->issued = 1; request->phase = CDK2_AHCI_ASYNC_CI;
		}
		break;
	case CDK2_AHCI_ASYNC_CI:
		value = engine->services.read(engine->services.context, request->port, PX_CI);
		if ((value & (1U << request->slot)) == 0U) {
			status = finalize(request); *complete = 1;
		}
		break;
	case CDK2_AHCI_ASYNC_DONE:
		*complete = 1;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}
	if (EFI_ERROR(status)) {
		if (!request->issued) {
			status = cleanup(request, status); *complete = 1;
		} else {
			request->aborting = 1; request->terminal_status = status;
			request->phase = CDK2_AHCI_ASYNC_ABORT_STOP; status = EFI_SUCCESS;
		}
	}
	return status;
}

EFI_STATUS cdk2_ahci_async_abort(struct cdk2_ahci_async_request *request,
	BOOLEAN *complete)
{
	struct cdk2_ahci_engine *engine;
	EFI_STATUS status = EFI_SUCCESS;

	if (request == NULL || complete == NULL || request->engine == NULL)
		return EFI_INVALID_PARAMETER;
	*complete = 0; engine = request->engine;
	if (!request->issued) {
		status = cleanup(request, ASYNC_ABORTED); *complete = 1;
		return status;
	}
	if (request->phase == CDK2_AHCI_ASYNC_ABORT_STOP) {
		status = engine->services.write(engine->services.context, request->port,
			PX_CMD, request->original_command & ~CMD_ST);
		request->phase = CDK2_AHCI_ASYNC_ABORT_WAIT;
	} else if (request->phase == CDK2_AHCI_ASYNC_ABORT_WAIT) {
		if ((engine->services.read(engine->services.context, request->port,
		    PX_CMD) & CMD_CR) == 0U)
			request->phase = CDK2_AHCI_ASYNC_ABORT_RESTART;
	} else if (request->phase == CDK2_AHCI_ASYNC_ABORT_RESTART) {
		status = engine->services.write(engine->services.context, request->port,
			PX_CMD, request->original_command | CMD_FRE | CMD_ST);
		status = cleanup(request, EFI_ERROR(status) ? EFI_DEVICE_ERROR : ASYNC_ABORTED);
		*complete = 1;
	}
	return status;
}
