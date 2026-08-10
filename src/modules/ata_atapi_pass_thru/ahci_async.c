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
	request->terminal_status = status;
	request->phase = CDK2_AHCI_ASYNC_CLEAN_UNMAP;
	return EFI_SUCCESS;
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
	EFI_STATUS status;


	if (request == NULL || engine == NULL || !engine->initialized || packet == NULL ||
	    port >= 32U || (engine->ports_implemented & (1U << port)) == 0U)
		return EFI_INVALID_PARAMETER;
	memset(request, 0, sizeof(*request)); request->engine = engine;
	request->packet = packet; request->port = port;
	status = cdk2_ahci_build_command(packet, 0, NULL, 0, &request->command);
	if (EFI_ERROR(status))
		return status;
	request->buffer = packet->out_length != 0U ? packet->out_data : packet->in_data;
	request->remaining = packet->out_length != 0U ? packet->out_length :
		packet->in_length;
	request->operation = packet->out_length != 0U ? CDK2_AHCI_BUS_MASTER_READ :
		CDK2_AHCI_BUS_MASTER_WRITE;
	request->timeout = timeout;
	request->phase = CDK2_AHCI_ASYNC_SLOT;
	return EFI_SUCCESS;
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

static EFI_STATUS restore_prior(struct cdk2_ahci_async_request *request)
{
	static const UINT16 offsets[] = { PX_CLB, PX_CLBU, PX_FB, PX_FBU, PX_CMD };
	struct cdk2_ahci_engine *engine = request->engine;
	UINT16 port = request->prior_port;
	UINT32 values[] = { engine->original_clb[port], engine->original_clbu[port],
		engine->original_fb[port], engine->original_fbu[port],
		engine->original_command[port] };
	EFI_STATUS status = engine->services.write(engine->services.context, port,
		offsets[request->restore_index], values[request->restore_index]);

	if (!EFI_ERROR(status) && ++request->restore_index == 5U) {
		engine->configured_ports &= ~(1U << port); engine->active_port = 0xffffU;
		request->phase = CDK2_AHCI_ASYNC_CONFIG_STOP;
	}
	return status;
}

static void reverse_prior_failure(struct cdk2_ahci_async_request *request)
{
	if (request->prior_port < 32U)
		(void)request->engine->services.write(request->engine->services.context,
			request->prior_port, PX_CMD, request->prior_runtime_command);
}

static void reverse_config_failure(struct cdk2_ahci_async_request *request)
{
	struct cdk2_ahci_engine *engine = request->engine;
	UINT16 port = request->port;

	(void)engine->services.write(engine->services.context, port, PX_CLB,
		engine->original_clb[port]);
	(void)engine->services.write(engine->services.context, port, PX_CLBU,
		engine->original_clbu[port]);
	(void)engine->services.write(engine->services.context, port, PX_FB,
		engine->original_fb[port]);
	(void)engine->services.write(engine->services.context, port, PX_FBU,
		engine->original_fbu[port]);
	(void)engine->services.write(engine->services.context, port, PX_CMD,
		engine->original_command[port]);
	engine->configured_ports &= ~(1U << port);
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
	if (request->phase < CDK2_AHCI_ASYNC_ABORT_STOP && expired(request)) {
		request->aborting = 1; request->terminal_status = EFI_TIMEOUT;
		request->phase = CDK2_AHCI_ASYNC_ABORT_STOP;
		return EFI_SUCCESS;
	}
	switch (request->phase) {
	case CDK2_AHCI_ASYNC_SLOT:
		if (request->slot_probe == engine->slots)
			return EFI_NOT_READY;
		request->slot = request->slot_probe++;
		if ((engine->active_slots & (1U << request->slot)) == 0U) {
			engine->active_slots |= 1U << request->slot;
			request->slot_owned = 1;
			request->phase = request->remaining != 0U ? CDK2_AHCI_ASYNC_MAP :
				CDK2_AHCI_ASYNC_TABLE_CLEAR;
		}
		break;
	case CDK2_AHCI_ASYNC_MAP: {
		size_t mapped = request->remaining > CDK2_AHCI_PRDT_MAX_BYTES ?
			CDK2_AHCI_PRDT_MAX_BYTES : request->remaining;
		UINT64 device;

		if (request->mapping_count == CDK2_AHCI_MAX_PRDT)
			status = EFI_BAD_BUFFER_SIZE;
		else
			status = engine->services.map(engine->services.context,
				(enum cdk2_ahci_dma_operation)request->operation,
				request->buffer, &mapped, &device,
				&request->mappings[request->mapping_count]);
		if (EFI_ERROR(status) || mapped == 0U) {
			status = EFI_DEVICE_ERROR;
			break;
		}
		request->mapping_count++;
		request->command.prdt[request->command.prdt_count++] =
			(struct cdk2_ahci_prdt) { device, (UINT32)mapped, 0 };
		request->buffer += mapped; request->remaining -= mapped;
		if (request->remaining == 0U) {
			request->command.prdt[request->command.prdt_count - 1U].interrupt = 1;
			request->phase = CDK2_AHCI_ASYNC_TABLE_CLEAR;
		}
		break;
	}
	case CDK2_AHCI_ASYNC_TABLE_CLEAR: {
		UINT8 *table = engine->command_tables[request->slot].host;
		size_t left = engine->command_tables[request->slot].size -
			request->table_offset;
		size_t bytes = left > 64U ? 64U : left;

		memset(table + request->table_offset, 0, bytes);
		request->table_offset += bytes;
		if (request->table_offset == engine->command_tables[request->slot].size) {
			memcpy(table, request->command.fis, 20U);
			request->phase = CDK2_AHCI_ASYNC_TABLE_BUILD;
		}
		break;
	}
	case CDK2_AHCI_ASYNC_TABLE_BUILD:
		if (request->serialize_index < request->command.prdt_count) {
			struct cdk2_ahci_prdt *prdt =
				&request->command.prdt[request->serialize_index];
			UINT8 *entry = (UINT8 *)engine->command_tables[request->slot].host +
				0x80U + request->serialize_index * 16U;

			put32(entry, (UINT32)prdt->address);
			put32(entry + 4U, (UINT32)(prdt->address >> 32));
			put32(entry + 12U, (prdt->bytes - 1U) |
				(prdt->interrupt ? 0x80000000U : 0U));
			request->serialize_index++;
		} else {
			request->phase = CDK2_AHCI_ASYNC_HEADER_BUILD;
		}
		break;
	case CDK2_AHCI_ASYNC_HEADER_BUILD: {
		UINT8 *header = (UINT8 *)engine->command_list.host + request->slot * 32U;
		UINT32 flags = 5U | (request->command.write ? 0x40U : 0U) |
			((UINT32)request->command.prdt_count << 16);

		memset(header, 0, 32U); put32(header, flags);
		put32(header + 8U, (UINT32)engine->command_tables[request->slot].device);
		put32(header + 12U,
			(UINT32)(engine->command_tables[request->slot].device >> 32));
		request->phase = CDK2_AHCI_ASYNC_PREP_FLUSH;
		break;
	}
	case CDK2_AHCI_ASYNC_PREP_FLUSH:
		status = engine->services.flush(engine->services.context);
		if (!EFI_ERROR(status))
			request->phase = CDK2_AHCI_ASYNC_SNAPSHOT;
		break;
	case CDK2_AHCI_ASYNC_SNAPSHOT: {
		static const UINT16 offsets[] = { PX_CMD, PX_CLB, PX_CLBU, PX_FB, PX_FBU };
		UINT32 observed = engine->services.read(engine->services.context,
			request->port, offsets[request->snapshot_index]);

		if (request->snapshot_index == 0U) {
			request->original_command = observed;
			if ((engine->configured_ports & (1U << request->port)) != 0U) {
				request->snapshot_index = 5U;
				request->prior_port = engine->active_port;
				request->phase = CDK2_AHCI_ASYNC_PRIOR_READ;
				break;
			}
			engine->original_command[request->port] = observed;
		} else if (request->snapshot_index == 1U)
			engine->original_clb[request->port] = observed;
		else if (request->snapshot_index == 2U)
			engine->original_clbu[request->port] = observed;
		else if (request->snapshot_index == 3U)
			engine->original_fb[request->port] = observed;
		else
			engine->original_fbu[request->port] = observed;
		if (++request->snapshot_index == 5U) {
			request->deadline = request->timeout == 0U ? 0U :
				engine->services.time(engine->services.context) + request->timeout;
			engine->configured_ports |= 1U << request->port;
			request->prior_port = engine->active_port;
			request->phase = CDK2_AHCI_ASYNC_PRIOR_READ;
		}
		break;
	}
	case CDK2_AHCI_ASYNC_PRIOR_READ:
		if (request->deadline == 0U && request->timeout != 0U)
			request->deadline = engine->services.time(engine->services.context) +
				request->timeout;
		if (request->prior_port < 32U && request->prior_port != request->port)
			request->prior_runtime_command = engine->services.read(
				engine->services.context, request->prior_port, PX_CMD);
		request->phase = request->prior_port < 32U &&
			request->prior_port != request->port ? CDK2_AHCI_ASYNC_RESTORE_STOP :
			(engine->active_port == request->port ? CDK2_AHCI_ASYNC_TFD :
			 CDK2_AHCI_ASYNC_CONFIG_STOP);
		break;
	case CDK2_AHCI_ASYNC_RESTORE_STOP:
		status = engine->services.write(engine->services.context, request->prior_port,
			PX_CMD, request->prior_runtime_command & ~CMD_ST);
		request->phase = CDK2_AHCI_ASYNC_RESTORE_WAIT_CR;
		break;
	case CDK2_AHCI_ASYNC_RESTORE_WAIT_CR:
		value = engine->services.read(engine->services.context, request->prior_port,
			PX_CMD);
		if ((value & CMD_CR) == 0U)
			request->phase = CDK2_AHCI_ASYNC_RESTORE_FRE_STOP;
		break;
	case CDK2_AHCI_ASYNC_RESTORE_FRE_STOP:
		status = engine->services.write(engine->services.context, request->prior_port,
			PX_CMD, request->prior_runtime_command & ~(CMD_ST | CMD_FRE));
		request->phase = CDK2_AHCI_ASYNC_RESTORE_WAIT_FR;
		break;
	case CDK2_AHCI_ASYNC_RESTORE_WAIT_FR:
		value = engine->services.read(engine->services.context, request->prior_port,
			PX_CMD);
		if ((value & CMD_FR) == 0U)
			request->phase = CDK2_AHCI_ASYNC_RESTORE_PROGRAM;
		break;
	case CDK2_AHCI_ASYNC_RESTORE_PROGRAM:
		status = restore_prior(request);
		break;
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
			status = finalize(request);
		}
		break;
	case CDK2_AHCI_ASYNC_CLEAN_UNMAP:
		if (request->mapping_count != 0U) {
			request->mapping_count--;
			if (EFI_ERROR(engine->services.unmap(engine->services.context,
			    request->mappings[request->mapping_count])) &&
			    !EFI_ERROR(request->terminal_status))
				request->terminal_status = EFI_DEVICE_ERROR;
		} else {
			request->phase = CDK2_AHCI_ASYNC_CLEAN_FLUSH;
		}
		break;
	case CDK2_AHCI_ASYNC_CLEAN_FLUSH:
		if (EFI_ERROR(engine->services.flush(engine->services.context)) &&
		    !EFI_ERROR(request->terminal_status))
			request->terminal_status = EFI_DEVICE_ERROR;
		request->phase = CDK2_AHCI_ASYNC_CLEAN_RELEASE;
		break;
	case CDK2_AHCI_ASYNC_CLEAN_RELEASE:
		if (request->slot_owned)
			engine->active_slots &= ~(1U << request->slot);
		request->cleaned = 1; request->phase = CDK2_AHCI_ASYNC_DONE;
		*complete = 1; status = request->terminal_status;
		break;
	case CDK2_AHCI_ASYNC_DONE:
		*complete = 1;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}
	if (EFI_ERROR(status) && !request->cleaned) {
		if (!request->issued) {
			if (request->phase <= CDK2_AHCI_ASYNC_RESTORE_PROGRAM)
				reverse_prior_failure(request);
			else if (request->engine->active_port != request->port)
				reverse_config_failure(request);
			status = cleanup(request, status);
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
	if (request->phase >= CDK2_AHCI_ASYNC_CLEAN_UNMAP)
		return cdk2_ahci_async_step(request, complete);
	if (!request->issued) {
		if (request->phase < CDK2_AHCI_ASYNC_CLEAN_UNMAP)
			status = cleanup(request, request->terminal_status != EFI_SUCCESS ?
				request->terminal_status : ASYNC_ABORTED);
		else
			status = cdk2_ahci_async_step(request, complete);
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
		status = cleanup(request, EFI_ERROR(status) ? EFI_DEVICE_ERROR :
			(request->terminal_status != EFI_SUCCESS ? request->terminal_status :
			 ASYNC_ABORTED));
	}
	return status;
}
