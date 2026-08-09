/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <string.h>

#define AHCI_GHC 0x04U
#define AHCI_GHC_HR 0x01U
#define AHCI_PX_CMD 0x18U
#define AHCI_PX_TFD 0x20U
#define AHCI_PX_SCTL 0x2cU
#define AHCI_PX_SERR 0x30U
#define AHCI_PX_CI 0x38U
#define AHCI_PX_IS 0x10U
#define AHCI_PX_CLB 0x00U
#define AHCI_PX_CLBU 0x04U
#define AHCI_PX_FB 0x08U
#define AHCI_PX_FBU 0x0cU
#define AHCI_CMD_ST 0x01U
#define AHCI_CMD_FRE 0x10U
#define AHCI_CMD_CR 0x8000U
#define AHCI_CMD_FR 0x4000U
#define AHCI_TFD_ERR 0x01U
#define AHCI_TFD_BUSY 0x80U
#define AHCI_TFD_DRQ 0x08U

static int services_valid(const struct cdk2_ahci_dma_services *services)
{
	return services != NULL && services->allocate != NULL && services->release != NULL &&
		services->map != NULL && services->unmap != NULL && services->flush != NULL &&
		services->read != NULL && services->write != NULL && services->time != NULL &&
		services->delay != NULL;
}
static EFI_STATUS restore_port(struct cdk2_ahci_engine *engine, UINT16 port,
	UINT64 timeout);

static EFI_STATUS allocate_dma(struct cdk2_ahci_engine *engine,
	struct cdk2_ahci_allocation *allocation, size_t size, size_t alignment)
{
	EFI_STATUS status = engine->services.allocate(engine->services.context, size,
		alignment, &allocation->host, &allocation->device);
	if (EFI_ERROR(status))
		return status;
	allocation->size = size;
	if (((uintptr_t)allocation->host & (alignment - 1U)) != 0U ||
	    (allocation->device & (alignment - 1U)) != 0U) {
		(void)engine->services.release(engine->services.context, allocation->host, size);
		memset(allocation, 0, sizeof(*allocation));
		return EFI_DEVICE_ERROR;
	}
	memset(allocation->host, 0, size);
	return EFI_SUCCESS;
}

void cdk2_ahci_engine_destroy(struct cdk2_ahci_engine *engine)
{
	if (engine == NULL || !services_valid(&engine->services))
		return;
	for (UINT16 port = 0; port < 32U; port++)
		if ((engine->configured_ports & (1U << port)) != 0U)
			(void)restore_port(engine, port, 5000000U);
	for (UINT8 slot = engine->slots; slot != 0U; slot--)
		if (engine->command_tables[slot - 1U].host != NULL)
			(void)engine->services.release(engine->services.context,
				engine->command_tables[slot - 1U].host,
				engine->command_tables[slot - 1U].size);
	if (engine->received_fis.host != NULL)
		(void)engine->services.release(engine->services.context,
			engine->received_fis.host, engine->received_fis.size);
	if (engine->command_list.host != NULL)
		(void)engine->services.release(engine->services.context,
			engine->command_list.host, engine->command_list.size);
	memset(engine, 0, sizeof(*engine));
}

EFI_STATUS cdk2_ahci_engine_init(struct cdk2_ahci_engine *engine,
	const struct cdk2_ahci_dma_services *services, UINT32 capability,
	UINT32 ports_implemented)
{
	EFI_STATUS status;
	if (engine == NULL || !services_valid(services) || ports_implemented == 0U)
		return EFI_INVALID_PARAMETER;
	memset(engine, 0, sizeof(*engine)); engine->services = *services;
	engine->capability = capability; engine->ports_implemented = ports_implemented;
	engine->active_port = 0xffffU;
	engine->slots = (UINT8)(((capability >> 8) & 0x1fU) + 1U);
	status = allocate_dma(engine, &engine->command_list, 1024, 1024);
	if (EFI_ERROR(status))
		goto error;
	status = allocate_dma(engine, &engine->received_fis, 256, 256);
	if (EFI_ERROR(status))
		goto error;
	for (UINT8 slot = 0; slot < engine->slots; slot++) {
		status = allocate_dma(engine, &engine->command_tables[slot], 4096, 128);
		if (EFI_ERROR(status))
			goto error;
	}
	engine->initialized = 1;
	return EFI_SUCCESS;
error:
	cdk2_ahci_engine_destroy(engine);
	return status;
}

static EFI_STATUS wait_clear(struct cdk2_ahci_engine *engine, UINT16 port,
	UINT16 offset, UINT32 mask, UINT64 timeout)
{
	UINT64 start = engine->services.time(engine->services.context);
	for (;;) {
		if ((engine->services.read(engine->services.context, port, offset) & mask) == 0U)
			return EFI_SUCCESS;
		if (timeout != 0U && engine->services.time(engine->services.context) - start >= timeout)
			return EFI_TIMEOUT;
		engine->services.delay(engine->services.context, 10);
	}
}

static void put32(UINT8 *buffer, UINT32 value)
{
	buffer[0] = (UINT8)value; buffer[1] = (UINT8)(value >> 8);
	buffer[2] = (UINT8)(value >> 16); buffer[3] = (UINT8)(value >> 24);
}

static EFI_STATUS abort_port(struct cdk2_ahci_engine *engine, UINT16 port,
	UINT64 timeout)
{
	UINT32 command = engine->services.read(engine->services.context, port, AHCI_PX_CMD);
	EFI_STATUS status = engine->services.write(engine->services.context, port,
		AHCI_PX_CMD, command & ~AHCI_CMD_ST);
	if (!EFI_ERROR(status))
		status = wait_clear(engine, port, AHCI_PX_CMD, AHCI_CMD_CR, timeout);
	if (EFI_ERROR(engine->services.write(engine->services.context, port, AHCI_PX_CMD,
		command | AHCI_CMD_ST)) && !EFI_ERROR(status))
		status = EFI_DEVICE_ERROR;
	return status;
}

static EFI_STATUS configure_port(struct cdk2_ahci_engine *engine, UINT16 port,
	UINT64 timeout)
{
	UINT32 command = engine->services.read(engine->services.context, port,
		AHCI_PX_CMD);
	EFI_STATUS status;

	if (engine->active_port == port)
		return EFI_SUCCESS;
	if (engine->active_port < 32U) {
		status = restore_port(engine, engine->active_port, timeout);
		if (EFI_ERROR(status))
			return status;
	}
	engine->original_command[port] = command;
	engine->original_clb[port] = engine->services.read(engine->services.context,
		port, AHCI_PX_CLB);
	engine->original_clbu[port] = engine->services.read(engine->services.context,
		port, AHCI_PX_CLBU);
	engine->original_fb[port] = engine->services.read(engine->services.context,
		port, AHCI_PX_FB);
	engine->original_fbu[port] = engine->services.read(engine->services.context,
		port, AHCI_PX_FBU);
	engine->configured_ports |= 1U << port;
	status = engine->services.write(engine->services.context, port, AHCI_PX_CMD,
		command & ~AHCI_CMD_ST);
	if (!EFI_ERROR(status))
		status = wait_clear(engine, port, AHCI_PX_CMD, AHCI_CMD_CR, timeout);
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_CMD, command & ~(AHCI_CMD_ST | AHCI_CMD_FRE));
	if (!EFI_ERROR(status))
		status = wait_clear(engine, port, AHCI_PX_CMD, AHCI_CMD_FR, timeout);
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_CLB, (UINT32)engine->command_list.device);
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_CLBU, (UINT32)(engine->command_list.device >> 32));
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_FB, (UINT32)engine->received_fis.device);
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_FBU, (UINT32)(engine->received_fis.device >> 32));
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_IS, 0xffffffffU);
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_SERR, 0xffffffffU);
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_CMD, (command & ~(AHCI_CMD_ST | AHCI_CMD_FRE)) |
			AHCI_CMD_FRE);
	if (!EFI_ERROR(status))
		status = engine->services.write(engine->services.context, port,
			AHCI_PX_CMD, command | AHCI_CMD_FRE | AHCI_CMD_ST);
	if (EFI_ERROR(status)) {
		EFI_STATUS rollback = restore_port(engine, port, timeout);

		return EFI_ERROR(rollback) ? EFI_DEVICE_ERROR : status;
	}
	engine->active_port = port;
	return status;
}

static EFI_STATUS restore_port(struct cdk2_ahci_engine *engine, UINT16 port,
	UINT64 timeout)
{
	EFI_STATUS first = EFI_SUCCESS, status;
	UINT32 command;

	if (port >= 32U || (engine->configured_ports & (1U << port)) == 0U)
		return EFI_SUCCESS;
	command = engine->services.read(engine->services.context, port, AHCI_PX_CMD);
	status = engine->services.write(engine->services.context, port, AHCI_PX_CMD,
		command & ~AHCI_CMD_ST);
	if (!EFI_ERROR(status))
		status = wait_clear(engine, port, AHCI_PX_CMD, AHCI_CMD_CR, timeout);
	if (EFI_ERROR(status))
		first = status;
	status = engine->services.write(engine->services.context, port, AHCI_PX_CMD,
		command & ~(AHCI_CMD_ST | AHCI_CMD_FRE));
	if (!EFI_ERROR(status))
		status = wait_clear(engine, port, AHCI_PX_CMD, AHCI_CMD_FR, timeout);
	if (EFI_ERROR(status) && !EFI_ERROR(first))
		first = status;
	if (EFI_ERROR(engine->services.write(engine->services.context, port,
		AHCI_PX_CLB, engine->original_clb[port])) && !EFI_ERROR(first))
		first = EFI_DEVICE_ERROR;
	if (EFI_ERROR(engine->services.write(engine->services.context, port,
		AHCI_PX_CLBU, engine->original_clbu[port])) && !EFI_ERROR(first))
		first = EFI_DEVICE_ERROR;
	if (EFI_ERROR(engine->services.write(engine->services.context, port,
		AHCI_PX_FB, engine->original_fb[port])) && !EFI_ERROR(first))
		first = EFI_DEVICE_ERROR;
	if (EFI_ERROR(engine->services.write(engine->services.context, port,
		AHCI_PX_FBU, engine->original_fbu[port])) && !EFI_ERROR(first))
		first = EFI_DEVICE_ERROR;
	if (EFI_ERROR(engine->services.write(engine->services.context, port,
		AHCI_PX_CMD, engine->original_command[port])) && !EFI_ERROR(first))
		first = EFI_DEVICE_ERROR;
	if (!EFI_ERROR(first)) {
		engine->configured_ports &= ~(1U << port);
		if (engine->active_port == port)
			engine->active_port = 0xffffU;
	}
	return first;
}

EFI_STATUS cdk2_ahci_reset_controller(struct cdk2_ahci_engine *engine,
	UINT64 timeout)
{
	if (engine == NULL || !engine->initialized)
		return EFI_NOT_READY;
	if (EFI_ERROR(engine->services.write(engine->services.context, 0xffffU,
		AHCI_GHC, engine->services.read(engine->services.context, 0xffffU,
		AHCI_GHC) | AHCI_GHC_HR)))
		return EFI_DEVICE_ERROR;
	return wait_clear(engine, 0xffffU, AHCI_GHC, AHCI_GHC_HR, timeout);
}

EFI_STATUS cdk2_ahci_reset_port(struct cdk2_ahci_engine *engine, UINT16 port,
	UINT64 timeout)
{
	UINT32 command;
	if (engine == NULL || !engine->initialized || port >= 32U ||
	    (engine->ports_implemented & (1U << port)) == 0U)
		return EFI_INVALID_PARAMETER;
	command = engine->services.read(engine->services.context, port, AHCI_PX_CMD);
	if (EFI_ERROR(engine->services.write(engine->services.context, port, AHCI_PX_CMD,
		command & ~(AHCI_CMD_ST | AHCI_CMD_FRE))) ||
	    EFI_ERROR(engine->services.write(engine->services.context, port, AHCI_PX_SCTL, 1U)))
		return EFI_DEVICE_ERROR;
	engine->services.delay(engine->services.context, 1000);
	if (EFI_ERROR(engine->services.write(engine->services.context, port, AHCI_PX_SCTL, 0U)) ||
	    EFI_ERROR(engine->services.write(engine->services.context, port, AHCI_PX_SERR,
		0xffffffffU)) || EFI_ERROR(engine->services.write(engine->services.context, port,
		AHCI_PX_CMD, command | AHCI_CMD_FRE | AHCI_CMD_ST)))
		return EFI_DEVICE_ERROR;
	return wait_clear(engine, port, AHCI_PX_TFD, AHCI_TFD_BUSY | AHCI_TFD_DRQ, timeout);
}

EFI_STATUS cdk2_ahci_build_command(const struct cdk2_ata_command_packet *packet,
	UINT16 multiplier, const UINT8 *atapi, size_t atapi_size,
	struct cdk2_ahci_command *command)
{
	const struct cdk2_ata_command_block *acb;
	if (packet == NULL || packet->acb == NULL || command == NULL ||
	    (atapi_size != 0U && (atapi == NULL || atapi_size > sizeof(command->atapi))))
		return EFI_INVALID_PARAMETER;
	memset(command, 0, sizeof(*command)); acb = packet->acb;
	command->fis[0] = 0x27; command->fis[1] = 0x80U | (UINT8)(multiplier & 0x0fU);
	command->fis[2] = acb->command; command->fis[3] = acb->features;
	command->fis[4] = acb->sector_number; command->fis[5] = acb->cylinder_low;
	command->fis[6] = acb->cylinder_high; command->fis[7] = acb->device_head;
	command->fis[8] = acb->sector_number_exp; command->fis[9] = acb->cylinder_low_exp;
	command->fis[10] = acb->cylinder_high_exp; command->fis[11] = acb->features_exp;
	command->fis[12] = acb->sector_count; command->fis[13] = acb->sector_count_exp;
	if (atapi_size != 0U) {
		memcpy(command->atapi, atapi, atapi_size); command->atapi_command = 1;
	}
	command->write = packet->out_length != 0U;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ahci_execute(struct cdk2_ahci_engine *engine, UINT16 port,
	struct cdk2_ata_command_packet *packet, const UINT8 *atapi, size_t atapi_size,
	UINT64 timeout)
{
	struct cdk2_ahci_command command; void *mappings[CDK2_AHCI_MAX_PRDT];
	UINT16 mapping_count = 0; UINT64 device;
	void *buffer; size_t remaining, mapped; UINT8 slot, command_issued = 0;
	EFI_STATUS status;
	enum cdk2_ahci_dma_operation operation;
	if (engine == NULL || !engine->initialized || packet == NULL || port >= 32U ||
	    (engine->ports_implemented & (1U << port)) == 0U)
		return EFI_INVALID_PARAMETER;
	status = cdk2_ahci_build_command(packet, 0, atapi, atapi_size, &command);
	if (EFI_ERROR(status))
		return status;
	for (slot = 0; slot < engine->slots; slot++)
		if ((engine->active_slots & (1U << slot)) == 0U)
			break;
	if (slot == engine->slots)
		return EFI_NOT_READY;
	engine->active_slots |= 1U << slot;
	buffer = packet->out_length != 0U ? packet->out_data : packet->in_data;
	remaining = packet->out_length != 0U ? packet->out_length : packet->in_length;
	operation = packet->out_length != 0U ? CDK2_AHCI_BUS_MASTER_READ :
		CDK2_AHCI_BUS_MASTER_WRITE;
	while (remaining != 0U) {
		mapped = remaining;
		if (mapping_count == CDK2_AHCI_MAX_PRDT) {
			status = EFI_BAD_BUFFER_SIZE;
			goto cleanup;
		}
		status = engine->services.map(engine->services.context, operation, buffer,
			&mapped, &device, &mappings[mapping_count]);
		if (EFI_ERROR(status) || mapped == 0U) {
			status = EFI_DEVICE_ERROR;
			goto cleanup;
		}
		mapping_count++;
		while (mapped != 0U) {
			size_t chunk = mapped > CDK2_AHCI_PRDT_MAX_BYTES ?
				CDK2_AHCI_PRDT_MAX_BYTES : mapped;
			if (command.prdt_count == CDK2_AHCI_MAX_PRDT) {
				status = EFI_BAD_BUFFER_SIZE;
				goto cleanup;
			}
			command.prdt[command.prdt_count++] = (struct cdk2_ahci_prdt) {
				.address = device, .bytes = (UINT32)chunk };
			device += chunk; mapped -= chunk; remaining -= chunk;
			buffer = (UINT8 *)buffer + chunk;
		}
	}
	if (command.prdt_count != 0U)
		command.prdt[command.prdt_count - 1U].interrupt = 1;
	{
		UINT8 *table = engine->command_tables[slot].host;
		UINT8 *header = (UINT8 *)engine->command_list.host + slot * 32U;
		UINT32 flags = 5U | (command.atapi_command ? 0x20U : 0U) |
			(command.write ? 0x40U : 0U) | ((UINT32)command.prdt_count << 16);
		memset(table, 0, engine->command_tables[slot].size);
		memset(header, 0, 32); memcpy(table, command.fis, sizeof(command.fis));
		memcpy(table + 0x40U, command.atapi, sizeof(command.atapi));
		put32(header, flags);
		put32(header + 8U, (UINT32)engine->command_tables[slot].device);
		put32(header + 12U, (UINT32)(engine->command_tables[slot].device >> 32));
		for (UINT16 index = 0; index < command.prdt_count; index++) {
			UINT8 *entry = table + 0x80U + index * 16U;
			put32(entry, (UINT32)command.prdt[index].address);
			put32(entry + 4U, (UINT32)(command.prdt[index].address >> 32));
			put32(entry + 12U, (command.prdt[index].bytes - 1U) |
				(command.prdt[index].interrupt ? 0x80000000U : 0U));
		}
	}
	status = engine->services.flush(engine->services.context);
	if (EFI_ERROR(status))
		goto cleanup;
	status = configure_port(engine, port, timeout);
	if (EFI_ERROR(status))
		goto cleanup;
	status = wait_clear(engine, port, AHCI_PX_TFD, AHCI_TFD_BUSY | AHCI_TFD_DRQ,
		timeout);
	if (EFI_ERROR(status))
		goto cleanup;
	if (EFI_ERROR(engine->services.write(engine->services.context, port, AHCI_PX_IS,
		0xffffffffU)) || EFI_ERROR(engine->services.write(engine->services.context,
		port, AHCI_PX_CI, 1U << slot))) {
		status = EFI_DEVICE_ERROR;
		goto cleanup;
	}
	command_issued = 1;
	status = wait_clear(engine, port, AHCI_PX_CI, 1U << slot, timeout);
	if (!EFI_ERROR(status) && (engine->services.read(engine->services.context, port,
		AHCI_PX_TFD) & AHCI_TFD_ERR) != 0U)
		status = EFI_DEVICE_ERROR;
	if (packet->asb != NULL) {
		const UINT8 *fis = (const UINT8 *)engine->received_fis.host + 0x40U;

		memset(packet->asb, 0, sizeof(*packet->asb));
		packet->asb->status = fis[2];
		packet->asb->error = fis[3];
		packet->asb->sector_number = fis[4];
		packet->asb->cylinder_low = fis[5];
		packet->asb->cylinder_high = fis[6];
		packet->asb->device_head = fis[7];
		packet->asb->sector_number_exp = fis[8];
		packet->asb->cylinder_low_exp = fis[9];
		packet->asb->cylinder_high_exp = fis[10];
		packet->asb->sector_count = fis[12];
		packet->asb->sector_count_exp = fis[13];
	}
cleanup:
	while (mapping_count != 0U) {
		mapping_count--;
		if (EFI_ERROR(engine->services.unmap(engine->services.context,
			mappings[mapping_count])) && !EFI_ERROR(status))
			status = EFI_DEVICE_ERROR;
	}
	if (EFI_ERROR(status) && command_issued &&
	    EFI_ERROR(abort_port(engine, port, timeout)) &&
	    status != EFI_TIMEOUT)
		status = EFI_DEVICE_ERROR;
	if (EFI_ERROR(engine->services.flush(engine->services.context)) && !EFI_ERROR(status))
		status = EFI_DEVICE_ERROR;
	engine->active_slots &= ~(1U << slot);
	return status;
}
