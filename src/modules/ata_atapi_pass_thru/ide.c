/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <string.h>

#define ATA_DATA 0U
#define ATA_FEATURE 1U
#define ATA_COUNT 2U
#define ATA_LBA_LOW 3U
#define ATA_LBA_MID 4U
#define ATA_LBA_HIGH 5U
#define ATA_DEVICE 6U
#define ATA_STATUS 7U
#define ATA_COMMAND 7U
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

static void capture_status(struct cdk2_ide_engine *engine, UINT8 channel,
	struct cdk2_ata_status_block *asb)
{
	UINT16 base;

	if (asb == NULL)
		return;
	base = engine->channels[channel].command;
	memset(asb, 0, sizeof(*asb));
	asb->status = engine->services.read8(engine->services.context,
		base + ATA_STATUS);
	asb->error = engine->services.read8(engine->services.context,
		base + ATA_FEATURE);
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

static int valid_services(const struct cdk2_ide_services *services)
{
	return services != NULL && services->read8 != NULL && services->read16 != NULL &&
		services->write8 != NULL && services->write16 != NULL &&
		services->write32 != NULL && services->map != NULL &&
		services->unmap != NULL && services->flush != NULL &&
		services->set_timing != NULL && services->time != NULL &&
		services->delay != NULL;
}

EFI_STATUS cdk2_ide_engine_init(struct cdk2_ide_engine *engine,
	const struct cdk2_ide_services *services, const struct cdk2_ide_channel *channels,
	UINT8 channel_count)
{
	if (engine == NULL || !valid_services(services) || channels == NULL ||
	    channel_count == 0U || channel_count > 2U)
		return EFI_INVALID_PARAMETER;
	memset(engine, 0, sizeof(*engine)); engine->services = *services;
	memcpy(engine->channels, channels, channel_count * sizeof(*channels));
	engine->channel_count = channel_count; engine->initialized = 1;
	return EFI_SUCCESS;
}

static EFI_STATUS wait_status(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT8 clear, UINT8 set, UINT64 timeout)
{
	UINT64 start = engine->services.time(engine->services.context);
	for (;;) {
		UINT8 status = engine->services.read8(engine->services.context,
			engine->channels[channel].command + ATA_STATUS);
		if ((status & (ATA_ST_ERR | ATA_ST_DF)) != 0U)
			return EFI_DEVICE_ERROR;
		if ((status & clear) == 0U && (status & set) == set)
			return EFI_SUCCESS;
		if (timeout != 0U && engine->services.time(engine->services.context) - start >= timeout)
			return EFI_TIMEOUT;
		engine->services.delay(engine->services.context, 10);
	}
}

EFI_STATUS cdk2_ide_reset(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT64 timeout)
{
	UINT16 control;
	if (engine == NULL || !engine->initialized || channel >= engine->channel_count)
		return EFI_INVALID_PARAMETER;
	control = engine->channels[channel].control;
	if (EFI_ERROR(engine->services.write8(engine->services.context, control,
		ATA_CTL_SRST)))
		return EFI_DEVICE_ERROR;
	engine->services.delay(engine->services.context, 5);
	if (EFI_ERROR(engine->services.write8(engine->services.context, control, 0)))
		return EFI_DEVICE_ERROR;
	engine->services.delay(engine->services.context, 2000);
	return wait_status(engine, channel, ATA_ST_BSY, 0, timeout);
}

static EFI_STATUS issue_task_file(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT8 device, const struct cdk2_ata_command_block *acb, UINT64 timeout)
{
	UINT16 base = engine->channels[channel].command; EFI_STATUS status;
	status = wait_status(engine, channel, ATA_ST_BSY | ATA_ST_DRQ, 0, timeout);
	if (EFI_ERROR(status))
		return status;
	if (EFI_ERROR(engine->services.set_timing(engine->services.context, channel, device)) ||
	    EFI_ERROR(engine->services.write8(engine->services.context, base + ATA_DEVICE,
		(UINT8)((device != 0U ? 0xb0U : 0xa0U) | (acb->device_head & 0x4fU)))) ||
	    EFI_ERROR(engine->services.write8(engine->services.context, base + ATA_FEATURE,
		acb->features)) || EFI_ERROR(engine->services.write8(engine->services.context,
		base + ATA_COUNT, acb->sector_count)) ||
	    EFI_ERROR(engine->services.write8(engine->services.context, base + ATA_LBA_LOW,
		acb->sector_number)) || EFI_ERROR(engine->services.write8(engine->services.context,
		base + ATA_LBA_MID, acb->cylinder_low)) ||
	    EFI_ERROR(engine->services.write8(engine->services.context, base + ATA_LBA_HIGH,
		acb->cylinder_high)) || EFI_ERROR(engine->services.write8(engine->services.context,
		base + ATA_COMMAND, acb->command)))
		return EFI_DEVICE_ERROR;
	return EFI_SUCCESS;
}

static EFI_STATUS pio_transfer(struct cdk2_ide_engine *engine, UINT8 channel,
	struct cdk2_ata_command_packet *packet, UINT64 timeout)
{
	UINT8 *buffer = packet->out_length != 0U ? packet->out_data : packet->in_data;
	UINT32 bytes = packet->out_length != 0U ? packet->out_length : packet->in_length;
	UINT16 data = engine->channels[channel].command + ATA_DATA; EFI_STATUS status;
	if ((bytes & 1U) != 0U)
		return EFI_BAD_BUFFER_SIZE;
	status = wait_status(engine, channel, ATA_ST_BSY, ATA_ST_DRQ, timeout);
	if (EFI_ERROR(status))
		return status;
	for (UINT32 offset = 0; offset < bytes; offset += 2U) {
		if (packet->out_length != 0U) {
			UINT16 value = buffer[offset] | ((UINT16)buffer[offset + 1U] << 8);
			if (EFI_ERROR(engine->services.write16(engine->services.context, data, value)))
				return EFI_DEVICE_ERROR;
		} else {
			UINT16 value = engine->services.read16(engine->services.context, data);
			buffer[offset] = (UINT8)value; buffer[offset + 1U] = (UINT8)(value >> 8);
		}
	}
	return wait_status(engine, channel, ATA_ST_BSY | ATA_ST_DRQ, 0, timeout);
}

static EFI_STATUS dma_transfer(struct cdk2_ide_engine *engine, UINT8 channel,
	struct cdk2_ata_command_packet *packet, UINT64 timeout)
{
	struct cdk2_ide_channel *ide = &engine->channels[channel];
	void *buffer = packet->out_length != 0U ? packet->out_data : packet->in_data;
	size_t remaining = packet->out_length != 0U ? packet->out_length : packet->in_length;
	void *mappings[CDK2_IDE_MAX_PRD], *prd_mapping = NULL;
	UINT16 mapping_count = 0; UINT64 device, prd_device; UINT16 entries = 0;
	EFI_STATUS status;
	enum cdk2_ahci_dma_operation operation = packet->out_length != 0U ?
		CDK2_AHCI_BUS_MASTER_READ : CDK2_AHCI_BUS_MASTER_WRITE;
	while (remaining != 0U) {
		size_t mapped = remaining;
		if (mapping_count == CDK2_IDE_MAX_PRD) {
			status = EFI_BAD_BUFFER_SIZE;
			goto cleanup;
		}
		status = engine->services.map(engine->services.context, operation, buffer,
			&mapped, &device, &mappings[mapping_count]);
		if (EFI_ERROR(status) || mapped == 0U || device > 0xffffffffU) {
			status = EFI_DEVICE_ERROR;
			goto cleanup;
		}
		mapping_count++;
		while (mapped != 0U) {
			size_t boundary = 0x10000U - ((UINT32)device & 0xffffU);
			size_t chunk = mapped < boundary ? mapped : boundary;
			if (entries == CDK2_IDE_MAX_PRD) {
				status = EFI_BAD_BUFFER_SIZE;
				goto cleanup;
			}
			engine->prd[entries++] = (struct cdk2_ide_prd) {
				.address = (UINT32)device, .count = chunk == 0x10000U ? 0U : (UINT16)chunk };
			device += chunk; mapped -= chunk; remaining -= chunk;
			buffer = (UINT8 *)buffer + chunk;
		}
	}
	engine->prd[entries - 1U].end = 0x8000U;
	{
		size_t prd_size = entries * sizeof(engine->prd[0]);
		status = engine->services.map(engine->services.context,
			CDK2_AHCI_BUS_MASTER_READ, engine->prd, &prd_size, &prd_device,
			&prd_mapping);
		if (EFI_ERROR(status) || prd_size != entries * sizeof(engine->prd[0]) ||
		    prd_device > 0xffffffffU) {
			status = EFI_DEVICE_ERROR;
			goto cleanup;
		}
	}
	if (EFI_ERROR(engine->services.flush(engine->services.context)) ||
	    EFI_ERROR(engine->services.write32(engine->services.context,
		ide->bus_master + BM_PRDT, (UINT32)prd_device)) ||
	    EFI_ERROR(engine->services.write8(engine->services.context,
		ide->bus_master + BM_STATUS, BM_ERROR | BM_INTERRUPT)) ||
	    EFI_ERROR(engine->services.write8(engine->services.context,
		ide->bus_master + BM_COMMAND,
		(UINT8)(BM_START | (packet->in_length != 0U ? BM_READ : 0U))))) {
		status = EFI_DEVICE_ERROR;
		goto cleanup;
	}
	{
		UINT64 start = engine->services.time(engine->services.context);
		for (;;) {
			UINT8 bm = engine->services.read8(engine->services.context,
				ide->bus_master + BM_STATUS);
			if ((bm & BM_ERROR) != 0U) {
				status = EFI_DEVICE_ERROR;
				break;
			}
			if ((bm & BM_INTERRUPT) != 0U) {
				status = EFI_SUCCESS;
				break;
			}
			if (timeout != 0U && engine->services.time(engine->services.context) -
			    start >= timeout) {
				status = EFI_TIMEOUT;
				break;
			}
			engine->services.delay(engine->services.context, 10);
		}
	}
cleanup:
	(void)engine->services.write8(engine->services.context,
		ide->bus_master + BM_COMMAND, 0);
	if (prd_mapping != NULL && EFI_ERROR(engine->services.unmap(
		engine->services.context, prd_mapping)) && !EFI_ERROR(status))
		status = EFI_DEVICE_ERROR;
	while (mapping_count != 0U) {
		mapping_count--;
		if (EFI_ERROR(engine->services.unmap(engine->services.context,
			mappings[mapping_count])) && !EFI_ERROR(status))
			status = EFI_DEVICE_ERROR;
	}
	if (EFI_ERROR(engine->services.flush(engine->services.context)) && !EFI_ERROR(status))
		status = EFI_DEVICE_ERROR;
	return status;
}

EFI_STATUS cdk2_ide_execute(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT8 device, struct cdk2_ata_command_packet *packet, UINT64 timeout)
{
	EFI_STATUS status;
	if (engine == NULL || !engine->initialized || packet == NULL || packet->acb == NULL ||
	    channel >= engine->channel_count || device > 1U)
		return EFI_INVALID_PARAMETER;
	status = issue_task_file(engine, channel, device, packet->acb, timeout);
	if (EFI_ERROR(status))
		return status;
	if (packet->protocol == 4U || packet->protocol == 5U)
		status = pio_transfer(engine, channel, packet, timeout);
	else if (packet->protocol == 6U || packet->protocol == 0x0aU ||
		 packet->protocol == 0x0bU)
		status = dma_transfer(engine, channel, packet, timeout);
	else
		status = wait_status(engine, channel, ATA_ST_BSY | ATA_ST_DRQ, 0, timeout);
	capture_status(engine, channel, packet->asb);
	if (EFI_ERROR(status))
		(void)cdk2_ide_reset(engine, channel, timeout);
	return status;
}

EFI_STATUS cdk2_ide_atapi_execute(struct cdk2_ide_engine *engine, UINT8 channel,
	UINT8 device, struct cdk2_ata_command_packet *packet, const UINT8 *cdb,
	size_t cdb_size, UINT64 timeout)
{
	struct cdk2_ata_command_block acb = { 0 };
	UINT8 *in_buffer, *out_buffer;
	UINT32 in_remaining, out_remaining;
	UINT16 base, data;
	EFI_STATUS status;
	UINT64 start;

	if (engine == NULL || !engine->initialized || packet == NULL || cdb == NULL ||
	    (cdb_size != 12U && cdb_size != 16U) ||
	    channel >= engine->channel_count || device > 1U)
		return EFI_INVALID_PARAMETER;
	acb.command = 0xa0U;
	acb.features = (packet->protocol == 6U || packet->protocol == 0x0aU ||
		packet->protocol == 0x0bU) ? 1U : 0U;
	acb.cylinder_low = 0xfeU;
	acb.cylinder_high = 0xffU;
	status = issue_task_file(engine, channel, device, &acb, timeout);
	if (EFI_ERROR(status))
		goto complete;
	status = wait_status(engine, channel, ATA_ST_BSY, ATA_ST_DRQ, timeout);
	if (EFI_ERROR(status))
		goto complete;
	base = engine->channels[channel].command;
	data = base + ATA_DATA;
	for (size_t index = 0; index < cdb_size; index += 2U)
		if (EFI_ERROR(engine->services.write16(engine->services.context, data,
			(UINT16)cdb[index] | ((UINT16)cdb[index + 1U] << 8)))) {
			status = EFI_DEVICE_ERROR;
			goto complete;
		}
	if (packet->protocol == 6U || packet->protocol == 0x0aU ||
	    packet->protocol == 0x0bU) {
		status = dma_transfer(engine, channel, packet, timeout);
		goto complete;
	}
	in_buffer = packet->in_data;
	out_buffer = packet->out_data;
	in_remaining = packet->in_length;
	out_remaining = packet->out_length;
	start = engine->services.time(engine->services.context);
	for (;;) {
		UINT8 ata_status = engine->services.read8(engine->services.context,
			base + ATA_STATUS);
		UINT8 reason;
		UINT32 phase_bytes, transfer_bytes;

		if ((ata_status & (ATA_ST_ERR | ATA_ST_DF)) != 0U) {
			status = EFI_DEVICE_ERROR;
			break;
		}
		if ((ata_status & ATA_ST_BSY) != 0U) {
			if (timeout != 0U && engine->services.time(
				engine->services.context) - start >= timeout) {
				status = EFI_TIMEOUT;
				break;
			}
			engine->services.delay(engine->services.context, 10);
			continue;
		}
		if ((ata_status & ATA_ST_DRQ) == 0U) {
			status = EFI_SUCCESS;
			break;
		}
		reason = engine->services.read8(engine->services.context,
			base + ATA_COUNT);
		if ((reason & 1U) != 0U) {
			status = EFI_DEVICE_ERROR;
			break;
		}
		phase_bytes = engine->services.read8(engine->services.context,
			base + ATA_LBA_MID) | ((UINT32)engine->services.read8(
			engine->services.context, base + ATA_LBA_HIGH) << 8);
		if (phase_bytes == 0U)
			phase_bytes = 0x10000U;
		if ((reason & 2U) != 0U) {
			transfer_bytes = phase_bytes < in_remaining ? phase_bytes : in_remaining;
			for (UINT32 offset = 0; offset < phase_bytes; offset += 2U) {
				UINT16 value = engine->services.read16(
					engine->services.context, data);
				if (offset < transfer_bytes)
					in_buffer[offset] = (UINT8)value;
				if (offset + 1U < transfer_bytes)
					in_buffer[offset + 1U] = (UINT8)(value >> 8);
			}
			in_buffer += transfer_bytes;
			in_remaining -= transfer_bytes;
		} else {
			transfer_bytes = phase_bytes < out_remaining ?
				phase_bytes : out_remaining;
			for (UINT32 offset = 0; offset < phase_bytes; offset += 2U) {
				UINT16 value = offset < transfer_bytes ? out_buffer[offset] : 0U;

				if (offset + 1U < transfer_bytes)
					value |= (UINT16)out_buffer[offset + 1U] << 8;
				if (EFI_ERROR(engine->services.write16(
					engine->services.context, data, value))) {
					status = EFI_DEVICE_ERROR;
					goto complete;
				}
			}
			out_buffer += transfer_bytes;
			out_remaining -= transfer_bytes;
		}
		if (phase_bytes > transfer_bytes) {
			status = EFI_BAD_BUFFER_SIZE;
			break;
		}
	}
	packet->in_length -= in_remaining;
	packet->out_length -= out_remaining;
complete:
	capture_status(engine, channel, packet->asb);
	if (EFI_ERROR(status))
		(void)cdk2_ide_reset(engine, channel, timeout);
	return status;
}
