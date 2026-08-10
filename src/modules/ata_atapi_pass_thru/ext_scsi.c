/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stddef.h>
#include <string.h>

static struct cdk2_ext_scsi_instance *from_protocol(
	struct cdk2_ext_scsi_protocol *protocol)
{
	return protocol == NULL ? NULL :
		(struct cdk2_ext_scsi_instance *)((UINT8 *)protocol -
		offsetof(struct cdk2_ext_scsi_instance, protocol));
}

static UINT16 target_multiplier(UINT8 value)
{
	return value == 0xffU ? CDK2_ATA_NO_PORT_MULTIPLIER : value;
}

static int atapi_exists(const struct cdk2_ata_topology *topology, UINT16 port,
	UINT16 multiplier)
{
	for (size_t index = 0; index < topology->count; index++)
		if (topology->devices[index].type == CDK2_ATAPI_DEVICE &&
		    topology->devices[index].port == port &&
		    topology->devices[index].multiplier == multiplier)
			return 1;
	return 0;
}

static EFI_STATUS execute(struct cdk2_ext_scsi_instance *instance, UINT16 port,
	UINT16 multiplier, struct cdk2_ext_scsi_packet *packet, const UINT8 *cdb,
	UINT8 cdb_length)
{
	struct cdk2_ata_command_block acb = { .command = 0xa0U };
	struct cdk2_ata_status_block asb;
	UINT8 packet_cdb[16] = { 0 };
	size_t packet_cdb_length = cdb_length <= 12U ? 12U : 16U;
	struct cdk2_ata_command_packet ata = { .asb = &asb, .acb = &acb,
		.timeout = packet->timeout, .in_data = packet->in_data,
		.out_data = packet->out_data, .in_length = packet->in_length,
		.out_length = packet->out_length, .length = 0x20U };
	EFI_STATUS status;

	for (UINT8 index = 0; index < cdb_length; index++)
		packet_cdb[index] = cdb[index];

	ata.protocol = packet->direction == CDK2_EXT_SCSI_DIRECTION_READ ? 4U :
		packet->direction == CDK2_EXT_SCSI_DIRECTION_WRITE ? 5U : 2U;
	if (instance->controller->topology.mode == CDK2_ATA_AHCI) {
		if (instance->controller->ahci == NULL)
			return EFI_NOT_READY;
		status = cdk2_ahci_execute(instance->controller->ahci, port, &ata,
			packet_cdb, packet_cdb_length, packet->timeout);
	} else {
		if (instance->controller->ide_engine == NULL || port > 1U ||
		    multiplier > 1U)
			return EFI_NOT_READY;
		status = cdk2_ide_atapi_execute(instance->controller->ide_engine,
			(UINT8)port, (UINT8)multiplier, &ata, packet_cdb,
			packet_cdb_length,
			packet->timeout);
	}
	packet->in_length = ata.in_length;
	packet->out_length = ata.out_length;
	packet->host_status = EFI_ERROR(status) ?
		(status == EFI_TIMEOUT ? 0x09U : 0x7fU) : 0U;
	packet->target_status = EFI_ERROR(status) ? 0x02U : 0U;
	return status;
}

static EFI_STATUS CDK2_MS_ABI pass_thru(struct cdk2_ext_scsi_protocol *protocol,
	UINT8 *target, UINT64 lun, struct cdk2_ext_scsi_packet *packet, void *event)
{
	struct cdk2_ext_scsi_instance *instance = from_protocol(protocol);
	UINT16 port, multiplier;
	EFI_STATUS status;

	(void)event;
	if (instance == NULL || target == NULL || packet == NULL ||
	    packet->cdb == NULL || lun != 0U ||
	    (packet->cdb_length != 6U && packet->cdb_length != 10U &&
	     packet->cdb_length != 12U && packet->cdb_length != 16U) ||
	    packet->direction > CDK2_EXT_SCSI_DIRECTION_WRITE ||
	    (packet->in_length != 0U && packet->in_data == NULL) ||
	    (packet->out_length != 0U && packet->out_data == NULL) ||
	    (packet->sense_length != 0U && packet->sense_data == NULL))
		return EFI_INVALID_PARAMETER;
	if (instance->mode.io_align > 1U &&
	    ((packet->in_data != NULL && (uintptr_t)packet->in_data %
	      instance->mode.io_align != 0U) ||
	     (packet->out_data != NULL && (uintptr_t)packet->out_data %
	      instance->mode.io_align != 0U) ||
	     (packet->sense_data != NULL && (uintptr_t)packet->sense_data %
	      instance->mode.io_align != 0U)))
		return EFI_INVALID_PARAMETER;
	port = target[0];
	multiplier = target_multiplier(target[1]);
	if (!atapi_exists(&instance->controller->topology, port, multiplier))
		return EFI_INVALID_PARAMETER;
	if (instance->services.wait != NULL) {
		status = instance->services.wait(instance->services.context,
			instance->controller);
		if (EFI_ERROR(status))
			return status;
	}
	status = execute(instance, port, multiplier, packet, packet->cdb,
		packet->cdb_length);
	if (EFI_ERROR(status) && packet->sense_length != 0U &&
	    *(UINT8 *)packet->cdb != 0x03U) {
		UINT8 request_sense[12] = { 0x03U, 0, 0, 0, packet->sense_length, 0 };
		struct cdk2_ext_scsi_packet sense = { .timeout = packet->timeout,
			.in_data = packet->sense_data, .in_length = packet->sense_length,
			.cdb = request_sense, .cdb_length = 12,
			.direction = CDK2_EXT_SCSI_DIRECTION_READ };
		EFI_STATUS sense_status = execute(instance, port, multiplier, &sense,
			request_sense, sizeof(request_sense));

		packet->sense_length = EFI_ERROR(sense_status) ? 0U :
			(UINT8)sense.in_length;
		if (EFI_ERROR(sense_status))
			packet->host_status = 0x10U;
	} else if (!EFI_ERROR(status)) {
		packet->sense_length = 0;
	}
	if (instance->services.done != NULL)
		instance->services.done(instance->services.context, instance->controller);
	return status;
}

static int all_ff(const UINT8 *target)
{
	for (size_t index = 0; index < CDK2_EXT_SCSI_TARGET_BYTES; index++)
		if (target[index] != 0xffU)
			return 0;
	return 1;
}
static int target_equal(const UINT8 *left, const UINT8 *right)
{
	for (size_t index = 0; index < CDK2_EXT_SCSI_TARGET_BYTES; index++)
		if (left[index] != right[index])
			return 0;
	return 1;
}

static EFI_STATUS next_common(struct cdk2_ext_scsi_instance *instance,
	UINT8 **target, UINT64 *lun, int include_lun)
{
	size_t start = 0;

	if (instance == NULL || target == NULL || *target == NULL ||
	    (include_lun && lun == NULL))
		return EFI_INVALID_PARAMETER;
	if (!all_ff(*target)) {
		if (!instance->enumerated || !target_equal(*target, instance->previous) ||
		    (include_lun && *lun != instance->previous_lun))
			return EFI_INVALID_PARAMETER;
		for (; start < instance->controller->topology.count; start++)
			if (instance->controller->topology.devices[start].port == (*target)[0] &&
			    instance->controller->topology.devices[start].multiplier ==
			    target_multiplier((*target)[1])) {
				start++;
				break;
			}
	}
	for (; start < instance->controller->topology.count; start++) {
		struct cdk2_ata_device *device =
			&instance->controller->topology.devices[start];

		if (device->type != CDK2_ATAPI_DEVICE)
			continue;
		memset(instance->target, 0, sizeof(instance->target));
		instance->target[0] = (UINT8)device->port;
		instance->target[1] = device->multiplier ==
			CDK2_ATA_NO_PORT_MULTIPLIER ? 0xffU : (UINT8)device->multiplier;
		memcpy(instance->previous, instance->target, sizeof(instance->target));
		instance->previous_lun = 0;
		instance->enumerated = 1;
		*target = instance->target;
		if (include_lun)
			*lun = 0;
		return EFI_SUCCESS;
	}
	instance->enumerated = 0;
	return EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI next_target_lun(
	struct cdk2_ext_scsi_protocol *protocol, UINT8 **target, UINT64 *lun)
{
	return next_common(from_protocol(protocol), target, lun, 1);
}

static EFI_STATUS CDK2_MS_ABI next_target(
	struct cdk2_ext_scsi_protocol *protocol, UINT8 **target)
{
	return next_common(from_protocol(protocol), target, NULL, 0);
}

static EFI_STATUS CDK2_MS_ABI build_path(
	struct cdk2_ext_scsi_protocol *protocol, UINT8 *target, UINT64 lun,
	void **device_path)
{
	struct cdk2_ext_scsi_instance *instance = from_protocol(protocol);
	UINT16 multiplier;
	size_t size;
	void *path;
	EFI_STATUS status;

	if (instance == NULL || target == NULL || device_path == NULL)
		return EFI_INVALID_PARAMETER;
	if (lun != 0U)
		return EFI_NOT_FOUND;
	multiplier = target_multiplier(target[1]);
	if (!atapi_exists(&instance->controller->topology, target[0], multiplier))
		return EFI_NOT_FOUND;
	size = instance->controller->topology.mode == CDK2_ATA_IDE ?
		sizeof(struct cdk2_atapi_device_path) :
		sizeof(struct cdk2_sata_device_path);
	status = instance->services.allocate(instance->services.context, size, &path);
	if (EFI_ERROR(status))
		return status;
	memset(path, 0, size);
	((struct cdk2_device_path_header *)path)->type = 3U;
	((struct cdk2_device_path_header *)path)->subtype =
		instance->controller->topology.mode == CDK2_ATA_IDE ? 1U : 18U;
	((struct cdk2_device_path_header *)path)->length[0] = (UINT8)size;
	if (instance->controller->topology.mode == CDK2_ATA_IDE) {
		struct cdk2_atapi_device_path *node = path;

		node->primary_secondary = target[0];
		node->slave_master = (UINT8)multiplier;
	} else {
		struct cdk2_sata_device_path *node = path;

		node->hba_port = target[0];
		node->multiplier = multiplier;
	}
	*device_path = path;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_target_lun(
	struct cdk2_ext_scsi_protocol *protocol, void *device_path, UINT8 **target,
	UINT64 *lun)
{
	struct cdk2_ext_scsi_instance *instance = from_protocol(protocol);
	struct cdk2_device_path_header *header = device_path;
	UINT16 port, multiplier;

	if (instance == NULL || device_path == NULL || target == NULL || lun == NULL)
		return EFI_INVALID_PARAMETER;
	if (header->type != 3U)
		return EFI_UNSUPPORTED;
	if (instance->controller->topology.mode == CDK2_ATA_IDE &&
	    header->subtype == 1U && header->length[0] ==
	    sizeof(struct cdk2_atapi_device_path)) {
		struct cdk2_atapi_device_path *node = device_path;

		port = node->primary_secondary;
		multiplier = node->slave_master;
	} else if (instance->controller->topology.mode == CDK2_ATA_AHCI &&
		   header->subtype == 18U && header->length[0] ==
		   sizeof(struct cdk2_sata_device_path)) {
		struct cdk2_sata_device_path *node = device_path;

		port = node->hba_port;
		multiplier = node->multiplier;
	} else {
		return EFI_UNSUPPORTED;
	}
	if (!atapi_exists(&instance->controller->topology, port, multiplier))
		return EFI_NOT_FOUND;
	memset(instance->target, 0, sizeof(instance->target));
	instance->target[0] = (UINT8)port;
	instance->target[1] = multiplier == CDK2_ATA_NO_PORT_MULTIPLIER ?
		0xffU : (UINT8)multiplier;
	*target = instance->target;
	*lun = 0;
	return EFI_SUCCESS;
}

static EFI_STATUS reset_one(struct cdk2_ext_scsi_instance *instance,
	UINT16 port, UINT16 multiplier, int validate)
{
	EFI_STATUS status;

	if (validate && !atapi_exists(&instance->controller->topology, port,
		multiplier))
		return EFI_INVALID_PARAMETER;
	if (instance->services.wait != NULL) {
		status = instance->services.wait(instance->services.context,
			instance->controller);
		if (EFI_ERROR(status))
			return status;
	}
	if (instance->controller->topology.mode == CDK2_ATA_AHCI)
		status = cdk2_ahci_reset_port(instance->controller->ahci, port, 5000000U);
	else
		status = cdk2_ide_reset(instance->controller->ide_engine, (UINT8)port,
			5000000U);
	if (instance->services.done != NULL)
		instance->services.done(instance->services.context, instance->controller);
	return status;
}

static EFI_STATUS CDK2_MS_ABI reset_channel(
	struct cdk2_ext_scsi_protocol *protocol)
{
	struct cdk2_ext_scsi_instance *instance = from_protocol(protocol);
	UINT32 ports = 0;
	EFI_STATUS result = EFI_SUCCESS;

	if (instance == NULL)
		return EFI_INVALID_PARAMETER;
	for (size_t index = 0; index < instance->controller->topology.count; index++) {
		UINT16 port = instance->controller->topology.devices[index].port;
		EFI_STATUS status;

		if (port >= 32U || (ports & (1U << port)) != 0U)
			continue;
		ports |= 1U << port;
		status = reset_one(instance, port, 0, 0);
		if (EFI_ERROR(status) && !EFI_ERROR(result))
			result = status;
	}
	return result;
}

static EFI_STATUS CDK2_MS_ABI reset_target(
	struct cdk2_ext_scsi_protocol *protocol, UINT8 *target, UINT64 lun)
{
	struct cdk2_ext_scsi_instance *instance = from_protocol(protocol);

	if (instance == NULL || target == NULL || lun != 0U)
		return EFI_INVALID_PARAMETER;
	return reset_one(instance, target[0], target_multiplier(target[1]), 1);
}

EFI_STATUS cdk2_ext_scsi_init(struct cdk2_ext_scsi_instance *instance,
	struct cdk2_ata_controller *controller,
	const struct cdk2_ata_protocol_services *services, UINT32 io_align)
{
	if (instance == NULL || controller == NULL || services == NULL ||
	    services->allocate == NULL || io_align == 0U)
		return EFI_INVALID_PARAMETER;
	memset(instance, 0, sizeof(*instance));
	instance->controller = controller;
	instance->services = *services;
	instance->mode = (struct cdk2_ext_scsi_mode) { 0U,
		CDK2_ATA_PASS_THRU_ATTRIBUTES_PHYSICAL |
		CDK2_ATA_PASS_THRU_ATTRIBUTES_LOGICAL, io_align };
	instance->protocol = (struct cdk2_ext_scsi_protocol) { &instance->mode,
		pass_thru, next_target_lun, build_path, get_target_lun,
		reset_channel, reset_target, next_target };
	return EFI_SUCCESS;
}
