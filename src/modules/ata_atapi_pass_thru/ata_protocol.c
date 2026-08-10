/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stddef.h>
#include <string.h>

static struct cdk2_ata_protocol_instance *instance_from_protocol(
	struct cdk2_ata_pass_thru_protocol *protocol)
{
	if (protocol == NULL)
		return NULL;
	return (struct cdk2_ata_protocol_instance *)((UINT8 *)protocol -
		offsetof(struct cdk2_ata_protocol_instance, protocol));
}

static int device_exists(const struct cdk2_ata_topology *topology, UINT16 port,
	UINT16 multiplier)
{
	for (size_t index = 0; index < topology->count; index++)
		if (topology->devices[index].port == port &&
		    topology->devices[index].multiplier == multiplier)
			return 1;
	return 0;
}

static const struct cdk2_ata_device *find_device(
	const struct cdk2_ata_topology *topology, UINT16 port, UINT16 multiplier)
{
	for (size_t index = 0; index < topology->count; index++)
		if (topology->devices[index].port == port &&
		    topology->devices[index].multiplier == multiplier)
			return &topology->devices[index];
	return NULL;
}

static EFI_STATUS CDK2_MS_ABI pass_thru(
	struct cdk2_ata_pass_thru_protocol *protocol, UINT16 port,
	UINT16 multiplier, struct cdk2_ata_command_packet *packet, void *event)
{
	struct cdk2_ata_protocol_instance *instance =
		instance_from_protocol(protocol);
	struct cdk2_ata_controller *controller;
	const struct cdk2_ata_device *device;
	EFI_STATUS status;

	if (instance == NULL || packet == NULL || packet->acb == NULL)
		return EFI_INVALID_PARAMETER;
	(void)event;
	controller = instance->controller;
	device = controller == NULL ? NULL : find_device(&controller->topology, port,
		multiplier);
	if (controller == NULL || !controller->started || device == NULL)
		return EFI_NOT_FOUND;
	status = cdk2_ata_validate_transfer(packet->protocol, packet->length,
		packet->in_data, packet->in_length, packet->out_data,
		packet->out_length, instance->mode.io_align);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_ata_normalize_transfer(device, packet);
	if (EFI_ERROR(status))
		return status;
	if (event != NULL)
		return instance->services.submit == NULL ? EFI_UNSUPPORTED :
			instance->services.submit(instance->services.context, controller, port,
				multiplier, packet, event);
	if (instance->services.wait != NULL) {
		status = instance->services.wait(instance->services.context, controller);
		if (EFI_ERROR(status))
			return status;
	}
	if (controller->topology.mode == CDK2_ATA_AHCI) {
		if (controller->ahci == NULL ||
		    multiplier != CDK2_ATA_NO_PORT_MULTIPLIER)
			status = EFI_UNSUPPORTED;
		else
			status = cdk2_ahci_execute(controller->ahci, port, packet, NULL, 0,
				packet->timeout);
	} else if (controller->ide_engine == NULL || port > 1U || multiplier > 1U) {
		status = EFI_UNSUPPORTED;
	} else {
		status = cdk2_ide_execute(controller->ide_engine, (UINT8)port,
			(UINT8)multiplier, packet, packet->timeout);
	}
	if (instance->services.done != NULL)
		instance->services.done(instance->services.context, controller);
	return status;
}

static EFI_STATUS CDK2_MS_ABI next_port(
	struct cdk2_ata_pass_thru_protocol *protocol, UINT16 *port)
{
	struct cdk2_ata_protocol_instance *instance =
		instance_from_protocol(protocol);

	return instance == NULL || instance->controller == NULL ?
		EFI_INVALID_PARAMETER :
		cdk2_ata_get_next_port(&instance->controller->topology, port);
}

static EFI_STATUS CDK2_MS_ABI next_device(
	struct cdk2_ata_pass_thru_protocol *protocol, UINT16 port,
	UINT16 *multiplier)
{
	struct cdk2_ata_protocol_instance *instance =
		instance_from_protocol(protocol);

	return instance == NULL || instance->controller == NULL ?
		EFI_INVALID_PARAMETER : cdk2_ata_get_next_device(
			&instance->controller->topology, port, multiplier);
}

static EFI_STATUS CDK2_MS_ABI build_path(
	struct cdk2_ata_pass_thru_protocol *protocol, UINT16 port,
	UINT16 multiplier, void **device_path)
{
	struct cdk2_ata_protocol_instance *instance =
		instance_from_protocol(protocol);
	size_t size;
	EFI_STATUS status;
	void *path;

	if (instance == NULL || instance->controller == NULL ||
	    device_path == NULL || instance->services.allocate == NULL)
		return EFI_INVALID_PARAMETER;
	*device_path = NULL;
	if (!device_exists(&instance->controller->topology, port, multiplier))
		return EFI_NOT_FOUND;
	size = instance->controller->topology.mode == CDK2_ATA_IDE ?
		sizeof(struct cdk2_atapi_device_path) :
		sizeof(struct cdk2_sata_device_path);
	status = instance->services.allocate(instance->services.context, size, &path);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_ata_build_device_path(&instance->controller->topology, port,
		multiplier, path, &size);
	if (EFI_ERROR(status)) {
		if (instance->services.release != NULL)
			instance->services.release(instance->services.context, path);
		return status;
	}
	*device_path = path;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_device(
	struct cdk2_ata_pass_thru_protocol *protocol, void *device_path,
	UINT16 *port, UINT16 *multiplier)
{
	struct cdk2_ata_protocol_instance *instance =
		instance_from_protocol(protocol);
	struct cdk2_device_path_header *header = device_path;
	size_t size;

	if (instance == NULL || instance->controller == NULL || header == NULL)
		return EFI_INVALID_PARAMETER;
	size = (size_t)header->length[0] | ((size_t)header->length[1] << 8);
	return cdk2_ata_get_device(&instance->controller->topology, device_path,
		size, port, multiplier);
}

static EFI_STATUS reset(struct cdk2_ata_protocol_instance *instance, UINT16 port,
	UINT16 multiplier, int check_device)
{
	struct cdk2_ata_controller *controller;
	EFI_STATUS status;

	if (instance == NULL || instance->controller == NULL)
		return EFI_INVALID_PARAMETER;
	controller = instance->controller;
	if (check_device && !device_exists(&controller->topology, port, multiplier))
		return EFI_NOT_FOUND;
	if (instance->services.cancel_scope != NULL) {
		EFI_STATUS cancel_status = instance->services.cancel_scope(
			instance->services.context, controller, port, multiplier,
			check_device && controller->topology.mode == CDK2_ATA_AHCI);

		if (EFI_ERROR(cancel_status))
			return cancel_status;
	} else if (instance->services.wait != NULL) {
		EFI_STATUS wait_status = instance->services.wait(instance->services.context,
			controller);

		if (EFI_ERROR(wait_status))
			return wait_status;
	}
	if (controller->topology.mode == CDK2_ATA_AHCI)
		status = controller->ahci == NULL ? EFI_UNSUPPORTED :
			cdk2_ahci_reset_port(controller->ahci, port, 5000000U);
	else if (controller->ide_engine == NULL || port > 1U)
		status = EFI_UNSUPPORTED;
	else
		status = cdk2_ide_reset(controller->ide_engine, (UINT8)port, 5000000U);
	if (instance->services.done != NULL && instance->services.cancel_scope == NULL)
		instance->services.done(instance->services.context, controller);
	return status;
}

static EFI_STATUS CDK2_MS_ABI reset_port(
	struct cdk2_ata_pass_thru_protocol *protocol, UINT16 port)
{
	return reset(instance_from_protocol(protocol), port, 0, 0);
}

static EFI_STATUS CDK2_MS_ABI reset_device(
	struct cdk2_ata_pass_thru_protocol *protocol, UINT16 port,
	UINT16 multiplier)
{
	return reset(instance_from_protocol(protocol), port, multiplier, 1);
}

EFI_STATUS cdk2_ata_protocol_init(struct cdk2_ata_protocol_instance *instance,
	struct cdk2_ata_controller *controller,
	const struct cdk2_ata_protocol_services *services, UINT32 io_align)
{
	if (instance == NULL || controller == NULL || services == NULL ||
	    services->allocate == NULL || io_align == 0U)
		return EFI_INVALID_PARAMETER;
	memset(instance, 0, sizeof(*instance));
	instance->controller = controller;
	instance->services = *services;
	instance->mode.attributes = CDK2_ATA_PASS_THRU_ATTRIBUTES_PHYSICAL |
		CDK2_ATA_PASS_THRU_ATTRIBUTES_LOGICAL |
		(services->submit != NULL ? CDK2_ATA_PASS_THRU_ATTRIBUTES_NONBLOCKIO : 0U);
	instance->mode.io_align = io_align;
	instance->protocol = (struct cdk2_ata_pass_thru_protocol) {
		&instance->mode, pass_thru, next_port, next_device, build_path,
		get_device, reset_port, reset_device
	};
	return EFI_SUCCESS;
}
