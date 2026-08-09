/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_backend.h>

#include <string.h>

#define AHCI_PX_SIG 0x24U
#define AHCI_PX_SSTS 0x28U
#define AHCI_SIG_ATA 0x00000101U
#define AHCI_SIG_ATAPI 0xeb140101U

static UINT16 get16(const UINT8 *data, size_t word)
{
	return data[word * 2U] | ((UINT16)data[word * 2U + 1U] << 8);
}

EFI_STATUS cdk2_ata_backend_prepare(struct cdk2_ata_backend_pool *pool,
	struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_controller_backend *backend;
	struct cdk2_ahci_dma_services services;
	struct cdk2_ide_services ide_services;
	struct cdk2_ide_channel channels[2] = {
		{ 0x0000U, 0x1002U, 0x4000U },
		{ 0x2000U, 0x3002U, 0x4008U }
	};
	UINT32 capability, ports;
	EFI_STATUS status;

	if (pool == NULL || pool->allocate == NULL || pool->release == NULL ||
	    controller == NULL || controller->pci == NULL || controller->ide == NULL ||
	    controller->backend != NULL)
		return EFI_INVALID_PARAMETER;
	status = pool->allocate(pool->context, sizeof(*backend), (void **)&backend);
	if (EFI_ERROR(status))
		return status;
	memset(backend, 0, sizeof(*backend));
	backend->pool = *pool;
	status = cdk2_ata_pci_adapter_init(&backend->adapter, controller->pci,
		controller->ide, 5U);
	if (EFI_ERROR(status))
		goto fail;
	if (controller->topology.mode == CDK2_ATA_AHCI) {
		status = cdk2_ata_pci_read_ahci_capability(controller->pci, 5U,
			&capability, &ports);
		if (EFI_ERROR(status) || ports == 0U) {
			status = EFI_ERROR(status) ? status : EFI_NOT_FOUND;
			goto fail_adapter;
		}
		cdk2_ata_pci_ahci_services(&backend->adapter, &services);
		status = cdk2_ahci_engine_init(&backend->ahci, &services, capability,
			ports);
		if (EFI_ERROR(status))
			goto fail_adapter;
		backend->ahci_initialized = 1;
		controller->ahci = &backend->ahci;
		controller->ahci_capability = capability;
		controller->ports_implemented = ports;
	} else {
		cdk2_ata_pci_ide_services(&backend->adapter, &ide_services);
		status = cdk2_ide_engine_init(&backend->ide, &ide_services, channels, 2U);
		if (EFI_ERROR(status))
			goto fail_adapter;
		backend->ide_initialized = 1;
		controller->ide_engine = &backend->ide;
	}
	controller->backend = backend;
	return EFI_SUCCESS;
fail_adapter:
	(void)cdk2_ata_pci_adapter_release(&backend->adapter);
fail:
	memset(backend, 0xa5, sizeof(*backend));
	pool->release(pool->context, backend, sizeof(*backend));
	return status;
}

void cdk2_ata_backend_release(struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_controller_backend *backend;
	struct cdk2_ata_backend_pool pool;

	if (controller == NULL || controller->backend == NULL)
		return;
	backend = controller->backend;
	pool = backend->pool;
	if (backend->ahci_initialized)
		cdk2_ahci_engine_destroy(&backend->ahci);
	(void)cdk2_ata_pci_adapter_release(&backend->adapter);
	controller->ahci = NULL;
	controller->ide_engine = NULL;
	controller->backend = NULL;
	memset(backend, 0xa5, sizeof(*backend));
	pool.release(pool.context, backend, sizeof(*backend));
}

EFI_STATUS cdk2_ata_backend_discover_ahci(struct cdk2_ata_controller *controller,
	struct cdk2_ata_topology *topology)
{
	struct cdk2_ata_controller_backend *backend;
	struct cdk2_ata_topology original;

	if (controller == NULL || topology == NULL || controller->backend == NULL ||
	    controller->ahci == NULL || topology->mode != CDK2_ATA_AHCI)
		return EFI_INVALID_PARAMETER;
	backend = controller->backend;
	original = *topology;
	for (UINT16 port = 0; port < 32U; port++) {
		struct cdk2_ata_command_block acb = { 0 };
		struct cdk2_ata_status_block asb;
		struct cdk2_ata_command_packet packet = { .asb = &asb, .acb = &acb,
			.timeout = 5000000U, .in_data = backend->identify,
			.in_length = sizeof(backend->identify), .protocol = 0x0aU,
			.length = 0x20U };
		UINT32 ssts, signature;
		enum cdk2_ata_device_type type;
		EFI_STATUS status;

		if ((controller->ports_implemented & (1U << port)) == 0U)
			continue;
		ssts = controller->ahci->services.read(
			controller->ahci->services.context, port, AHCI_PX_SSTS);
		if ((ssts & 0x0fU) != 3U) {
			if ((ssts & 0x0fU) == 1U)
				(void)cdk2_ahci_reset_port(controller->ahci, port,
					5000000U);
			ssts = controller->ahci->services.read(
				controller->ahci->services.context, port, AHCI_PX_SSTS);
			if ((ssts & 0x0fU) != 3U)
				continue;
		}
		signature = controller->ahci->services.read(
			controller->ahci->services.context, port, AHCI_PX_SIG);
		if (signature == AHCI_SIG_ATA) {
			type = CDK2_ATA_DISK;
			acb.command = 0xecU;
		} else if (signature == AHCI_SIG_ATAPI) {
			type = CDK2_ATAPI_DEVICE;
			acb.command = 0xa1U;
		} else {
			continue;
		}
		memset(backend->identify, 0, sizeof(backend->identify));
		status = cdk2_ahci_execute(controller->ahci, port, &packet, NULL, 0,
			packet.timeout);
		if (EFI_ERROR(status))
			continue;
		status = cdk2_ata_add_device(topology, port,
			CDK2_ATA_NO_PORT_MULTIPLIER, type);
		if (EFI_ERROR(status)) {
			*topology = original;
			return status;
		}
		topology->devices[topology->count - 1U].block_size =
			(get16(backend->identify, 106U) & 0x5000U) == 0x5000U ?
			((UINT32)get16(backend->identify, 118U) << 16) |
			get16(backend->identify, 117U) : 512U;
		topology->devices[topology->count - 1U].alignment =
			(get16(backend->identify, 209U) & 0x4000U) != 0U ?
			get16(backend->identify, 209U) & 0x3fffU : 0U;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_backend_discover_ide(struct cdk2_ata_controller *controller,
	struct cdk2_ata_topology *topology)
{
	struct cdk2_ata_controller_backend *backend;
	struct cdk2_ata_topology original;
	EFI_STATUS status;

	if (controller == NULL || topology == NULL || controller->backend == NULL ||
	    controller->ide_engine == NULL || topology->mode != CDK2_ATA_IDE)
		return EFI_INVALID_PARAMETER;
	backend = controller->backend;
	original = *topology;
	for (UINT8 channel = 0; channel < 2U; channel++) {
		BOOLEAN enabled = FALSE;
		UINT8 devices = 0;

		status = ((struct cdk2_ide_init_protocol *)controller->ide)->get_channel(
			controller->ide, channel, &enabled, &devices);
		if (EFI_ERROR(status)) {
			*topology = original;
			return status;
		}
		if (!enabled)
			continue;
		if (devices > 2U) {
			*topology = original;
			return EFI_DEVICE_ERROR;
		}
		if (((struct cdk2_ide_init_protocol *)controller->ide)->notify != NULL)
			(void)((struct cdk2_ide_init_protocol *)controller->ide)->notify(
				controller->ide, 0U, channel);
		(void)cdk2_ide_reset(controller->ide_engine, channel, 5000000U);
		for (UINT8 device = 0; device < devices; device++) {
			struct cdk2_ata_command_block acb = { .command = 0xecU };
			struct cdk2_ata_status_block asb;
			struct cdk2_ata_command_packet packet = { .asb = &asb,
				.acb = &acb, .timeout = 5000000U,
				.in_data = backend->identify,
				.in_length = sizeof(backend->identify), .protocol = 4U,
				.length = 0x20U };
			enum cdk2_ata_device_type type = CDK2_ATA_DISK;

			memset(backend->identify, 0, sizeof(backend->identify));
			status = cdk2_ide_execute(controller->ide_engine, channel, device,
				&packet, packet.timeout);
			if (EFI_ERROR(status)) {
				acb.command = 0xa1U;
				status = cdk2_ide_execute(controller->ide_engine, channel,
					device, &packet, packet.timeout);
				type = CDK2_ATAPI_DEVICE;
			}
			if (EFI_ERROR(status))
				continue;
			if (((struct cdk2_ide_init_protocol *)controller->ide)->submit != NULL) {
				status = ((struct cdk2_ide_init_protocol *)controller->ide)->submit(
					controller->ide, channel, device, backend->identify);
				if (EFI_ERROR(status)) {
					*topology = original;
					return status;
				}
			}
			status = cdk2_ata_add_device(topology, channel, device, type);
			if (EFI_ERROR(status)) {
				*topology = original;
				return status;
			}
			topology->devices[topology->count - 1U].block_size = 512U;
		}
		if (((struct cdk2_ide_init_protocol *)controller->ide)->notify != NULL)
			(void)((struct cdk2_ide_init_protocol *)controller->ide)->notify(
				controller->ide, 1U, channel);
	}
	cdk2_ata_pci_adapter_enable_timing(&backend->adapter);
	return EFI_SUCCESS;
}
