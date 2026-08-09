/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <string.h>

#define PCI_CLASS_MASS_STORAGE 1U
#define PCI_SUBCLASS_IDE 1U
#define PCI_SUBCLASS_SATA 6U
#define PCI_IF_AHCI 1U
#define PCI_DEVICE_ENABLE 7U

static int class_mode(const UINT8 code[3], enum cdk2_ata_mode *mode)
{
	if (code[2] != PCI_CLASS_MASS_STORAGE)
		return -1;
	if (code[1] == PCI_SUBCLASS_IDE) {
		*mode = CDK2_ATA_IDE;
		return 0;
	}
	if (code[1] == PCI_SUBCLASS_SATA && code[0] == PCI_IF_AHCI) {
		*mode = CDK2_ATA_AHCI;
		return 0;
	}
	return -1;
}

static struct cdk2_ata_controller *find_controller(struct cdk2_ata_binding *binding,
	void *handle, size_t *index)
{
	for (size_t i = 0; i < binding->count; i++)
		if (binding->controllers[i].handle == handle) {
			if (index != NULL)
				*index = i;
			return &binding->controllers[i];
		}
	return NULL;
}

EFI_STATUS cdk2_ata_binding_init(struct cdk2_ata_binding *binding,
	const struct cdk2_ata_binding_services *services)
{
	if (binding == NULL || services == NULL || services->open_path == NULL ||
	    services->close_path == NULL || services->open_ide == NULL ||
	    services->close_ide == NULL || services->get_pci == NULL ||
	    services->read_class == NULL || services->get_attributes == NULL ||
	    services->enable_attributes == NULL || services->restore_attributes == NULL ||
	    services->discover_ide == NULL || services->discover_ahci == NULL ||
	    services->prepare_engines == NULL || services->release_engines == NULL ||
	    services->create_protocols == NULL || services->destroy_protocols == NULL ||
	    services->install == NULL || services->uninstall == NULL)
		return EFI_INVALID_PARAMETER;
	memset(binding, 0, sizeof(*binding));
	binding->services = *services;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_binding_supported(struct cdk2_ata_binding *binding,
	void *controller)
{
	struct cdk2_ata_binding_services *services;
	void *ide = NULL, *pci = NULL; UINT8 code[3]; enum cdk2_ata_mode mode;
	EFI_STATUS status;
	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_controller(binding, controller, NULL) != NULL)
		return EFI_ALREADY_STARTED;
	services = &binding->services;
	status = services->open_path(services->context, controller);
	if (EFI_ERROR(status))
		return status;
	status = services->close_path(services->context, controller);
	if (EFI_ERROR(status))
		return status;
	status = services->open_ide(services->context, controller, &ide);
	if (EFI_ERROR(status))
		return status;
	status = services->close_ide(services->context, controller);
	if (EFI_ERROR(status))
		return status;
	status = services->get_pci(services->context, controller, &pci);
	if (EFI_ERROR(status) || pci == NULL)
		return EFI_UNSUPPORTED;
	status = services->read_class(services->context, pci, code);
	return EFI_ERROR(status) || class_mode(code, &mode) != 0 ?
		EFI_UNSUPPORTED : EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_binding_start(struct cdk2_ata_binding *binding, void *controller)
{
	struct cdk2_ata_binding_services *services; struct cdk2_ata_controller staged;
	UINT8 code[3]; UINT64 supported; EFI_STATUS status;
	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_controller(binding, controller, NULL) != NULL)
		return EFI_ALREADY_STARTED;
	if (binding->count == CDK2_ATA_MAX_CONTROLLERS)
		return EFI_OUT_OF_RESOURCES;
	services = &binding->services; memset(&staged, 0, sizeof(staged));
	staged.handle = controller;
	status = services->open_ide(services->context, controller, &staged.ide);
	if (EFI_ERROR(status))
		return status;
	status = services->get_pci(services->context, controller, &staged.pci);
	if (EFI_ERROR(status) || staged.pci == NULL)
		goto rollback;
	status = services->read_class(services->context, staged.pci, code);
	if (EFI_ERROR(status) || class_mode(code, &staged.topology.mode) != 0) {
		status = EFI_UNSUPPORTED;
		goto rollback;
	}
	status = services->get_attributes(services->context, staged.pci,
		&staged.original_attributes, &supported);
	if (EFI_ERROR(status))
		goto rollback;
	staged.enabled_attributes = supported & PCI_DEVICE_ENABLE;
	status = services->enable_attributes(services->context, staged.pci,
		staged.enabled_attributes);
	if (EFI_ERROR(status))
		goto rollback;
	status = cdk2_ata_topology_init(&staged.topology, staged.topology.mode);
	if (EFI_ERROR(status))
		goto restore;
	status = staged.topology.mode == CDK2_ATA_IDE ?
		services->discover_ide(services->context, staged.pci, staged.ide,
			&staged.topology) :
		services->discover_ahci(services->context, staged.pci,
			&staged.ahci_capability, &staged.ports_implemented, &staged.topology);
	if (EFI_ERROR(status))
		goto restore;
	status = services->prepare_engines(services->context, &staged);
	if (EFI_ERROR(status))
		goto restore;
	status = services->create_protocols(services->context, &staged,
		&staged.protocols);
	if (EFI_ERROR(status) || staged.protocols == NULL) {
		status = EFI_ERROR(status) ? status : EFI_OUT_OF_RESOURCES;
		if (staged.protocols != NULL)
			services->destroy_protocols(services->context, staged.protocols);
		goto release_engines;
	}
	status = services->install(services->context, controller, staged.protocols);
	if (EFI_ERROR(status))
		goto destroy_protocols;
	staged.protocols_installed = staged.started = 1;
	binding->controllers[binding->count++] = staged;
	binding->controllers[binding->count - 1U].protocols->ata.controller =
		&binding->controllers[binding->count - 1U];
	binding->controllers[binding->count - 1U].protocols->ext_scsi.controller =
		&binding->controllers[binding->count - 1U];
	return EFI_SUCCESS;
destroy_protocols:
	services->destroy_protocols(services->context, staged.protocols);
release_engines:
	services->release_engines(services->context, &staged);
restore:
	(void)services->restore_attributes(services->context, staged.pci,
		staged.original_attributes);
rollback:
	(void)services->close_ide(services->context, controller);
	return status;
}

EFI_STATUS cdk2_ata_binding_stop(struct cdk2_ata_binding *binding, void *controller)
{
	struct cdk2_ata_controller *instance; size_t index; EFI_STATUS status;
	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	instance = find_controller(binding, controller, &index);
	if (instance == NULL)
		return EFI_NOT_STARTED;
	status = binding->services.uninstall(binding->services.context, controller,
		instance->protocols);
	if (EFI_ERROR(status))
		return status;
	status = binding->services.restore_attributes(binding->services.context,
		instance->pci, instance->original_attributes);
	if (EFI_ERROR(status)) {
		(void)binding->services.install(binding->services.context, controller,
			instance->protocols);
		return status;
	}
	status = binding->services.close_ide(binding->services.context, controller);
	if (EFI_ERROR(status)) {
		(void)binding->services.enable_attributes(binding->services.context,
			instance->pci, instance->enabled_attributes);
		(void)binding->services.install(binding->services.context, controller,
			instance->protocols);
		return status;
	}
	binding->services.release_engines(binding->services.context, instance);
	binding->services.destroy_protocols(binding->services.context,
		instance->protocols);
	memmove(&binding->controllers[index], &binding->controllers[index + 1U],
		(binding->count - index - 1U) * sizeof(binding->controllers[0]));
	binding->count--;
	for (size_t current = index; current < binding->count; current++) {
		binding->controllers[current].protocols->ata.controller =
			&binding->controllers[current];
		binding->controllers[current].protocols->ext_scsi.controller =
			&binding->controllers[current];
	}
	return EFI_SUCCESS;
}
