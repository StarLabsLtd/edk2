/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/sio_bus_binding.h>

static BOOLEAN supported_bridge(const struct cdk2_sio_pci_info *info)
{
	if ((info->command & 3U) != 3U || info->base_class != 6U)
		return FALSE;
	return info->sub_class == 1U ||
		(info->sub_class == 0x80U && info->vendor_id == 0x8086U &&
		 info->function == 0U);
}

EFI_STATUS cdk2_sio_binding_supported(struct cdk2_sio_binding *binding,
	void *controller)
{
	struct cdk2_sio_pci_info info;
	EFI_STATUS status;

	if (binding == NULL || binding->ops == NULL ||
	    binding->ops->open_pci == NULL || binding->ops->close_pci == NULL ||
	    binding->ops->get_info == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->ops->open_pci(binding->context, controller);
	if (EFI_ERROR(status))
		return status;
	status = binding->ops->get_info(binding->context, controller, &info);
	binding->ops->close_pci(binding->context, controller);
	if (EFI_ERROR(status))
		return status;
	return supported_bridge(&info) ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

static void remove_child(struct cdk2_sio_binding *binding, UINTN index)
{
	struct cdk2_sio_child *child = &binding->children[index];

	if (child->related) {
		(void)binding->ops->close_child(binding->context, binding->controller,
			child, index);
		child->related = FALSE;
	}
	if (child->installed) {
		(void)binding->ops->uninstall_child(binding->context,
			binding->controller, child, index);
		child->installed = FALSE;
	}
	child->handle = NULL;
	child->device_path = NULL;
}

static void rollback(struct cdk2_sio_binding *binding)
{
	while (binding->child_count != 0U) {
		binding->child_count--;
		remove_child(binding, binding->child_count);
	}
	if (binding->attributes_enabled && binding->ops->set_attributes != NULL) {
		(void)binding->ops->set_attributes(binding->context,
			binding->controller, binding->original_attributes, NULL);
		binding->attributes_enabled = FALSE;
	}
	if (binding->path_open) {
		(void)binding->ops->close_device_path(binding->context,
			binding->controller);
		binding->path_open = FALSE;
	}
	if (binding->pci_open) {
		(void)binding->ops->close_pci(binding->context, binding->controller);
		binding->pci_open = FALSE;
	}
	binding->controller = NULL;
}

EFI_STATUS cdk2_sio_binding_start(struct cdk2_sio_binding *binding,
	void *controller)
{
	UINT64 supported, isa;
	EFI_STATUS status;
	UINTN index;

	if (binding == NULL || binding->ops == NULL || binding->pci_open ||
	    binding->ops->open_pci == NULL || binding->ops->close_pci == NULL ||
	    binding->ops->open_device_path == NULL ||
	    binding->ops->close_device_path == NULL ||
	    binding->ops->get_attributes == NULL ||
	    binding->ops->supported_attributes == NULL ||
	    binding->ops->enable_attributes == NULL ||
	    binding->ops->set_attributes == NULL ||
	    binding->ops->install_child == NULL ||
	    binding->ops->uninstall_child == NULL ||
	    binding->ops->open_child == NULL || binding->ops->close_child == NULL)
		return EFI_INVALID_PARAMETER;
	binding->controller = controller;
	status = binding->ops->open_pci(binding->context, controller);
	if (EFI_ERROR(status))
		return status;
	binding->pci_open = TRUE;
	status = binding->ops->open_device_path(binding->context, controller);
	if (EFI_ERROR(status))
		goto fail;
	binding->path_open = TRUE;
	status = binding->ops->get_attributes(binding->context, controller, 0,
		&binding->original_attributes);
	if (EFI_ERROR(status))
		goto fail;
	status = binding->ops->supported_attributes(binding->context, controller,
		0, &supported);
	if (EFI_ERROR(status))
		goto fail;
	isa = supported & (CDK2_SIO_PCI_ISA_IO | CDK2_SIO_PCI_ISA_IO_16);
	if (isa != CDK2_SIO_PCI_ISA_IO && isa != CDK2_SIO_PCI_ISA_IO_16) {
		status = EFI_UNSUPPORTED;
		goto fail;
	}
	status = binding->ops->enable_attributes(binding->context, controller,
		CDK2_SIO_PCI_IO | CDK2_SIO_PCI_MEMORY | CDK2_SIO_PCI_BUS_MASTER |
		isa | CDK2_SIO_PCI_MOTHERBOARD_IO, NULL);
	if (EFI_ERROR(status))
		goto fail;
	binding->attributes_enabled = TRUE;
	for (index = 0; index < 3U; index++) {
		cdk2_sio_init(&binding->children[index].protocol, index);
		status = binding->ops->install_child(binding->context, controller,
			&binding->children[index], index);
		if (EFI_ERROR(status))
			goto fail;
		binding->children[index].installed = TRUE;
		binding->child_count = index + 1U;
		status = binding->ops->open_child(binding->context, controller,
			&binding->children[index], index);
		if (EFI_ERROR(status))
			goto fail;
		binding->children[index].related = TRUE;
	}
	return EFI_SUCCESS;
fail:
	rollback(binding);
	return status;
}

EFI_STATUS cdk2_sio_binding_stop(struct cdk2_sio_binding *binding,
	UINTN number_of_children, void **child_handles)
{
	UINTN index, request;

	if (binding == NULL || !binding->pci_open)
		return CDK2_SIO_NOT_STARTED;
	if (number_of_children != 0U && child_handles == NULL)
		return EFI_INVALID_PARAMETER;
	for (request = 0; request < number_of_children; request++)
		for (index = 0; index < 3U; index++)
			if (binding->children[index].installed &&
			    binding->children[index].handle == child_handles[request]) {
				remove_child(binding, index);
				binding->child_count--;
				break;
			}
	if (number_of_children != 0U)
		return EFI_SUCCESS;
	if (binding->child_count != 0U)
		return EFI_DEVICE_ERROR;
	rollback(binding);
	return EFI_SUCCESS;
}
