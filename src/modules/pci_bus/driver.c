/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_binding.h>

#include <string.h>

static struct cdk2_pci_bus_driver *driver(
	struct cdk2_driver_binding_protocol *protocol)
{
	return (struct cdk2_pci_bus_driver *)protocol;
}

static EFI_STATUS CDK2_MS_ABI supported(
	struct cdk2_driver_binding_protocol *protocol, void *controller,
	void *remaining)
{
	struct cdk2_pci_bus_driver *instance = driver(protocol);
	if (controller == NULL || instance->probe == NULL)
		return EFI_INVALID_PARAMETER;
	return instance->probe(instance->context, controller, remaining) == 0 ?
		EFI_SUCCESS : EFI_UNSUPPORTED;
}

static EFI_STATUS CDK2_MS_ABI start(struct cdk2_driver_binding_protocol *protocol,
	void *controller, void *remaining)
{
	struct cdk2_pci_bus_driver *instance = driver(protocol);
	struct cdk2_pci_topology topology;
	void *path = NULL;
	size_t path_size = 0;
	int call_status;
	if (controller == NULL || instance->discover == NULL ||
	    instance->release_discovery == NULL)
		return EFI_INVALID_PARAMETER;
	memset(&topology, 0, sizeof(topology));
	if (instance->discover(instance->context, controller, remaining, &topology,
		&path, &path_size) != 0)
		return EFI_UNSUPPORTED;
	call_status = cdk2_pci_bus_start(&instance->binding, controller, path,
		path_size, &topology);
	instance->release_discovery(instance->context, path);
	if (instance->finish_discovery != NULL)
		instance->finish_discovery(instance->context, controller,
			call_status == 0);
	return call_status == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

static EFI_STATUS CDK2_MS_ABI stop(struct cdk2_driver_binding_protocol *protocol,
	void *controller, UINTN child_count, void **children)
{
	struct cdk2_pci_bus_driver *instance = driver(protocol);
	if (cdk2_pci_bus_stop(&instance->binding, controller, children,
		child_count) != 0) {
		if (instance->finish_stop != NULL)
			instance->finish_stop(instance->context, controller, 0);
		return EFI_DEVICE_ERROR;
	}
	if (instance->finish_stop != NULL)
		instance->finish_stop(instance->context, controller, 1);
	return EFI_SUCCESS;
}

int cdk2_pci_bus_driver_entry(struct cdk2_pci_bus_driver *instance,
	void *image_handle)
{
	if (instance == NULL || image_handle == NULL || instance->publish == NULL ||
	    instance->unpublish == NULL || instance->published)
		return -1;
	instance->protocol = (struct cdk2_driver_binding_protocol) {
		.supported = supported, .start = start, .stop = stop, .version = 0x10,
		.image_handle = image_handle };
	cdk2_pci_bus_initialize_component_names(&instance->binding);
	if (instance->publish(instance->context, instance) != 0) {
		memset(&instance->protocol, 0, sizeof(instance->protocol));
		return -1;
	}
	instance->published = 1;
	return 0;
}

int cdk2_pci_bus_driver_unload(struct cdk2_pci_bus_driver *instance)
{
	if (instance == NULL || !instance->published)
		return -1;
	while (instance->binding.child_count != 0U) {
		void *parent = instance->binding.children[0]->parent;
		if (cdk2_pci_bus_stop(&instance->binding, parent, NULL, 0) != 0)
			return -1;
	}
	if (instance->unpublish(instance->context, instance) != 0)
		return -1;
	instance->published = 0;
	return 0;
}
