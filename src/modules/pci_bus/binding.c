/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_binding.h>

#include <string.h>

static int language_supported(const char *language)
{
	return language != NULL &&
		(strcmp(language, "eng") == 0 || strcmp(language, "en") == 0);
}

static int make_path(struct cdk2_pci_bus_binding *binding, const void *parent,
	size_t parent_size, const struct cdk2_pci_function *function,
	void **path, size_t *path_size)
{
	uint8_t *output;
	if (parent == NULL || parent_size < 4U || path == NULL || path_size == NULL ||
	    function->device >= 32U || function->function >= 8U ||
	    ((const uint8_t *)parent)[parent_size - 4U] != 0x7fU ||
	    ((const uint8_t *)parent)[parent_size - 2U] != 4U ||
	    ((const uint8_t *)parent)[parent_size - 1U] != 0U)
		return -1;
	if (parent_size > SIZE_MAX - 6U)
		return -1;
	output = binding->services.allocate(binding->services.context, parent_size + 6U);
	if (output == NULL)
		return -1;
	/* Replace the parent's end node with a PCI hardware node and a new end. */
	memcpy(output, parent, parent_size - 4U);
	output[parent_size - 4U] = 1U; output[parent_size - 3U] = 1U;
	output[parent_size - 2U] = 6U; output[parent_size - 1U] = 0U;
	output[parent_size] = function->function;
	output[parent_size + 1U] = function->device;
	output[parent_size + 2U] = 0x7fU; output[parent_size + 3U] = 0xffU;
	output[parent_size + 4U] = 4U; output[parent_size + 5U] = 0U;
	*path = output;
	*path_size = parent_size + 6U;
	return 0;
}

static int destroy_child(struct cdk2_pci_bus_binding *binding,
	struct cdk2_pci_bus_child *child)
{
	if (child->parent_open && binding->services.close_parent_by_child(
		binding->services.context, child->parent, child->handle) != 0)
		return -1;
	child->parent_open = 0;
	if (child->installed != 0U && binding->services.uninstall(
		binding->services.context, child->handle, child, child->installed) != 0) {
		if (binding->services.open_parent_by_child(binding->services.context,
			child->parent, child->handle) == 0)
			child->parent_open = 1;
		return -1;
	}
	child->installed = 0;
	if (child->device_path != NULL)
		binding->services.free(binding->services.context, child->device_path);
	child->device_path = NULL;
	binding->services.free(binding->services.context, child);
	return 0;
}

static int create_child(struct cdk2_pci_bus_binding *binding, void *parent,
	const void *parent_path, size_t parent_path_size,
	const struct cdk2_pci_function *function,
	struct cdk2_pci_bus_child **result)
{
	struct cdk2_pci_bus_child *child;
	unsigned int protocols = CDK2_PCI_CHILD_PCI_IO | CDK2_PCI_CHILD_DEVICE_PATH;
	child = binding->services.allocate(binding->services.context, sizeof(*child));
	if (child == NULL)
		return -1;
	memset(child, 0, sizeof(*child));
	child->parent = parent; child->function = *function;
	if (make_path(binding, parent_path, parent_path_size, function,
		&child->device_path, &child->device_path_size) != 0 ||
	    binding->services.initialize_io(binding->services.context, function,
		&child->io_model) != 0)
		goto rollback;
	child->io_model.rom_image = function->option_rom_shadow;
	child->io_model.rom_size = function->option_rom_shadow_size;
	cdk2_pci_io_initialize_protocol(&child->io, &child->io_model);
	if (function->option_rom_load_file)
		protocols |= CDK2_PCI_CHILD_LOAD_FILE;
	if (binding->services.install(binding->services.context, &child->handle,
		child, protocols) != 0)
		goto rollback;
	child->installed = protocols;
	if (binding->services.open_parent_by_child(binding->services.context, parent,
		child->handle) != 0)
		goto rollback;
	child->parent_open = 1;
	*result = child;
	return 0;
rollback:
	if (child->installed != 0U)
		(void)binding->services.uninstall(binding->services.context, child->handle,
			child, child->installed);
	if (child->device_path != NULL)
		binding->services.free(binding->services.context, child->device_path);
	binding->services.free(binding->services.context, child);
	return -1;
}

int cdk2_pci_bus_start(struct cdk2_pci_bus_binding *binding, void *parent,
	const void *parent_path, size_t parent_path_size,
	const struct cdk2_pci_topology *topology)
{
	size_t original_count;
	if (binding == NULL || parent == NULL || topology == NULL ||
	    binding->services.allocate == NULL || binding->services.free == NULL ||
	    binding->services.install == NULL || binding->services.uninstall == NULL ||
	    binding->services.open_parent_by_child == NULL ||
	    binding->services.close_parent_by_child == NULL ||
	    binding->services.initialize_io == NULL ||
	    topology->count > CDK2_PCI_MAX_FUNCTIONS - binding->child_count)
		return -1;
	original_count = binding->child_count;
	for (size_t i = 0; i < topology->count; i++) {
		struct cdk2_pci_bus_child *child;
		if (create_child(binding, parent, parent_path, parent_path_size,
			&topology->functions[i], &child) != 0)
			goto rollback;
		binding->children[binding->child_count++] = child;
	}
	return 0;
rollback:
	while (binding->child_count != original_count) {
		struct cdk2_pci_bus_child *child =
			binding->children[binding->child_count - 1U];
		if (destroy_child(binding, child) != 0)
			return -1;
		binding->child_count--;
	}
	return -1;
}

int cdk2_pci_bus_stop(struct cdk2_pci_bus_binding *binding, void *parent,
	void *const *child_handles, size_t requested_count)
{
	if (binding == NULL || parent == NULL ||
	    (requested_count != 0U && child_handles == NULL))
		return -1;
	for (size_t requested = 0; requested < requested_count; requested++) {
		int found = 0;
		for (size_t i = 0; i < binding->child_count; i++)
			if (binding->children[i]->parent == parent &&
			    binding->children[i]->handle == child_handles[requested])
				found = 1;
		if (!found)
			return -1;
	}
	for (size_t i = binding->child_count; i != 0U; i--) {
		struct cdk2_pci_bus_child *candidate = binding->children[i - 1U];
		int selected = requested_count == 0U;
		if (candidate->parent != parent)
			continue;
		for (size_t requested = 0; requested < requested_count; requested++)
			if (child_handles[requested] == candidate->handle)
				selected = 1;
		if (!selected)
			continue;
		if (destroy_child(binding, candidate) != 0)
			return -1;
		memmove(&binding->children[i - 1U], &binding->children[i],
			(binding->child_count - i) * sizeof(binding->children[0]));
		binding->child_count--;
	}
	return 0;
}

int cdk2_pci_bus_remove_bdf(struct cdk2_pci_bus_binding *binding, void *parent,
	uint8_t bus, uint8_t device, uint8_t function)
{
	for (size_t i = 0; binding != NULL && i < binding->child_count; i++) {
		struct cdk2_pci_bus_child *child = binding->children[i];
		if (child->parent == parent && child->function.bus == bus &&
		    child->function.device == device && child->function.function == function) {
			void *handle = child->handle;
			return cdk2_pci_bus_stop(binding, parent, &handle, 1);
		}
	}
	return -1;
}

int cdk2_pci_bus_component_name(const char *language, const char **name)
{
	if (!language_supported(language) || name == NULL)
		return -1;
	*name = "PCI Bus Driver";
	return 0;
}

int cdk2_pci_bus_controller_name(const struct cdk2_pci_bus_binding *binding,
	void *controller, void *child, const char *language, const char **name)
{
	if (binding == NULL || child == NULL || !language_supported(language) ||
	    name == NULL)
		return -1;
	for (size_t i = 0; i < binding->child_count; i++)
		if (binding->children[i]->parent == controller &&
		    binding->children[i]->handle == child) {
			*name = "PCI Device";
			return 0;
		}
	return -1;
}
