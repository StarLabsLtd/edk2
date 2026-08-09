/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_binding.h>

#include <string.h>

static int string_equal(const char *left, const char *right)
{
	while (*left != 0 && *left == *right) {
		left++;
		right++;
	}
	return *left == *right;
}

static int language_supported(const char *language)
{
	return language != NULL &&
		(string_equal(language, "eng") || string_equal(language, "en"));
}

static CHAR16 driver_name[] = { 'P', 'C', 'I', ' ', 'B', 'u', 's', ' ',
	'D', 'r', 'i', 'v', 'e', 'r', 0 };
static CHAR16 controller_name[] = { 'P', 'C', 'I', ' ', 'D', 'e', 'v', 'i', 'c', 'e', 0 };
static CHAR8 english[] = "eng";
static CHAR8 english2[] = "en";

static int component_language(struct cdk2_component_name_instance *instance,
	const CHAR8 *language)
{
	return language != NULL && string_equal((const char *)language,
		instance->iso639 ? "eng" : "en");
}

static EFI_STATUS CDK2_MS_ABI get_driver_name(
	struct cdk2_component_name_protocol *protocol, cdk2_char8_pointer language,
	cdk2_char16_pointer_pointer name)
{
	struct cdk2_component_name_instance *instance =
		(struct cdk2_component_name_instance *)protocol;
	if (name == NULL || !component_language(instance, language))
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_component_name_protocol *protocol, void *controller, void *child,
	cdk2_char8_pointer language, cdk2_char16_pointer_pointer name)
{
	struct cdk2_component_name_instance *instance =
		(struct cdk2_component_name_instance *)protocol;
	if (name == NULL || child == NULL ||
	    !component_language(instance, language))
		return EFI_UNSUPPORTED;
	for (size_t i = 0; i < instance->binding->child_count; i++)
		if (instance->binding->children[i]->parent == controller &&
		    instance->binding->children[i]->handle == child) {
			*name = controller_name;
			return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED;
}

void cdk2_pci_bus_initialize_component_names(struct cdk2_pci_bus_binding *binding)
{
	binding->component_name = (struct cdk2_component_name_instance) {
		.protocol = { get_driver_name, get_controller_name, english },
		.binding = binding, .iso639 = 1 };
	binding->component_name2 = (struct cdk2_component_name_instance) {
		.protocol = { get_driver_name, get_controller_name, english2 },
		.binding = binding, .iso639 = 0 };
}

static EFI_STATUS CDK2_MS_ABI load_file2(
	struct cdk2_efi_load_file2_protocol *protocol, const void *path,
	BOOLEAN boot_policy,
	cdk2_uintn_pointer buffer_size, void *buffer)
{
	struct cdk2_pci_bus_child *child =
		((struct cdk2_pci_load_file_instance *)protocol)->child;
	size_t native_size;
	int call_status;
	const uint8_t *bytes = path;
	if (child == NULL || path == NULL || buffer_size == NULL || boot_policy ||
	    bytes[2] != 24U || bytes[3] != 0U || bytes[24] != 0x7fU ||
	    bytes[26] != 4U || bytes[27] != 0U)
		return EFI_INVALID_PARAMETER;
	native_size = *buffer_size;
	call_status = cdk2_pci_option_rom_load_file_path(&child->function, path, 24,
		0, buffer, &native_size);
	*buffer_size = native_size;
	return call_status == 0 ? EFI_SUCCESS :
		(call_status == 1 ? EFI_BUFFER_TOO_SMALL : EFI_NOT_FOUND);
}

static int make_path(struct cdk2_pci_bus_binding *binding, const void *parent,
	size_t parent_size, const struct cdk2_pci_topology *topology, size_t index,
	void **path, size_t *path_size)
{
	uint8_t *output;
	uint16_t chain[CDK2_PCI_MAX_FUNCTIONS];
	size_t depth = 0, cursor;
	const struct cdk2_pci_function *function;
	if (topology == NULL || index >= topology->count)
		return -1;
	function = &topology->functions[index];
	if (parent == NULL || parent_size < 4U || path == NULL || path_size == NULL ||
	    function->device >= 32U || function->function >= 8U ||
	    ((const uint8_t *)parent)[parent_size - 4U] != 0x7fU ||
	    ((const uint8_t *)parent)[parent_size - 2U] != 4U ||
	    ((const uint8_t *)parent)[parent_size - 1U] != 0U)
		return -1;
	while (index != CDK2_PCI_ROOT_PARENT) {
		if (index >= topology->count || depth == CDK2_PCI_MAX_FUNCTIONS)
			return -1;
		if (topology->functions[index].device >= 32U ||
		    topology->functions[index].function >= 8U)
			return -1;
		chain[depth++] = (uint16_t)index;
		index = topology->functions[index].parent_index;
	}
	if (depth > (SIZE_MAX - parent_size) / 6U)
		return -1;
	*path_size = parent_size + depth * 6U;
	output = binding->services.allocate(binding->services.context, *path_size);
	if (output == NULL)
		return -1;
	/* Replace the parent's end node with a PCI hardware node and a new end. */
	memcpy(output, parent, parent_size - 4U);
	cursor = parent_size - 4U;
	while (depth != 0U) {
		function = &topology->functions[chain[--depth]];
		output[cursor] = 1U; output[cursor + 1U] = 1U;
		output[cursor + 2U] = 6U; output[cursor + 3U] = 0U;
		output[cursor + 4U] = function->function;
		output[cursor + 5U] = function->device;
		cursor += 6U;
	}
	output[cursor] = 0x7fU; output[cursor + 1U] = 0xffU;
	output[cursor + 2U] = 4U; output[cursor + 3U] = 0U;
	*path = output;
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
	if (binding->services.release_function != NULL)
		binding->services.release_function(binding->services.context,
			&child->function);
	if (child->device_path != NULL)
		binding->services.free(binding->services.context, child->device_path);
	child->device_path = NULL;
	binding->services.free(binding->services.context, child);
	return 0;
}

static int create_child(struct cdk2_pci_bus_binding *binding, void *parent,
	const void *parent_path, size_t parent_path_size,
	const struct cdk2_pci_topology *topology, size_t index,
	struct cdk2_pci_bus_child **result)
{
	const struct cdk2_pci_function *function = &topology->functions[index];
	struct cdk2_pci_bus_child *child;
	unsigned int protocols = CDK2_PCI_CHILD_PCI_IO | CDK2_PCI_CHILD_DEVICE_PATH;
	child = binding->services.allocate(binding->services.context, sizeof(*child));
	if (child == NULL)
		return -1;
	memset(child, 0, sizeof(*child));
	child->parent = parent; child->function = *function;
	if (make_path(binding, parent_path, parent_path_size, topology, index,
		&child->device_path, &child->device_path_size) != 0 ||
	    binding->services.initialize_io(binding->services.context, function,
		&child->io_model) != 0)
		goto rollback;
	child->io_model.rom_image = function->option_rom_shadow;
	child->io_model.rom_size = function->option_rom_shadow_size;
	cdk2_pci_io_initialize_protocol(&child->io, &child->io_model);
	if (function->option_rom_load_file) {
		protocols |= CDK2_PCI_CHILD_LOAD_FILE;
		child->load_file.protocol.load_file = load_file2;
		child->load_file.child = child;
	}
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
	if (binding->services.release_function != NULL)
		binding->services.release_function(binding->services.context,
			&child->function);
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
			topology, i, &child) != 0)
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

static int topology_has_bdf(const struct cdk2_pci_topology *topology,
	const struct cdk2_pci_function *function)
{
	for (size_t i = 0; topology != NULL && i < topology->count; i++)
		if (topology->functions[i].bus == function->bus &&
		    topology->functions[i].device == function->device &&
		    topology->functions[i].function == function->function)
			return 1;
	return 0;
}

int cdk2_pci_bus_start_new(struct cdk2_pci_bus_binding *binding, void *parent,
	const void *parent_path, size_t parent_path_size,
	const struct cdk2_pci_topology *retained,
	const struct cdk2_pci_topology *discovered, void **handles,
	size_t *handle_count)
{
	size_t original_count, output_count = 0;
	if (binding == NULL || parent == NULL || retained == NULL ||
	    discovered == NULL || handle_count == NULL ||
	    (handles == NULL && discovered->count != retained->count) ||
	    binding->services.allocate == NULL || binding->services.free == NULL ||
	    binding->services.install == NULL || binding->services.uninstall == NULL ||
	    binding->services.open_parent_by_child == NULL ||
	    binding->services.close_parent_by_child == NULL ||
	    binding->services.initialize_io == NULL)
		return -1;
	original_count = binding->child_count;
	for (size_t i = 0; i < discovered->count; i++) {
		struct cdk2_pci_bus_child *child;
		if (topology_has_bdf(retained, &discovered->functions[i]))
			continue;
		if (binding->child_count == CDK2_PCI_MAX_FUNCTIONS ||
		    create_child(binding, parent, parent_path, parent_path_size,
			discovered, i, &child) != 0)
			goto rollback;
		binding->children[binding->child_count++] = child;
		handles[output_count++] = child->handle;
	}
	*handle_count = output_count;
	return 0;
rollback:
	while (binding->child_count != original_count) {
		struct cdk2_pci_bus_child *child =
			binding->children[binding->child_count - 1U];
		if (destroy_child(binding, child) != 0)
			return -1;
		binding->child_count--;
	}
	*handle_count = 0;
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
