/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/pci_bus_binding.h>

#include <stddef.h>
#include <string.h>

typedef EFI_STATUS CDK2_MS_ABI pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const EFI_GUID *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const EFI_GUID *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI image_unload_fn(void *);
struct root_io_protocol;
typedef EFI_STATUS CDK2_MS_ABI root_access_fn(struct root_io_protocol *, UINTN,
	UINT64, UINTN, void *);
typedef EFI_STATUS CDK2_MS_ABI root_configuration_fn(struct root_io_protocol *,
	void **);
typedef EFI_STATUS CDK2_MS_ABI root_poll_fn(struct root_io_protocol *, UINTN,
	UINT64, UINT64, UINT64, UINT64, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI root_copy_fn(struct root_io_protocol *, UINTN,
	UINT64, UINT64, UINTN);
typedef EFI_STATUS CDK2_MS_ABI root_map_fn(struct root_io_protocol *, UINTN,
	void *, UINTN *, UINT64 *, void **);
typedef EFI_STATUS CDK2_MS_ABI root_unmap_fn(struct root_io_protocol *, void *);
typedef EFI_STATUS CDK2_MS_ABI root_allocate_fn(struct root_io_protocol *, UINT32,
	UINT32, UINTN, void **, UINT64);
typedef EFI_STATUS CDK2_MS_ABI root_free_fn(struct root_io_protocol *, UINTN,
	void *);
typedef EFI_STATUS CDK2_MS_ABI root_flush_fn(struct root_io_protocol *);
typedef EFI_STATUS CDK2_MS_ABI root_get_attributes_fn(struct root_io_protocol *,
	UINT64 *, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI root_set_attributes_fn(struct root_io_protocol *,
	UINT64, UINT64 *, UINT64 *);
struct root_io_protocol {
	void *parent; root_poll_fn *poll_mem, *poll_io;
	struct { root_access_fn *read, *write; } mem, io, pci;
	root_copy_fn *copy_mem; root_map_fn *map; root_unmap_fn *unmap;
	root_allocate_fn *allocate_buffer; root_free_fn *free_buffer;
	root_flush_fn *flush; root_get_attributes_fn *get_attributes;
	root_set_attributes_fn *set_attributes;
	root_configuration_fn *configuration;
	UINT32 segment;
};

struct boot_services_view {
	UINT8 before_pool[64]; pool_fn *allocate_pool; free_fn *free_pool;
	UINT8 before_handle[72]; handle_fn *handle_protocol;
	UINT8 before_open[120]; open_fn *open_protocol; close_fn *close_protocol;
	UINT8 before_install[32]; install_fn *install_multiple;
	uninstall_fn *uninstall_multiple;
};
typedef char pool_offset_check[offsetof(struct boot_services_view,
	allocate_pool) == 64 ? 1 : -1];
typedef char handle_offset_check[offsetof(struct boot_services_view,
	handle_protocol) == 152 ? 1 : -1];
typedef char open_offset_check[offsetof(struct boot_services_view,
	open_protocol) == 280 ? 1 : -1];
typedef char install_offset_check[offsetof(struct boot_services_view,
	install_multiple) == 328 ? 1 : -1];

struct system_table_view {
	UINT8 header[24]; CHAR16 *vendor; UINT32 revision, pad;
	void *console[6], *runtime; struct boot_services_view *boot;
};
struct loaded_image_protocol {
	UINT32 revision; void *parent, *system, *device, *file_path, *reserved;
	UINT32 load_options_size; void *load_options, *image_base;
	UINT64 image_size; UINT32 code_type, data_type; image_unload_fn *unload;
};

static const EFI_GUID root_io_guid = { 0x2f707ebb, 0x4a1a, 0x11d4,
	{ 0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID pci_io_guid = { 0x4cf5b200, 0x68b8, 0x4ca5,
	{ 0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a } };
static const EFI_GUID device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID load_file2_guid = { 0x4006c0c1, 0xfcb3, 0x403e,
	{ 0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d } };
static const EFI_GUID driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const EFI_GUID component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const EFI_GUID loaded_image_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };

struct entry_context {
	struct cdk2_pci_bus_driver driver;
	struct boot_services_view *boot;
	void *image;
	struct loaded_image_protocol *loaded;
	image_unload_fn *original_unload;
	struct {
		void *controller;
		struct root_io_protocol *root;
		UINT8 committed;
	} roots[CDK2_PCI_MAX_ROOTS];
	UINTN building_root;
};
static struct entry_context context;

static void *allocate(void *opaque, size_t size)
{
	struct entry_context *entry = opaque; void *buffer = NULL;
	return EFI_ERROR(entry->boot->allocate_pool(4U, size, &buffer)) ? NULL : buffer;
}
static void release(void *opaque, void *buffer)
{ (void)((struct entry_context *)opaque)->boot->free_pool(buffer); }

static int cfg_read(void *opaque, uint8_t bus, uint8_t device, uint8_t function,
	uint16_t offset, uint8_t width, uint32_t *value)
{
	struct entry_context *entry = opaque;
	UINT64 address = ((UINT64)bus << 24) | ((UINT64)device << 16) |
		((UINT64)function << 8) | offset;
	struct root_io_protocol *root = entry->roots[entry->building_root].root;
	return EFI_ERROR(root->pci.read(root, width,
		address, 1, value)) ? -1 : 0;
}
static int cfg_write(void *opaque, uint8_t bus, uint8_t device, uint8_t function,
	uint16_t offset, uint8_t width, uint32_t value)
{
	struct entry_context *entry = opaque;
	UINT64 address = ((UINT64)bus << 24) | ((UINT64)device << 16) |
		((UINT64)function << 8) | offset;
	struct root_io_protocol *root = entry->roots[entry->building_root].root;
	return EFI_ERROR(root->pci.write(root, width,
		address, 1, &value)) ? -1 : 0;
}

static int probe(void *opaque, void *controller, void *remaining)
{
	struct entry_context *entry = opaque; void *interface = NULL; EFI_STATUS status;
	(void)remaining;
	status = entry->boot->open_protocol(controller, &root_io_guid, &interface,
		entry->image, controller, 0x10U);
	if (!EFI_ERROR(status))
		(void)entry->boot->close_protocol(controller, &root_io_guid,
			entry->image, controller);
	return EFI_ERROR(status) ? -1 : 0;
}

static int discover(void *opaque, void *controller, void *remaining,
	struct cdk2_pci_topology *topology, void **path, size_t *path_size)
{
	struct entry_context *entry = opaque; struct root_io_protocol *root = NULL;
	struct cdk2_pci_cfg cfg = { .context = entry, .crs_retries = 100,
		.read = cfg_read, .write = cfg_write };
	UINT8 *node, *resources; size_t length = 0; EFI_STATUS status;
	UINT8 first_bus = 0, last_bus = 0xff; int found_bus = 0;
	(void)remaining;
	for (entry->building_root = 0; entry->building_root < CDK2_PCI_MAX_ROOTS;
	     entry->building_root++)
		if (entry->roots[entry->building_root].controller == NULL)
			break;
	if (entry->building_root == CDK2_PCI_MAX_ROOTS)
		return -1;
	status = entry->boot->open_protocol(controller, &root_io_guid, (void **)&root,
		entry->image, controller, 0x10U);
	if (EFI_ERROR(status) || root == NULL || root->segment != 0U)
		return -1;
	entry->roots[entry->building_root].root = root;
	entry->roots[entry->building_root].controller = controller;
	status = entry->boot->handle_protocol(controller, &device_path_guid,
		(void **)&node);
	if (EFI_ERROR(status) || node == NULL)
		goto fail;
	while (length <= 4096U) {
		size_t node_size = (size_t)node[length + 2U] |
			((size_t)node[length + 3U] << 8);
		if (node_size < 4U || length > 4096U - node_size)
			goto fail;
		length += node_size;
		if (node[length - node_size] == 0x7fU)
			break;
	}
	if (length > 4096U || root->configuration == NULL ||
	    EFI_ERROR(root->configuration(root, (void **)&resources)) ||
	    resources == NULL)
		goto fail;
	for (size_t offset = 0; offset < 4096U && resources[offset] != 0x79U;) {
		size_t descriptor_size;
		if (resources[offset] == 0x8aU && resources[offset + 3U] == 2U &&
		    resources[offset + 1U] == 43U && resources[offset + 2U] == 0U) {
			memcpy(&first_bus, resources + offset + 14U, 1);
			memcpy(&last_bus, resources + offset + 22U, 1);
			found_bus = 1;
		}
		descriptor_size = (resources[offset] & 0x80U) != 0U ?
			(size_t)resources[offset + 1U] +
			((size_t)resources[offset + 2U] << 8) + 3U :
			(size_t)(resources[offset] & 7U) + 1U;
		if (descriptor_size == 0U || offset > 4096U - descriptor_size)
			goto fail;
		offset += descriptor_size;
	}
	if (!found_bus || first_bus > last_bus ||
	    cdk2_pci_enumerate(&cfg, first_bus, last_bus, topology) != 0)
		goto fail;
	*path = allocate(entry, length);
	if (*path == NULL)
		goto fail;
	memcpy(*path, node, length); *path_size = length;
	return 0;
fail:
	(void)entry->boot->close_protocol(controller, &root_io_guid,
		entry->image, controller);
	memset(&entry->roots[entry->building_root], 0,
		sizeof(entry->roots[entry->building_root]));
	return -1;
}
static void release_discovery(void *opaque, void *path)
{ release(opaque, path); }

static void finish_discovery(void *opaque, void *controller, int success)
{
	struct entry_context *entry = opaque;
	for (UINTN index = 0; index < CDK2_PCI_MAX_ROOTS; index++)
		if (entry->roots[index].controller == controller &&
		    !entry->roots[index].committed) {
			if (success)
				entry->roots[index].committed = 1;
			else {
				(void)entry->boot->close_protocol(controller, &root_io_guid,
					entry->image, controller);
				memset(&entry->roots[index], 0, sizeof(entry->roots[index]));
			}
			return;
		}
}

static void finish_stop(void *opaque, void *controller, int success)
{
	struct entry_context *entry = opaque;
	if (!success)
		return;
	for (UINTN child = 0; child < entry->driver.binding.child_count; child++)
		if (entry->driver.binding.children[child]->parent == controller)
			return;
	for (UINTN index = 0; index < CDK2_PCI_MAX_ROOTS; index++)
		if (entry->roots[index].controller == controller) {
			if (!EFI_ERROR(entry->boot->close_protocol(controller,
				&root_io_guid, entry->image, controller)))
				memset(&entry->roots[index], 0, sizeof(entry->roots[index]));
			return;
		}
}

static int install_child(void *opaque, void **handle,
	struct cdk2_pci_bus_child *child, unsigned int protocols)
{
	struct entry_context *entry = opaque; EFI_STATUS status;
	if ((protocols & CDK2_PCI_CHILD_LOAD_FILE) != 0U)
		status = entry->boot->install_multiple(handle,
			&device_path_guid, child->device_path, &pci_io_guid,
			&child->io.protocol, &load_file2_guid, &child->load_file.protocol, NULL);
	else
		status = entry->boot->install_multiple(handle,
			&device_path_guid, child->device_path, &pci_io_guid,
			&child->io.protocol, NULL);
	return EFI_ERROR(status) ? -1 : 0;
}
static int uninstall_child(void *opaque, void *handle,
	struct cdk2_pci_bus_child *child, unsigned int protocols)
{
	struct entry_context *entry = opaque; EFI_STATUS status;
	if ((protocols & CDK2_PCI_CHILD_LOAD_FILE) != 0U)
		status = entry->boot->uninstall_multiple(handle,
			&device_path_guid, child->device_path, &pci_io_guid,
			&child->io.protocol, &load_file2_guid, &child->load_file.protocol, NULL);
	else
		status = entry->boot->uninstall_multiple(handle,
			&device_path_guid, child->device_path, &pci_io_guid,
			&child->io.protocol, NULL);
	return EFI_ERROR(status) ? -1 : 0;
}
static int child_open(void *opaque, void *parent, void *child)
{
	struct entry_context *entry = opaque; void *interface = NULL;
	return EFI_ERROR(entry->boot->open_protocol(parent, &root_io_guid, &interface,
		entry->image, child, 0x08U)) ? -1 : 0;
}
static int child_close(void *opaque, void *parent, void *child)
{
	struct entry_context *entry = opaque;
	return EFI_ERROR(entry->boot->close_protocol(parent, &root_io_guid,
		entry->image, child)) ? -1 : 0;
}

static struct cdk2_pci_bus_child *io_child(void *opaque)
{ return opaque; }
static int root_access(void *opaque, enum cdk2_pci_io_space space, int write,
	unsigned int width, uint64_t address, size_t count, void *buffer)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	struct root_io_protocol *root = child->root_io;
	root_access_fn *function;
	if (space == CDK2_PCI_IO_CONFIG) {
		address |= ((UINT64)child->function.bus << 24) |
			((UINT64)child->function.device << 16) |
			((UINT64)child->function.function << 8);
		function = write ? root->pci.write : root->pci.read;
	} else if (space == CDK2_PCI_IO_PORT)
		function = write ? root->io.write : root->io.read;
	else
		function = write ? root->mem.write : root->mem.read;
	child->io_status = function(root, width, address, count, buffer);
	return EFI_ERROR(child->io_status) ? -1 : 0;
}
static int root_delay(void *opaque, uint64_t ticks)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	struct entry_context *entry = child->entry_context;
	typedef EFI_STATUS CDK2_MS_ABI stall_fn(UINTN);
	stall_fn **stall = (stall_fn **)((UINT8 *)entry->boot + 248U);
	child->io_status = *stall == NULL ? EFI_UNSUPPORTED : (*stall)(ticks);
	return EFI_ERROR(child->io_status) ? -1 : 0;
}
static int root_map(void *opaque, unsigned int operation, void *host,
	size_t *size, uint64_t *device, void **mapping)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	UINTN native_size = *size; UINT64 native_device;
	child->io_status = ((struct root_io_protocol *)child->root_io)->map(
		child->root_io, operation, host, &native_size, &native_device, mapping);
	*size = native_size; *device = native_device;
	return EFI_ERROR(child->io_status) ? -1 : 0;
}
static int root_unmap(void *opaque, void *mapping)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	child->io_status = ((struct root_io_protocol *)child->root_io)->unmap(
		child->root_io, mapping);
	return EFI_ERROR(child->io_status) ? -1 : 0;
}
static void *root_allocate(void *opaque, size_t pages, int below_4g)
{
	struct cdk2_pci_bus_child *child = io_child(opaque); void *buffer = NULL;
	child->io_status = ((struct root_io_protocol *)child->root_io)->allocate_buffer(
		child->root_io, 0U, 4U, pages, &buffer, below_4g ? 0U : 0x8000U);
	return EFI_ERROR(child->io_status) ? NULL : buffer;
}
static int root_free(void *opaque, size_t pages, void *buffer)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	child->io_status = ((struct root_io_protocol *)child->root_io)->free_buffer(
		child->root_io, pages, buffer);
	return EFI_ERROR(child->io_status) ? -1 : 0;
}
static int root_flush(void *opaque)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	child->io_status = ((struct root_io_protocol *)child->root_io)->flush(
		child->root_io);
	return EFI_ERROR(child->io_status) ? -1 : 0;
}
static void *root_pool(void *opaque, size_t size)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	return allocate(child->entry_context, size);
}
static int root_set_bar_attributes(void *opaque, unsigned int bar,
	uint64_t offset, uint64_t length, uint64_t attributes)
{
	struct cdk2_pci_bus_child *child = io_child(opaque);
	struct root_io_protocol *root = child->root_io;
	UINT64 base, native_length = length;
	if (bar >= 6U || offset > child->io_model.bar_size[bar] ||
	    length > child->io_model.bar_size[bar] - offset ||
	    child->io_model.bar_base[bar] > UINT64_MAX - offset ||
	    root->set_attributes == NULL)
		return -1;
	base = child->io_model.bar_base[bar] + offset;
	child->io_status = root->set_attributes(root, attributes, &base,
		&native_length);
	return EFI_ERROR(child->io_status) ? -1 : 0;
}
static uint64_t root_status(void *opaque)
{ return io_child(opaque)->io_status; }
static int initialize_io(void *opaque, const struct cdk2_pci_function *function,
	struct cdk2_pci_io_model *io)
{
	struct entry_context *entry = opaque;
	struct cdk2_pci_bus_child *child = (struct cdk2_pci_bus_child *)
		((UINT8 *)io - offsetof(struct cdk2_pci_bus_child, io_model));
	struct root_io_protocol *root = entry->roots[entry->building_root].root;
	if (root == NULL || root->mem.read == NULL || root->mem.write == NULL ||
	    root->io.read == NULL || root->io.write == NULL || root->pci.read == NULL ||
	    root->pci.write == NULL || root->map == NULL || root->unmap == NULL ||
	    root->allocate_buffer == NULL || root->free_buffer == NULL ||
	    root->flush == NULL)
		return -1;
	child->root_io = root; child->entry_context = entry;
	io->segment = 0; io->bus = function->bus; io->device = function->device;
	io->function = function->function;
	io->backend = (struct cdk2_pci_io_backend) {
		.context = child, .access = root_access, .delay = root_delay,
		.map = root_map, .unmap = root_unmap, .allocate = root_allocate,
		.free = root_free, .flush = root_flush, .allocate_pool = root_pool,
		.set_bar_attributes = root_set_bar_attributes, .status = root_status };
	for (UINTN bar = 0; bar < function->bar_count && bar < 6U; bar++) {
		io->bar_base[bar] = function->bars[bar].base;
		io->bar_size[bar] = function->bars[bar].size;
		io->bar_space[bar] = function->bars[bar].kind == CDK2_PCI_BAR_IO ?
			CDK2_PCI_IO_PORT : CDK2_PCI_IO_MEM;
	}
	io->supported_attributes = 0x100U | 0x200U | 0x400U | 0x8000U;
	return 0;
}

static int publish(void *opaque, struct cdk2_pci_bus_driver *driver)
{
	struct entry_context *entry = opaque; void *handle = NULL;
	EFI_STATUS status = entry->boot->install_multiple(&handle,
		&driver_binding_guid, &driver->protocol,
		&component_name_guid, &driver->binding.component_name.protocol,
		&component_name2_guid, &driver->binding.component_name2.protocol, NULL);
	if (!EFI_ERROR(status))
		driver->protocol.driver_binding_handle = handle;
	return EFI_ERROR(status) ? -1 : 0;
}
static int unpublish(void *opaque, struct cdk2_pci_bus_driver *driver)
{
	struct entry_context *entry = opaque;
	return EFI_ERROR(entry->boot->uninstall_multiple(
		driver->protocol.driver_binding_handle,
		&driver_binding_guid, &driver->protocol,
		&component_name_guid, &driver->binding.component_name.protocol,
		&component_name2_guid, &driver->binding.component_name2.protocol, NULL)) ? -1 : 0;
}

EFI_STATUS CDK2_MS_ABI cdk2_pci_bus_unload(void *image)
{
	if (image != context.image || !context.driver.published)
		return EFI_INVALID_PARAMETER;
	if (cdk2_pci_bus_driver_unload(&context.driver) != 0)
		return EFI_DEVICE_ERROR;
	if (context.loaded != NULL)
		context.loaded->unload = context.original_unload;
	memset(&context, 0, sizeof(context));
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_pci_bus_entry(void *image, void *system_table)
{
	struct system_table_view *system = system_table; EFI_STATUS status;
	if (image == NULL || system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	if (context.driver.published)
		return EFI_ALREADY_STARTED;
	memset(&context, 0, sizeof(context));
	context.boot = system->boot; context.image = image;
	if (context.boot->allocate_pool == NULL || context.boot->free_pool == NULL ||
	    context.boot->handle_protocol == NULL || context.boot->open_protocol == NULL ||
	    context.boot->close_protocol == NULL || context.boot->install_multiple == NULL ||
	    context.boot->uninstall_multiple == NULL)
		return EFI_UNSUPPORTED;
	context.driver = (struct cdk2_pci_bus_driver) {
		.context = &context, .probe = probe, .discover = discover,
		.release_discovery = release_discovery, .publish = publish,
		.finish_discovery = finish_discovery, .finish_stop = finish_stop,
		.unpublish = unpublish,
		.binding.services = { .context = &context, .allocate = allocate,
			.free = release, .install = install_child,
			.uninstall = uninstall_child, .open_parent_by_child = child_open,
			.close_parent_by_child = child_close, .initialize_io = initialize_io } };
	if (!EFI_ERROR(context.boot->handle_protocol(image, &loaded_image_guid,
		(void **)&context.loaded)) && context.loaded != NULL) {
		context.original_unload = context.loaded->unload;
		context.loaded->unload = cdk2_pci_bus_unload;
	}
	if (cdk2_pci_bus_driver_entry(&context.driver, image) != 0) {
		if (context.loaded != NULL)
			context.loaded->unload = context.original_unload;
		status = EFI_DEVICE_ERROR; memset(&context, 0, sizeof(context));
		return status;
	}
	return EFI_SUCCESS;
}
