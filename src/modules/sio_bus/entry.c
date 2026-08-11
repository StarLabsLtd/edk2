/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/sio_bus_binding.h>

struct guid {
	UINT32 a;
	UINT16 b, c;
	UINT8 d[8];
};
static const struct guid driver_binding_guid = {
	0x18a031ab,
	0xb443,
	0x4d1a,
	{0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71}};
static const struct guid pci_io_guid = {
	0x4cf5b200,
	0x68b8,
	0x4ca5,
	{0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a}};
static const struct guid device_path_guid = {
	0x09576e91,
	0x6d3f,
	0x11d2,
	{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static const struct guid sio_guid = {
	0x215fdd18,
	0xbd50,
	0x4feb,
	{0x89, 0x0b, 0x58, 0xca, 0x0b, 0x47, 0x39, 0xe9}};
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const struct guid *,
						void **, void *, void *,
						UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const struct guid *,
						 void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, const struct guid *,
						   void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *,
						     const struct guid *,
						     void *, ...);
struct boot_services {
	UINT8 to_allocate_pool[64];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	UINT8 to_open_protocol[200];
	open_protocol_fn *open_protocol;
	close_protocol_fn *close_protocol;
	UINT8 to_install_multiple[32];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct system_table {
	UINT8 before_boot_services[96];
	struct boot_services *boot_services;
};
struct pci_access;
struct pci_io;
typedef EFI_STATUS CDK2_MS_ABI pci_read_fn(struct pci_io *, UINT32, UINT32,
					   UINTN, void *);
struct pci_access {
	pci_read_fn *read;
	void *write;
};
typedef EFI_STATUS CDK2_MS_ABI pci_location_fn(struct pci_io *, UINTN *,
					       UINTN *, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI pci_attributes_fn(struct pci_io *, UINT32,
						 UINT64, UINT64 *);
struct pci_io {
	void *poll_mem, *poll_io;
	struct pci_access mem, io, pci;
	void *copy_mem, *map, *unmap, *allocate_buffer, *free_buffer, *flush;
	pci_location_fn *get_location;
	pci_attributes_fn *attributes;
};
struct driver_binding;
typedef EFI_STATUS CDK2_MS_ABI supported_fn(struct driver_binding *, void *,
					    void *);
typedef EFI_STATUS CDK2_MS_ABI start_fn(struct driver_binding *, void *,
					void *);
typedef EFI_STATUS CDK2_MS_ABI stop_fn(struct driver_binding *, void *, UINTN,
				       void **);
struct driver_binding {
	supported_fn *supported;
	start_fn *start;
	stop_fn *stop;
	UINT32 version;
	void *image_handle;
	void *driver_binding_handle;
};
struct adapter {
	struct boot_services *bs;
	struct pci_io *pci;
	void *parent_path;
	void *image;
};
struct acpi_path {
	UINT8 type, subtype;
	UINT16 length;
	UINT32 hid, uid;
} __packed;

static struct cdk2_sio_binding bus;
static struct adapter adapter;

static EFI_STATUS open_pci(void *context, void *controller)
{
	struct adapter *a = context;
	return a->bs->open_protocol(controller, &pci_io_guid, (void **)&a->pci,
				    a->image, controller, 0x10U);
}
static EFI_STATUS close_pci(void *context, void *controller)
{
	struct adapter *a = context;
	a->pci = NULL;
	return a->bs->close_protocol(controller, &pci_io_guid, a->image,
				     controller);
}
static EFI_STATUS open_path(void *context, void *controller)
{
	struct adapter *a = context;
	return a->bs->open_protocol(controller, &device_path_guid,
				    &a->parent_path, a->image, controller,
				    0x10U);
}
static EFI_STATUS close_path(void *context, void *controller)
{
	struct adapter *a = context;
	a->parent_path = NULL;
	return a->bs->close_protocol(controller, &device_path_guid, a->image,
				     controller);
}
static EFI_STATUS get_info(void *context, void *controller,
			   struct cdk2_sio_pci_info *info)
{
	struct adapter *a = context;
	UINT8 pci[64] = {0};
	UINTN seg, bus_no, dev, function;
	EFI_STATUS status;
	(void)controller;
	if (a->pci == NULL || a->pci->pci.read == NULL ||
	    a->pci->get_location == NULL)
		return EFI_UNSUPPORTED;
	status = a->pci->pci.read(a->pci, 2U, 0U, 16U, pci);
	if (EFI_ERROR(status))
		return status;
	status = a->pci->get_location(a->pci, &seg, &bus_no, &dev, &function);
	if (EFI_ERROR(status))
		return status;
	info->vendor_id = (UINT16)(pci[0] | (UINT16)pci[1] << 8);
	info->command = (UINT16)(pci[4] | (UINT16)pci[5] << 8);
	info->sub_class = pci[0x0a];
	info->base_class = pci[0x0b];
	info->function = (UINT8)function;
	return EFI_SUCCESS;
}
static EFI_STATUS attributes(void *context, void *controller, UINT64 value,
			     UINT64 *result, UINT32 operation)
{
	struct adapter *a = context;
	(void)controller;
	return a->pci == NULL || a->pci->attributes == NULL
		       ? EFI_UNSUPPORTED
		       : a->pci->attributes(a->pci, operation, value, result);
}
static EFI_STATUS get_attributes(void *c, void *h, UINT64 v, UINT64 *r)
{
	return attributes(c, h, v, r, 0U);
}
static EFI_STATUS supported_attributes(void *c, void *h, UINT64 v, UINT64 *r)
{
	return attributes(c, h, v, r, 4U);
}
static EFI_STATUS enable_attributes(void *c, void *h, UINT64 v, UINT64 *r)
{
	return attributes(c, h, v, r, 2U);
}
static EFI_STATUS set_attributes(void *c, void *h, UINT64 v, UINT64 *r)
{
	return attributes(c, h, v, r, 1U);
}
static UINTN path_size(const UINT8 *path)
{
	UINTN size = 0, length;
	while (size < 0x10000U) {
		length = path[size + 2] | (UINTN)path[size + 3] << 8;
		if (length < 4U || size > 0x10000U - length)
			return 0;
		if (path[size] == 0x7fU && path[size + 1] == 0xffU)
			return size + length;
		size += length;
	}
	return 0;
}
static EFI_STATUS install_child(void *context, void *controller,
				struct cdk2_sio_child *child, UINTN index)
{
	struct adapter *a = context;
	UINTN parent_size, prefix, total, byte;
	UINT8 *path;
	struct acpi_path *node;
	EFI_STATUS status;
	(void)controller;
	parent_size = path_size(a->parent_path);
	if (parent_size < 4U)
		return EFI_UNSUPPORTED;
	prefix = parent_size - 4U;
	total = prefix + sizeof(*node) + 4U;
	status = a->bs->allocate_pool(4U, total, (void **)&path);
	if (EFI_ERROR(status))
		return status;
	for (byte = 0; byte < prefix; byte++)
		path[byte] = ((UINT8 *)a->parent_path)[byte];
	node = (struct acpi_path *)(path + prefix);
	*node = (struct acpi_path){2U, 1U, sizeof(*node),
				   cdk2_sio_devices[index].hid,
				   cdk2_sio_devices[index].uid};
	path[prefix + sizeof(*node)] = 0x7fU;
	path[prefix + sizeof(*node) + 1U] = 0xffU;
	path[prefix + sizeof(*node) + 2U] = 4U;
	path[prefix + sizeof(*node) + 3U] = 0U;
	child->device_path = path;
	child->handle = NULL;
	status =
		a->bs->install_multiple(&child->handle, &device_path_guid, path,
					&sio_guid, &child->protocol, NULL);
	if (EFI_ERROR(status)) {
		a->bs->free_pool(path);
		child->device_path = NULL;
	}
	return status;
}
static EFI_STATUS uninstall_child(void *context, void *controller,
				  struct cdk2_sio_child *child, UINTN index)
{
	struct adapter *a = context;
	EFI_STATUS status;
	(void)controller;
	(void)index;
	status = a->bs->uninstall_multiple(child->handle, &device_path_guid,
					   child->device_path, &sio_guid,
					   &child->protocol, NULL);
	if (!EFI_ERROR(status))
		a->bs->free_pool(child->device_path);
	return status;
}
static EFI_STATUS open_child(void *context, void *controller,
			     struct cdk2_sio_child *child, UINTN index)
{
	struct adapter *a = context;
	void *pci = NULL;
	(void)index;
	return a->bs->open_protocol(controller, &pci_io_guid, &pci, a->image,
				    child->handle, 0x08U);
}
static EFI_STATUS close_child(void *context, void *controller,
			      struct cdk2_sio_child *child, UINTN index)
{
	struct adapter *a = context;
	(void)index;
	return a->bs->close_protocol(controller, &pci_io_guid, a->image,
				     child->handle);
}
static const struct cdk2_sio_binding_ops ops = {open_pci,
						close_pci,
						open_path,
						close_path,
						get_info,
						get_attributes,
						supported_attributes,
						enable_attributes,
						set_attributes,
						install_child,
						uninstall_child,
						open_child,
						close_child};
static EFI_STATUS CDK2_MS_ABI supported(struct driver_binding *d, void *c,
					void *r)
{
	(void)d;
	(void)r;
	return cdk2_sio_binding_supported(&bus, c);
}
static EFI_STATUS CDK2_MS_ABI start(struct driver_binding *d, void *c, void *r)
{
	(void)d;
	(void)r;
	return cdk2_sio_binding_start(&bus, c);
}
static EFI_STATUS CDK2_MS_ABI stop(struct driver_binding *d, void *c, UINTN n,
				   void **h)
{
	(void)d;
	(void)c;
	return cdk2_sio_binding_stop(&bus, n, h);
}
static struct driver_binding binding = {supported, start, stop,
					0x10U,	   NULL,  NULL};

EFI_STATUS CDK2_MS_ABI cdk2_sio_bus_entry(void *image,
					  struct system_table *system)
{
	EFI_STATUS status;
	if (image == NULL || system == NULL || system->boot_services == NULL ||
	    system->boot_services->install_multiple == NULL)
		return EFI_INVALID_PARAMETER;
	adapter = (struct adapter){system->boot_services, NULL, NULL, image};
	bus = (struct cdk2_sio_binding){.ops = &ops, .context = &adapter};
	binding.image_handle = image;
	binding.driver_binding_handle = image;
	status = system->boot_services->install_multiple(
		&image, &driver_binding_guid, &binding, NULL);
	if (EFI_ERROR(status)) {
		binding.image_handle = NULL;
		binding.driver_binding_handle = NULL;
	}
	return status;
}
