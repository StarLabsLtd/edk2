/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_output_driver.h>
#include <pi/hob.h>

#include <string.h>

#define GOP_ALREADY_STARTED ((1ULL << 63) | 20ULL)

typedef uint64_t CDK2_MS_ABI pci_rw_fn(void *, uint32_t, uint8_t, uint64_t,
				       size_t, void *);
struct pci_access {
	pci_rw_fn *read, *write;
};
typedef uint64_t CDK2_MS_ABI pci_bar_fn(void *, uint8_t, uint64_t *, void **);
struct pci_view {
	void *poll_mem, *poll_io;
	struct pci_access mem, io, pci;
	void *copy_mem, *map, *unmap, *allocate, *free, *flush, *get_location,
		*attributes;
	pci_bar_fn *get_bar_attributes;
};

typedef uint64_t CDK2_MS_ABI allocate_pool_fn(uint32_t, size_t, void **);
typedef uint64_t CDK2_MS_ABI free_pool_fn(void *);
struct boot_view {
	uint8_t before_allocate[64];
	allocate_pool_fn *allocate;
	free_pool_fn *free;
	uint8_t before_close_event[32];
	cdk2_graphics_close_event_fn *close_event;
	uint8_t before_open[160];
	cdk2_graphics_open_fn *open;
	cdk2_graphics_close_fn *close;
	uint8_t before_install[32];
	cdk2_graphics_install_fn *install;
	cdk2_graphics_uninstall_fn *uninstall;
	uint8_t before_create_event_ex[24];
	cdk2_graphics_event_fn *create_event_ex;
};
struct configuration {
	EFI_GUID guid;
	void *table;
};
struct system_view {
	uint8_t header[24];
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6], *runtime;
	struct boot_view *boot;
	size_t table_count;
	struct configuration *tables;
};

struct binding;
typedef uint64_t CDK2_MS_ABI supported_fn(struct binding *, void *, void *);
typedef uint64_t CDK2_MS_ABI stop_fn(struct binding *, void *, size_t, void **);
struct binding {
	supported_fn *supported, *start;
	stop_fn *stop;
	uint32_t version, pad;
	void *image, *handle;
};

static const EFI_GUID binding_guid = {
	0x18a031ab,
	0xb443,
	0x4d1a,
	{0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71}};
static const EFI_GUID hob_list_guid = {
	0x7739f24c,
	0x93d7,
	0x11d4,
	{0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}};
static const EFI_GUID graphics_hob_guid = {
	0x39f62cce,
	0x6825,
	0x4669,
	{0xbb, 0x56, 0x54, 0x1a, 0xba, 0x75, 0x3a, 0x07}};

static struct cdk2_graphics_services services;
static struct cdk2_graphics_child child;
static EFI_PEI_GRAPHICS_INFO_HOB *graphics_hob;
static struct binding driver_binding;
static struct boot_view *boot;

static void *CDK2_MS_ABI allocate(size_t size)
{
	void *buffer = NULL;
	return boot->allocate(4, size, &buffer) == EFI_SUCCESS ? buffer : NULL;
}

static void CDK2_MS_ABI release(void *buffer)
{
	(void)boot->free(buffer);
}

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static uint64_t CDK2_MS_ABI pci_info(void *interface,
				     struct cdk2_graphics_pci_info *info)
{
	struct pci_view *pci = interface;
	uint8_t config[64];
	uint8_t bar;
	if (pci == NULL || info == NULL || pci->pci.read == NULL ||
	    pci->pci.read(pci, 2, 0, 0, sizeof(config) / 4, config) !=
		    EFI_SUCCESS)
		return EFI_DEVICE_ERROR;
	info->vendor_id = config[0] | (uint16_t)config[1] << 8;
	info->device_id = config[2] | (uint16_t)config[3] << 8;
	info->revision_id = config[8];
	info->subsystem_vendor_id = config[44] | (uint16_t)config[45] << 8;
	info->subsystem_id = config[46] | (uint16_t)config[47] << 8;
	for (bar = 0; bar < 6; bar++) {
		uint64_t attributes;
		uint8_t *resource = NULL;
		uint64_t base, length;
		if (pci->get_bar_attributes(pci, bar, &attributes,
					    (void **)&resource) !=
			    EFI_SUCCESS ||
		    resource == NULL)
			continue;
		memcpy(&base, resource + 14, sizeof(base));
		memcpy(&length, resource + 38, sizeof(length));
		(void)boot->free(resource);
		if (graphics_hob->frame_buffer_base >= base && length != 0 &&
		    graphics_hob->frame_buffer_base - base < length) {
			info->bar_index = bar;
			info->bar_base = base;
			info->bar_size = length;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_FOUND;
}

static uint64_t CDK2_MS_ABI supported(struct binding *self, void *controller,
				      void *remaining)
{
	(void)remaining;
	return cdk2_graphics_supported(&services, self->handle, controller,
				       NULL);
}
static uint64_t CDK2_MS_ABI start(struct binding *self, void *controller,
				  void *remaining)
{
	(void)remaining;
	if (child.started)
		return GOP_ALREADY_STARTED;
	return cdk2_graphics_start(&child, &services, self->handle, controller,
				   graphics_hob, NULL);
}
static uint64_t CDK2_MS_ABI stop(struct binding *self, void *controller,
				 size_t count, void **handles)
{
	(void)self;
	(void)controller;
	if (count != 0 && (handles == NULL || handles[0] != child.handle))
		return EFI_NOT_FOUND;
	return cdk2_graphics_stop(&child);
}

static EFI_PEI_GRAPHICS_INFO_HOB *find_graphics_hob(struct system_view *system)
{
	size_t index;
	for (index = 0; index < system->table_count; index++)
		if (guid_equal(&system->tables[index].guid, &hob_list_guid)) {
			uint8_t *hob = system->tables[index].table;
			for (;;) {
				EFI_HOB_GENERIC_HEADER *header = (void *)hob;
				if (header->hob_type ==
					    EFI_HOB_TYPE_END_OF_HOB_LIST ||
				    header->hob_length < sizeof(*header))
					break;
				if (header->hob_type ==
					    EFI_HOB_TYPE_GUID_EXTENSION &&
				    header->hob_length >=
					    sizeof(*header) + sizeof(EFI_GUID) +
						    sizeof(EFI_PEI_GRAPHICS_INFO_HOB) &&
				    guid_equal(
					    (EFI_GUID *)(hob + sizeof(*header)),
					    &graphics_hob_guid))
					return (void *)(hob + sizeof(*header) +
							sizeof(EFI_GUID));
				hob += header->hob_length;
			}
		}
	return NULL;
}

uint64_t CDK2_MS_ABI cdk2_graphics_output_entry(void *image_handle,
						void *system_table)
{
	struct system_view *system = system_table;
	if (system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	boot = system->boot;
	graphics_hob = find_graphics_hob(system);
	if (graphics_hob == NULL)
		return EFI_NOT_FOUND;
	services = (struct cdk2_graphics_services){boot->open,
						   boot->close,
						   boot->install,
						   boot->uninstall,
						   boot->create_event_ex,
						   boot->close_event,
						   pci_info,
						   allocate,
						   release};
	driver_binding = (struct binding){
		supported, start, stop, 0xa, 0, image_handle, image_handle};
	return boot->install(&driver_binding.handle, &binding_guid,
			     &driver_binding, NULL);
}
