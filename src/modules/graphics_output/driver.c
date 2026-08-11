/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_output_driver.h>

#include <stddef.h>
#include <string.h>

#define OPEN_GET 2U
#define OPEN_BY_DRIVER 0x10U
#define OPEN_BY_CHILD 8U
#define EVT_NOTIFY_SIGNAL 0x200U
#define TPL_CALLBACK 8U
#define GOP_NOT_STARTED ((1ULL << 63) | 19ULL)

static const EFI_GUID pci_io_guid = {
	0x4cf5b200,
	0x68b8,
	0x4ca5,
	{0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a}};
static const EFI_GUID gop_guid = {
	0x9042a9de,
	0x23dc,
	0x4a38,
	{0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a}};
static const EFI_GUID device_path_guid = {
	0x09576e91,
	0x6d3f,
	0x11d2,
	{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static const EFI_GUID ready_to_boot_guid = {
	0x7ce88fb3,
	0x4bd7,
	0x4679,
	{0x87, 0xa8, 0xa8, 0xd8, 0xde, 0xe5, 0x0d, 0x2b}};

static struct cdk2_graphics_child *from_gop(struct cdk2_gop *gop)
{
	return (struct cdk2_graphics_child
			*)((uint8_t *)gop -
			   offsetof(struct cdk2_graphics_child, gop));
}

static uint64_t CDK2_MS_ABI
query_mode(struct cdk2_gop *gop, uint32_t mode, size_t *size,
	   EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **info)
{
	struct cdk2_graphics_child *child = from_gop(gop);
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *copy;
	if (size == NULL || info == NULL || mode >= child->graphics.max_mode)
		return EFI_INVALID_PARAMETER;
	copy = child->services->allocate(sizeof(*copy));
	if (copy == NULL)
		return EFI_OUT_OF_RESOURCES;
	*copy = mode == 0 ? child->graphics.physical : child->graphics.logical;
	*size = sizeof(*copy);
	*info = copy;
	return EFI_SUCCESS;
}

static void sync_mode(struct cdk2_graphics_child *child)
{
	child->mode.max_mode = child->graphics.max_mode;
	child->mode.mode = child->graphics.current_mode;
	child->mode.info = child->graphics.current_mode == 0
				   ? &child->graphics.physical
				   : &child->graphics.logical;
	child->mode.size_of_info = sizeof(*child->mode.info);
	child->mode.framebuffer_base =
		child->graphics.current_mode == 0
			? (uint64_t)(size_t)child->graphics.framebuffer
			: 0;
	child->mode.framebuffer_size =
		child->graphics.current_mode == 0
			? child->graphics.framebuffer_size
			: 0;
}

static uint64_t CDK2_MS_ABI set_mode(struct cdk2_gop *gop, uint32_t mode)
{
	struct cdk2_graphics_child *child = from_gop(gop);
	uint64_t status = cdk2_graphics_set_mode(&child->graphics, mode, 1);
	if (status == EFI_SUCCESS)
		sync_mode(child);
	return status;
}

static uint64_t CDK2_MS_ABI blt(struct cdk2_gop *gop,
				struct cdk2_blt_pixel *buffer,
				enum cdk2_blt_operation operation,
				size_t source_x, size_t source_y,
				size_t destination_x, size_t destination_y,
				size_t width, size_t height, size_t delta)
{
	return cdk2_graphics_blt(&from_gop(gop)->graphics, buffer, operation,
				 source_x, source_y, destination_x,
				 destination_y, width, height, delta);
}

static int matches(const struct cdk2_graphics_pci_info *actual,
		   const struct cdk2_graphics_device_info *expected)
{
	return expected == NULL ||
	       (actual->vendor_id == expected->vendor_id &&
		actual->device_id == expected->device_id &&
		actual->revision_id == expected->revision_id &&
		actual->subsystem_vendor_id == expected->subsystem_vendor_id &&
		actual->subsystem_id == expected->subsystem_id &&
		actual->bar_index == expected->bar_index);
}

uint64_t
cdk2_graphics_supported(struct cdk2_graphics_services *services, void *driver,
			void *controller,
			const struct cdk2_graphics_device_info *expected)
{
	struct cdk2_graphics_pci_info info;
	void *pci = NULL;
	uint64_t status;
	if (services == NULL || services->open == NULL ||
	    services->pci_info == NULL)
		return EFI_INVALID_PARAMETER;
	status = services->open(controller, &pci_io_guid, &pci, driver,
				controller, OPEN_GET);
	if (status != EFI_SUCCESS)
		return status;
	status = services->pci_info(pci, &info);
	return status == EFI_SUCCESS && matches(&info, expected)
		       ? EFI_SUCCESS
		       : EFI_UNSUPPORTED;
}

uint64_t cdk2_graphics_start(struct cdk2_graphics_child *child,
			     struct cdk2_graphics_services *services,
			     void *driver, void *controller,
			     const EFI_PEI_GRAPHICS_INFO_HOB *hob,
			     const struct cdk2_graphics_device_info *expected)
{
	struct cdk2_graphics_pci_info info;
	uint64_t status;
	uint64_t framebuffer_end, bar_end;
	if (child == NULL || services == NULL || hob == NULL)
		return EFI_INVALID_PARAMETER;
	memset(child, 0, sizeof(*child));
	child->services = services;
	child->driver = driver;
	child->controller = controller;
	status = services->open(controller, &pci_io_guid, &child->pci, driver,
				controller, OPEN_BY_DRIVER);
	if (status != EFI_SUCCESS)
		return status;
	status = services->pci_info(child->pci, &info);
	if (status != EFI_SUCCESS || !matches(&info, expected)) {
		status = EFI_UNSUPPORTED;
		goto close_parent;
	}
	framebuffer_end = hob->frame_buffer_base + hob->frame_buffer_size;
	bar_end = info.bar_base + info.bar_size;
	if (framebuffer_end < hob->frame_buffer_base ||
	    bar_end < info.bar_base || hob->frame_buffer_base < info.bar_base ||
	    framebuffer_end > bar_end) {
		status = EFI_UNSUPPORTED;
		goto close_parent;
	}
	status = cdk2_graphics_init(&child->graphics, hob, 2, 4, 3);
	if (status != EFI_SUCCESS)
		goto close_parent;
	child->gop = (struct cdk2_gop){query_mode, set_mode, blt, &child->mode};
	child->path = (struct cdk2_graphics_adr_path){2,    3,	  8, 0x00010000,
						      0x7f, 0xff, 4};
	sync_mode(child);
	status = services->create_event_ex(
		EVT_NOTIFY_SIGNAL, TPL_CALLBACK, cdk2_graphics_ready_to_boot,
		child, &ready_to_boot_guid, &child->ready_event);
	if (status != EFI_SUCCESS)
		goto close_parent;
	status = services->install(&child->handle, &device_path_guid,
				   &child->path, &gop_guid, &child->gop, NULL);
	if (status != EFI_SUCCESS)
		goto close_event;
	status = services->open(controller, &pci_io_guid, &child->pci, driver,
				child->handle, OPEN_BY_CHILD);
	if (status != EFI_SUCCESS)
		goto uninstall;
	child->started = 1;
	return EFI_SUCCESS;
uninstall:
	(void)services->uninstall(child->handle, &device_path_guid,
				  &child->path, &gop_guid, &child->gop, NULL);
close_event:
	(void)services->close_event(child->ready_event);
close_parent:
	(void)services->close(controller, &pci_io_guid, driver, controller);
	return status;
}

void CDK2_MS_ABI cdk2_graphics_ready_to_boot(void *event, void *context)
{
	struct cdk2_graphics_child *child = context;
	(void)event;
	if (child != NULL && child->started &&
	    child->graphics.current_mode != 0) {
		(void)cdk2_graphics_set_mode(&child->graphics, 0, 0);
		sync_mode(child);
	}
}

uint64_t cdk2_graphics_stop(struct cdk2_graphics_child *child)
{
	uint64_t status;
	if (child == NULL || !child->started)
		return GOP_NOT_STARTED;
	status = child->services->uninstall(child->handle, &device_path_guid,
					    &child->path, &gop_guid,
					    &child->gop, NULL);
	if (status != EFI_SUCCESS)
		return status;
	(void)child->services->close(child->controller, &pci_io_guid,
				     child->driver, child->handle);
	(void)child->services->close_event(child->ready_event);
	(void)child->services->close(child->controller, &pci_io_guid,
				     child->driver, child->controller);
	child->started = 0;
	return EFI_SUCCESS;
}
