/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_bus_binding.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI image_unload_fn(void *);

struct boot_view {
	UINT8 header[24];
	void *raise_tpl, *restore_tpl, *allocate_pages, *free_pages, *get_memory_map;
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	void *create_event, *set_timer, *wait_event, *signal_event, *close_event;
	void *check_event, *install_protocol, *reinstall_protocol, *uninstall_protocol;
	handle_fn *handle_protocol;
	void *reserved, *register_notify, *locate_handle, *locate_path;
	void *install_config, *load_image, *start_image, *exit, *unload_image;
	void *exit_boot, *monotonic, *stall, *watchdog, *connect, *disconnect;
	open_fn *open_protocol;
	close_fn *close_protocol;
	void *open_info, *protocols, *locate_buffer, *locate_protocol;
	install_fn *install_multiple;
	uninstall_fn *uninstall_multiple;
};
struct system_view { UINT8 prefix[96]; struct boot_view *boot; };
struct loaded_view {
	UINT32 revision;
	void *parent, *system, *device, *path, *reserved;
	UINT32 options_size;
	void *options, *base;
	UINT64 size;
	UINT32 code_type, data_type;
	image_unload_fn *unload;
};

static struct cdk2_scsi_driver_binding *published_driver;
static struct loaded_view loaded;
static UINTN allocations, closes, uninstalls;
static struct cdk2_device_path end_path = { 0x7f, 0xff, { 4, 0 } };
static struct cdk2_ext_scsi_mode mode = { 0, 3, 4 };
static EFI_STATUS CDK2_MS_ABI build_path(struct cdk2_ext_scsi *pass, UINT8 *target,
	UINT64 lun, struct cdk2_device_path **path)
{
	(void)pass; (void)target; (void)lun; (void)path;
	return EFI_UNSUPPORTED;
}
static struct cdk2_ext_scsi pass = { .build_device_path = build_path, .mode = &mode };

static EFI_STATUS CDK2_MS_ABI handle(void *image, const EFI_GUID *guid,
	void **interface)
{
	(void)image; (void)guid; *interface = &loaded; return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI allocate(UINT32 type, UINTN size, void **buffer)
{
	(void)type; *buffer = malloc(size);
	if (*buffer != NULL)
		allocations++;
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI release(void *buffer)
{
	free(buffer); allocations--; return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI open(void *controller, const EFI_GUID *guid,
	void **interface, void *agent, void *child, UINT32 attributes)
{
	(void)controller; (void)agent; (void)child; (void)attributes;
	*interface = guid->data1 == cdk2_device_path_guid.data1 ?
		(void *)&end_path : (void *)&pass;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI close(void *controller, const EFI_GUID *guid,
	void *agent, void *child)
{
	(void)controller; (void)guid; (void)agent; (void)child; closes++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI install(void **handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)handle;
	published_driver = interface;
	return guid == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{
	(void)handle; uninstalls++; return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI old_unload(void *image)
{
	(void)image; return EFI_SUCCESS;
}

struct cdk2_system_table;
EFI_STATUS CDK2_MS_ABI cdk2_scsi_bus_entry(void *, struct cdk2_system_table *);

int main(void)
{
	struct boot_view boot = { 0 };
	struct system_view system = { { 0 }, &boot };
	EFI_STATUS status;

	boot.allocate_pool = allocate; boot.free_pool = release;
	boot.handle_protocol = handle; boot.open_protocol = open;
	boot.close_protocol = close; boot.install_multiple = (install_fn *)install;
	boot.uninstall_multiple = uninstall; boot.locate_path = (void *)1;
	boot.signal_event = (void *)1; loaded.unload = old_unload;
	status = cdk2_scsi_bus_entry((void *)1, (struct cdk2_system_table *)&system);
	if (status != EFI_SUCCESS || published_driver == NULL ||
	    published_driver->start(published_driver, (void *)2, &end_path) != EFI_SUCCESS ||
	    published_driver->start(published_driver, (void *)3, &end_path) != EFI_SUCCESS ||
	    allocations != 2 || loaded.unload == old_unload)
		return 1;
	status = loaded.unload((void *)1);
	if (status != EFI_SUCCESS || allocations != 0 || closes != 4 ||
	    uninstalls != 1 || loaded.unload != old_unload)
		return 1;
	return cdk2_scsi_bus_entry((void *)1, NULL) == EFI_INVALID_PARAMETER ? 0 : 1;
}
