/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_console_package.h>
#include <stdarg.h>
#include <stdlib.h>

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN, event_notify_fn *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI register_notify_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);

struct boot_services_view {
	UINT8 header[24];
	void *slots_before_allocate[5];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	create_event_fn *create_event;
	void *slots_before_close[3];
	close_event_fn *close_event;
	void *slots_before_register[6];
	register_notify_fn *register_protocol_notify;
	void *slots_before_open[13];
	void *open_protocol;
	void *close_protocol;
	void *open_protocol_information;
	void *protocols_per_handle;
	void *locate_handle_buffer;
	locate_protocol_fn *locate_protocol;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct system_table_view { UINT8 before_boot_services[96]; struct boot_services_view *boot; };
EFI_STATUS CDK2_MS_ABI cdk2_graphics_console_entry(void *, struct system_table_view *);

static UINTN installs, additions, removals, notifications, closes, frees, fail_install;
static EFI_STATUS package_status;
static EFI_STATUS locate_status;
static event_notify_fn *saved_notify;
static void *saved_context;
static struct cdk2_hii_database_view database;
static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{ (void)type; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{ frees++; free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	event_notify_fn *notify, void *context, void **event)
{ (void)type; (void)tpl; saved_notify = notify; saved_context = context; *event = (void *)1; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{ if (event == NULL) return EFI_INVALID_PARAMETER; closes++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI register_notify(const EFI_GUID * guid, void *event,
	void **registration)
{ if (guid == NULL || event == NULL) return EFI_INVALID_PARAMETER; notifications++; *registration = (void *)2; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI locate_protocol(const EFI_GUID * guid, void *registration,
	void **interface)
{
	(void)registration;
	if (guid == NULL)
		return EFI_INVALID_PARAMETER;
	if (EFI_ERROR(locate_status))
		return locate_status;
	*interface = &database;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{ if (handle == NULL) return EFI_INVALID_PARAMETER; installs++; return installs == fail_install ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle, ...)
{ return handle == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI new_package(const struct cdk2_hii_database_view *self,
	const void *list, void *driver, void **handle)
{ (void)self; (void)driver; if (list == NULL) return EFI_INVALID_PARAMETER; additions++; if (EFI_ERROR(package_status)) return package_status; *handle = (void *)3; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI remove_package(const struct cdk2_hii_database_view *self,
	void *handle)
{ (void)self; (void)handle; removals++; return EFI_SUCCESS; }

int main(void)
{
	struct boot_services_view boot = { 0 };
	struct system_table_view system = { { 0 }, &boot };

	database.new_package_list = new_package;
	database.remove_package_list = remove_package;
	boot.allocate_pool = allocate_pool;
	boot.free_pool = free_pool;
	boot.create_event = create_event;
	boot.close_event = close_event;
	boot.register_protocol_notify = register_notify;
	boot.locate_protocol = locate_protocol;
	boot.install_multiple = install_multiple;
	boot.uninstall_multiple = uninstall_multiple;
	locate_status = EFI_NOT_FOUND;
	if (cdk2_graphics_console_entry((void *)4, &system) != EFI_SUCCESS ||
	    installs != 3U || notifications != 1U || additions != 0U || closes != 0U ||
	    saved_notify == NULL)
		return 1;
	locate_status = EFI_SUCCESS;
	saved_notify((void *)1, saved_context);
	if (additions != 1U)
		return 1;
	installs = additions = notifications = removals = closes = frees = 0U;
	if (cdk2_graphics_console_entry((void *)4, &system) != EFI_SUCCESS)
		return 1;
	installs = additions = notifications = removals = closes = frees = 0U;
	package_status = EFI_OUT_OF_RESOURCES;
	if (cdk2_graphics_console_entry((void *)4, &system) != EFI_OUT_OF_RESOURCES ||
	    installs != 0U || additions != 1U || closes != 1U || frees != 1U)
		return 1;
	package_status = EFI_SUCCESS;
	installs = additions = notifications = removals = closes = frees = 0U;
	fail_install = 2U;
	if (cdk2_graphics_console_entry((void *)4, &system) != EFI_DEVICE_ERROR)
		return 1;
	return installs == 2U && notifications == 1U && additions == 1U &&
		removals == 1U && closes == 1U && frees == 1U ? 0 : 1;
}
