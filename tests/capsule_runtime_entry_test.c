/* SPDX-License-Identifier: GPL-2.0-only */

#include <assert.h>
#include <cdk2/capsule_runtime_entry.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, const EFI_GUID *, void **);

static EFI_STATUS install_status, event_status;
static UINTN installs, uninstalls, converts;
static void (CDK2_MS_ABI *notification)(void *, void *);

static EFI_STATUS CDK2_MS_ABI crc32(void *table, UINTN size, cdk2_uint32_ptr crc)
{ (void)table; (void)size; *crc = 0xabcdef01U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{ installs++; *handle = (void *)1; return install_status; }
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{ assert(handle == (void *)1); uninstalls++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context,
	cdk2_const_guid_ptr group, cdk2_void_ptr_ptr event)
{
	(void)context;
	assert(type == 0x200U && tpl == 16U && group != NULL);
	notification = notify;
	*event = (void *)2;
	return event_status;
}
static EFI_STATUS CDK2_MS_ABI convert_pointer(UINTN disposition, void **pointer)
{ (void)disposition; assert(pointer != NULL); converts++; return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_boot_services_view boot = { 0 };
	struct cdk2_runtime_services_view runtime = { 0 };
	struct cdk2_system_table_view system = { 0 };
	void *old_update = (void *)3, *old_query = (void *)4;

	boot.calculate_crc32 = crc32;
	boot.create_event_ex = create_event;
	boot.install_multiple = install;
	boot.uninstall_multiple = uninstall;
	runtime.header.size = sizeof(runtime);
	runtime.header.crc32 = 7U;
	runtime.update_capsule = old_update;
	runtime.query_capsule = old_query;
	runtime.convert_pointer = convert_pointer;
	system.boot = &boot;
	system.runtime = &runtime;
	event_status = EFI_DEVICE_ERROR;
	assert(cdk2_capsule_runtime_entry((void *)5, &system) == EFI_DEVICE_ERROR);
	assert(runtime.update_capsule == old_update && runtime.query_capsule == old_query &&
		runtime.header.crc32 == 7U && installs == 1U && uninstalls == 1U);
	event_status = EFI_SUCCESS;
	install_status = EFI_DEVICE_ERROR;
	assert(cdk2_capsule_runtime_entry((void *)5, &system) == EFI_DEVICE_ERROR);
	assert(uninstalls == 1U && runtime.update_capsule == old_update &&
		runtime.query_capsule == old_query && runtime.header.crc32 == 7U);
	install_status = EFI_SUCCESS;
	assert(cdk2_capsule_runtime_entry((void *)5, &system) == EFI_SUCCESS);
	assert(installs == 3U && runtime.update_capsule != old_update &&
		runtime.query_capsule != old_query && runtime.header.crc32 == 0xabcdef01U);
	assert(notification != NULL);
	notification((void *)2, NULL);
	assert(converts == 4U);
	return 0;
}
