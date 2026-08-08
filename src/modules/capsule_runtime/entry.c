/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/capsule_runtime.h>
#include <cdk2/capsule_runtime_entry.h>

#define EVT_NOTIFY_SIGNAL 0x200U
#define TPL_NOTIFY 16U

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI convert_pointer_fn(UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI set_variable_fn(CHAR16 *, EFI_GUID *, UINT32,
	UINTN, void *);
typedef void CDK2_MS_ABI reset_system_fn(UINT32, EFI_STATUS, UINTN, void *);

static const EFI_GUID capsule_arch_guid = { 0x5053697e, 0x2cbc, 0x4819,
	{ 0x90, 0xd9, 0x05, 0x80, 0xde, 0xee, 0x57, 0x54 } };
static const EFI_GUID va_change_guid = { 0x13fa7698, 0xc831, 0x49c7,
	{ 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 } };
static const EFI_GUID capsule_vendor_guid = { 0x711c703f, 0xc285, 0x4b10,
	{ 0xa3, 0xb0, 0x36, 0xec, 0xbd, 0x3c, 0x8b, 0xe2 } };
static struct cdk2_system_table_view *system_table;
static struct cdk2_capsule_runtime runtime;
static void *capsule_handle;
static void *va_event;

static EFI_STATUS support(const struct cdk2_capsule_header *capsule, void *context)
{
	(void)capsule;
	(void)context;
	return EFI_UNSUPPORTED;
}

static EFI_STATUS process(const struct cdk2_capsule_header *capsule, void *context)
{
	(void)capsule;
	(void)context;
	return EFI_UNSUPPORTED;
}

static EFI_STATUS persist(UINTN sequence, UINT64 scatter_gather, void *context)
{
	set_variable_fn *set_variable = (void *)system_table->runtime->set_variable;
	CHAR16 name[20] = L"CapsuleUpdateData";

	(void)context;
	if (sequence > 9U || set_variable == NULL)
		return EFI_OUT_OF_RESOURCES;
	if (sequence != 0U)
		name[17] = (CHAR16)(L'0' + sequence);
	return set_variable(name, (EFI_GUID *)&capsule_vendor_guid, 7U,
		sizeof(scatter_gather), &scatter_gather);
}

static void writeback(UINT64 scatter_gather, void *context)
{
	(void)scatter_gather;
	(void)context;
#ifndef CDK2_CAPSULE_ENTRY_TEST
	__asm__ volatile("wbinvd" : : : "memory");
#endif
}

static void warm_reset(void *context)
{
	reset_system_fn *reset = (void *)system_table->runtime->reset_system;

	(void)context;
	if (reset != NULL)
		reset(1U, EFI_SUCCESS, 0, NULL);
}

static EFI_STATUS CDK2_MS_ABI update_capsule(
	const struct cdk2_capsule_header *const *capsules, UINTN count, UINT64 scatter_gather)
{
	static const struct cdk2_capsule_policy policy = {
		.max_nonpopulate = 0xa00000U,
		.max_populate = 0x6400000U,
		.in_ram = TRUE,
		.persist = TRUE,
		.process_at_runtime = FALSE,
	};

	return cdk2_capsule_update(&runtime, capsules, count, scatter_gather, &policy, support);
}

static EFI_STATUS CDK2_MS_ABI query_capsule(
	const struct cdk2_capsule_header *const *capsules, UINTN count,
	UINT64 *maximum_size, UINT32 *reset_type)
{
	static const struct cdk2_capsule_policy policy = {
		.max_nonpopulate = 0xa00000U,
		.max_populate = 0x6400000U,
		.in_ram = TRUE,
		.persist = TRUE,
		.process_at_runtime = FALSE,
	};

	return cdk2_capsule_query(capsules, count, &policy, support, NULL,
		maximum_size, reset_type);
}

static EFI_STATUS convert(void **pointer, void *context)
{
	convert_pointer_fn *convert_pointer = (void *)system_table->runtime->convert_pointer;

	(void)context;
	return convert_pointer == NULL ? EFI_UNSUPPORTED : convert_pointer(0, pointer);
}

static void CDK2_MS_ABI virtual_address_change(void *event, void *context)
{
	(void)event;
	(void)context;
	(void)cdk2_capsule_convert_runtime(&runtime, convert, NULL);
}

static void restore_slots(struct cdk2_runtime_services_view *rt, void *old_update,
	void *old_query, UINT32 old_crc)
{
	rt->update_capsule = old_update;
	rt->query_capsule = old_query;
	rt->header.crc32 = old_crc;
}

EFI_STATUS CDK2_MS_ABI cdk2_capsule_runtime_entry(void *image,
	struct cdk2_system_table_view *system)
{
	create_event_ex_fn *create_event_ex;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
	void *old_update, *old_query;
	UINT32 old_crc;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->boot == NULL || system->runtime == NULL)
		return EFI_INVALID_PARAMETER;
	system_table = system;
	old_update = system->runtime->update_capsule;
	old_query = system->runtime->query_capsule;
	old_crc = system->runtime->header.crc32;
	runtime = (struct cdk2_capsule_runtime) {
		.context = NULL,
		.process = process,
		.persist = persist,
		.writeback = writeback,
		.warm_reset = warm_reset,
	};
	status = cdk2_capsule_install_runtime_slots(system->runtime, system->boot,
		update_capsule, query_capsule);
	if (EFI_ERROR(status))
		return status;
	install_multiple = system->boot->install_multiple;
	if (install_multiple == NULL) {
		status = EFI_UNSUPPORTED;
		goto restore;
	}
	capsule_handle = NULL;
	status = install_multiple(&capsule_handle, &capsule_arch_guid, NULL, NULL);
	if (EFI_ERROR(status))
		goto restore;
	create_event_ex = (void *)system->boot->create_event_ex;
	if (create_event_ex == NULL) {
		status = EFI_UNSUPPORTED;
		goto uninstall;
	}
	va_event = NULL;
	status = create_event_ex(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, virtual_address_change,
		NULL, &va_change_guid, &va_event);
	if (!EFI_ERROR(status))
		return EFI_SUCCESS;
uninstall:
	uninstall_multiple = system->boot->uninstall_multiple;
	if (uninstall_multiple != NULL)
		(void)uninstall_multiple(capsule_handle, &capsule_arch_guid, NULL, NULL);
	capsule_handle = NULL;
restore:
	restore_slots(system->runtime, old_update, old_query, old_crc);
	return status;
}
