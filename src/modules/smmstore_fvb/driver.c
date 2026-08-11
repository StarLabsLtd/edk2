/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

#define HOB_TYPE_GUID_EXTENSION 4U
#define HOB_TYPE_END_OF_LIST 0xffffU
#define MAX_HOB_LIST_SIZE SIZE_1MB
#define EVT_NOTIFY_SIGNAL 0x00000200U
#define TPL_NOTIFY 16U
#define APM_CONTROL_PORT 0xb2U

struct table_header {
	UINT64 signature;
	UINT32 revision;
	UINT32 header_size;
	UINT32 crc32;
	UINT32 reserved;
};

struct config_table {
	EFI_GUID guid;
	void *table;
};

struct hob_header {
	UINT16 type;
	UINT16 length;
	UINT32 reserved;
};

struct guid_hob {
	struct hob_header header;
	EFI_GUID name;
};

typedef void CDK2_MS_ABI event_notify_fn(void *event, void *context);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **handle, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *handle, ...);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32 type, UINTN tpl,
						  event_notify_fn * notify,
						  void *context,
						  const EFI_GUID *group,
						  void **event);
typedef EFI_STATUS CDK2_MS_ABI convert_pointer_fn(UINTN disposition,
						  void **address);

struct boot_services_view {
	UINT8 before_install_multiple[328];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
	UINT8 before_create_event_ex[24];
	create_event_ex_fn *create_event_ex;
};

_Static_assert(offsetof(struct boot_services_view, install_multiple) == 328,
	       "InstallMultipleProtocolInterfaces offset");
_Static_assert(offsetof(struct boot_services_view, create_event_ex) == 368,
	       "CreateEventEx offset");

struct runtime_services_view {
	UINT8 before_convert_pointer[64];
	convert_pointer_fn *convert_pointer;
};

struct system_table_view {
	struct table_header header;
	CHAR16 *firmware_vendor;
	UINT32 firmware_revision;
	UINT32 padding;
	void *console_fields[6];
	struct runtime_services_view *runtime_services;
	struct boot_services_view *boot_services;
	UINTN table_count;
	struct config_table *tables;
};

static const EFI_GUID hob_list_guid = {
	0x7739f24cU,
	0x93d7U,
	0x11d4U,
	{0x9aU, 0x3aU, 0x00U, 0x90U, 0x27U, 0x3fU, 0xc1U, 0x4dU}};
static const EFI_GUID smmstore_info_guid = {
	0xf585ca19U,
	0x881bU,
	0x44fbU,
	{0x3fU, 0x3dU, 0x81U, 0x89U, 0x7cU, 0x57U, 0xbbU, 0x01U}};
static const EFI_GUID fvb_protocol_guid = {
	0x8f644fa9U,
	0xe850U,
	0x4db1U,
	{0x9cU, 0xe2U, 0x0bU, 0x44U, 0x69U, 0x8eU, 0x8dU, 0xa4U}};
static const EFI_GUID fvb_ready_guid = {
	0xd1a86e3fU,
	0x0707U,
	0x4c35U,
	{0x83U, 0xcdU, 0xdcU, 0x2cU, 0x29U, 0xc8U, 0x91U, 0xa3U}};
static const EFI_GUID virtual_address_change_guid = {
	0x13fa7698U,
	0xc831U,
	0x49c7U,
	{0x87U, 0xeaU, 0x8fU, 0x43U, 0xfcU, 0xc2U, 0x51U, 0x96U}};

static struct cdk2_smmstore_fvb runtime_fvb;
static struct runtime_services_view *runtime_services;
static struct boot_services_view *boot_services;
static void *driver_handle;
static void *virtual_address_event;

static BOOLEAN guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *left_bytes = (const UINT8 *)left;
	const UINT8 *right_bytes = (const UINT8 *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++)
		if (left_bytes[index] != right_bytes[index])
			return FALSE;
	return TRUE;
}

static const SMMSTORE_INFO *find_info(struct system_table_view *system,
				      UINTN *payload_size)
{
	const UINT8 *hob_list = NULL;
	const struct hob_header *hob;
	UINTN walked = 0;
	UINTN index;

	if (system->table_count != 0 && system->tables == NULL)
		return NULL;
	for (index = 0; index < system->table_count; index++)
		if (guid_equal(&system->tables[index].guid, &hob_list_guid)) {
			hob_list = system->tables[index].table;
			break;
		}
	if (hob_list == NULL)
		return NULL;
	hob = (const struct hob_header *)(const void *)hob_list;
	while (walked + sizeof(*hob) <= MAX_HOB_LIST_SIZE) {
		const struct guid_hob *guid_hob;

		if (hob->type == HOB_TYPE_END_OF_LIST)
			return NULL;
		if (hob->length < sizeof(*hob) ||
		    hob->length > MAX_HOB_LIST_SIZE - walked)
			return NULL;
		if (hob->type == HOB_TYPE_GUID_EXTENSION &&
		    hob->length >= sizeof(*guid_hob)) {
			guid_hob = (const struct guid_hob *)(const void *)hob;
			if (guid_equal(&guid_hob->name, &smmstore_info_guid)) {
				*payload_size = hob->length - sizeof(*guid_hob);
				return (const SMMSTORE_INFO
						*)(const void *)(guid_hob + 1);
			}
		}
		walked += hob->length;
		hob = (const struct hob_header *)(const void *)(hob_list +
								walked);
	}
	return NULL;
}

__weak UINT32 cdk2_smmstore_arch_invoke(UINT8 apm_command, UINT8 command,
					void *request)
{
#if defined(__i386__) || defined(__x86_64__)
	UINT32 result = apm_command | (UINT32)command << 8;
	UINTN parameter = (UINTN)request;

	if (parameter > MAX_UINT32)
		return 1U;
	__asm__ volatile("outb %%al, %w1"
			 : "+a"(result)
			 : "Nd"(APM_CONTROL_PORT), "b"((UINT32)parameter)
			 : "memory");
	return result;
#else
	(void)apm_command;
	(void)command;
	(void)request;
	return 2U;
#endif
}

static UINT32 invoke(void *context, UINT8 command, void *request)
{
	const SMMSTORE_INFO *info = context;

	return cdk2_smmstore_arch_invoke(info->apm_cmd, command, request);
}

static EFI_STATUS convert(void **pointer)
{
	return runtime_services->convert_pointer(0, pointer);
}

static void CDK2_MS_ABI virtual_address_change(void *event, void *context)
{
	(void)event;
	(void)context;
	(void)cdk2_smmstore_fvb_virtualize(&runtime_fvb, convert);
}

EFI_STATUS CDK2_MS_ABI cdk2_smmstore_fvb_entry(void *image,
					       struct system_table_view *system)
{
	const SMMSTORE_INFO *info;
	UINTN payload_size;
	UINTN variable_count;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->runtime_services == NULL ||
	    system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	info = find_info(system, &payload_size);
	if (info == NULL)
		return EFI_NOT_FOUND;
	if (payload_size < sizeof(*info))
		return EFI_COMPROMISED_DATA;
	runtime_services = system->runtime_services;
	boot_services = system->boot_services;
	status = cdk2_smmstore_fvb_initialize(&runtime_fvb, info, invoke,
					      (void *)info);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_variable_store_validate(&runtime_fvb.store,
					      &variable_count);
	if (status == EFI_COMPROMISED_DATA || status == EFI_CRC_ERROR) {
		status = cdk2_variable_store_format(&runtime_fvb.store);
		if (!EFI_ERROR(status))
			status = cdk2_variable_store_validate(
				&runtime_fvb.store, &variable_count);
	}
	if (EFI_ERROR(status))
		return status;
	status = boot_services->install_multiple(&driver_handle,
						 &fvb_ready_guid, NULL,
						 &fvb_protocol_guid,
						 &runtime_fvb.protocol, NULL);
	if (EFI_ERROR(status))
		return status;
	status = boot_services->create_event_ex(
		EVT_NOTIFY_SIGNAL, TPL_NOTIFY, virtual_address_change, NULL,
		&virtual_address_change_guid, &virtual_address_event);
	if (EFI_ERROR(status)) {
		(void)boot_services->uninstall_multiple(
			driver_handle, &fvb_ready_guid, NULL,
			&fvb_protocol_guid,
			&runtime_fvb.protocol, NULL);
		return status;
	}
	return EFI_SUCCESS;
}

const struct cdk2_fvb_protocol *cdk2_smmstore_fvb_protocol(void)
{
	return &runtime_fvb.protocol;
}
