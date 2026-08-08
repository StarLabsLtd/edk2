/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Native SMM Control 2 protocol using the bootloader register-info GUID HOB. */

#include <cdk2/smm_control.h>
#include <guid/smm_register_info.h>
#include <stddef.h>

#define HOB_TYPE_GUID_EXTENSION 0x0004U
#define HOB_TYPE_END_OF_LIST 0xffffU
#define MAX_HOB_LIST_SIZE SIZE_1MB
#define SMM_DATA_PORT 0xb3U
#define SMM_CONTROL_PORT 0xb2U
#define EVT_NOTIFY_SIGNAL 0x00000200U
#define TPL_NOTIFY 16U

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

typedef void CDK2_MS_ABI event_notify_function(void *event, void *context);
typedef void **cdk2_void_ptr_ptr;
typedef const EFI_GUID *cdk2_guid_const_ptr;
typedef EFI_STATUS CDK2_MS_ABI install_multiple_function(void **handle, ...);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_function(UINT32 type, UINTN tpl,
	event_notify_function notify, void *context, cdk2_guid_const_ptr group,
	cdk2_void_ptr_ptr event);
typedef EFI_STATUS CDK2_MS_ABI convert_pointer_function(UINTN disposition,
	void **address);

struct boot_services_view {
	UINT8 before_install_multiple[328];
	install_multiple_function *install_multiple;
	UINT8 before_create_event_ex[32];
	create_event_ex_function *create_event_ex;
};

struct runtime_services_view {
	UINT8 before_convert_pointer[64];
	convert_pointer_function *convert_pointer;
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

struct hob_header {
	UINT16 type;
	UINT16 length;
	UINT32 reserved;
};

struct guid_hob {
	struct hob_header header;
	EFI_GUID name;
};

static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4,
	{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID smm_register_info_guid = {
	0xaa9bd7a7, 0xcafb, 0x4499,
	{ 0xa4, 0xa9, 0x0b, 0x34, 0x6b, 0x40, 0xa6, 0x22 }
};
static const EFI_GUID smm_control2_guid = {
	0x843dc720, 0xab1e, 0x42cb,
	{ 0x93, 0x57, 0x8a, 0x00, 0x78, 0xf3, 0x56, 0x1b }
};
static const EFI_GUID virtual_address_change_guid = {
	0x13fa7698, 0xc831, 0x49c7,
	{ 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 }
};

static UINT16 smi_enable_port;
static UINT8 global_enable_bit;
static UINT8 apm_enable_bit;
static struct runtime_services_view *runtime_services;
static void *driver_handle;
static void *virtual_address_event;

#ifdef CDK2_SMM_CONTROL_TEST
extern UINT32 cdk2_smm_control_test_in32(UINT16 port);
extern void cdk2_smm_control_test_out32(UINT16 port, UINT32 value);
extern void cdk2_smm_control_test_out8(UINT16 port, UINT8 value);
#define io_in32 cdk2_smm_control_test_in32
#define io_out32 cdk2_smm_control_test_out32
#define io_out8 cdk2_smm_control_test_out8
#else
static UINT32 io_in32(UINT16 port)
{
	UINT32 value;

	__asm__ volatile("inl %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}

static void io_out32(UINT16 port, UINT32 value)
{
	__asm__ volatile("outl %0, %w1" : : "a"(value), "Nd"(port));
}

static void io_out8(UINT16 port, UINT8 value)
{
	__asm__ volatile("outb %b0, %w1" : : "a"(value), "Nd"(port));
}
#endif

static int guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left;
	const UINT8 *b = (const UINT8 *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++) {
		if (a[index] != b[index])
			return 0;
	}
	return 1;
}

static const void *find_guid_hob(const struct system_table_view *system,
	const EFI_GUID *wanted, UINTN *payload_size)
{
	const UINT8 *hob_list = NULL;
	const struct hob_header *hob;
	UINTN index;
	UINTN walked = 0;

	if (system->table_count != 0U && system->tables == NULL)
		return NULL;
	for (index = 0; index < system->table_count; index++) {
		if (guid_equal(&system->tables[index].guid, &hob_list_guid)) {
			hob_list = system->tables[index].table;
			break;
		}
	}
	if (hob_list == NULL)
		return NULL;
	hob = (const struct hob_header *)(const void *)hob_list;
	while (walked + sizeof(*hob) <= MAX_HOB_LIST_SIZE) {
		const struct guid_hob *guid_hob;

		if (hob->type == HOB_TYPE_END_OF_LIST)
			return NULL;
		if (hob->length < sizeof(*hob) || hob->length > MAX_HOB_LIST_SIZE - walked)
			return NULL;
		if (hob->type == HOB_TYPE_GUID_EXTENSION && hob->length >= sizeof(*guid_hob)) {
			guid_hob = (const struct guid_hob *)(const void *)hob;
			if (guid_equal(&guid_hob->name, wanted)) {
				*payload_size = hob->length - sizeof(*guid_hob);
				return guid_hob + 1;
			}
		}
		walked += hob->length;
		hob = (const struct hob_header *)(const void *)(hob_list + walked);
	}
	return NULL;
}

static const struct cdk2_smm_generic_register *find_register(
	const struct cdk2_smm_register_info *info, UINT64 id)
{
	UINTN index;

	for (index = 0; index < info->count; index++) {
		if (info->registers[index].id == id)
			return &info->registers[index];
	}
	return NULL;
}

static int valid_enable_register(const struct cdk2_smm_generic_register *reg)
{
	return reg != NULL && reg->value == 1U &&
		reg->address.address_space_id == CDK2_ACPI_SYSTEM_IO &&
		reg->address.register_bit_width == 1U &&
		reg->address.register_bit_offset < 32U &&
		reg->address.access_size == CDK2_ACPI_ACCESS_DWORD &&
		reg->address.address != 0U && reg->address.address <= 0xffffU;
}

static EFI_STATUS CDK2_MS_ABI trigger(
	const struct cdk2_smm_control2_protocol *protocol, UINT8 *command,
	UINT8 *data, BOOLEAN periodic, UINTN interval)
{
	UINT32 enable;
	UINT32 mask;

	(void)protocol;
	(void)interval;
	if (periodic)
		return EFI_INVALID_PARAMETER;
	mask = (UINT32)(1U << global_enable_bit) | (UINT32)(1U << apm_enable_bit);
	enable = io_in32(smi_enable_port);
	if ((enable & mask) != mask)
		io_out32(smi_enable_port, enable | mask);
	io_out8(SMM_DATA_PORT, data == NULL ? 0U : *data);
	io_out8(SMM_CONTROL_PORT, command == NULL ? 0U : *command);
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI clear(
	const struct cdk2_smm_control2_protocol *protocol, BOOLEAN periodic)
{
	(void)protocol;
	return periodic ? EFI_INVALID_PARAMETER : EFI_SUCCESS;
}

static struct cdk2_smm_control2_protocol smm_control = {
	trigger, clear, 0
};

static void CDK2_MS_ABI virtual_address_change(void *event, void *context)
{
	(void)event;
	(void)context;
	(void)runtime_services->convert_pointer(0, (void **)&smm_control.trigger);
	(void)runtime_services->convert_pointer(0, (void **)&smm_control.clear);
}

EFI_STATUS CDK2_MS_ABI cdk2_smm_control_entry(void *image,
	struct system_table_view *system)
{
	const struct cdk2_smm_register_info *info;
	const struct cdk2_smm_generic_register *global;
	const struct cdk2_smm_generic_register *apm;
	UINTN payload_size;
	UINTN required;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->runtime_services == NULL ||
	    system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	info = find_guid_hob(system, &smm_register_info_guid, &payload_size);
	if (info == NULL)
		return EFI_UNSUPPORTED;
	if (payload_size < sizeof(*info) || info->revision != CDK2_SMM_REGISTER_INFO_REVISION ||
	    info->reserved != 0U || info->count == 0U ||
	    info->count > CDK2_SMM_REGISTER_MAX_COUNT)
		return EFI_COMPROMISED_DATA;
	required = sizeof(*info) + (UINTN)info->count * sizeof(info->registers[0]);
	if (required > payload_size)
		return EFI_COMPROMISED_DATA;
	global = find_register(info, CDK2_SMM_REGISTER_ID_GLOBAL_ENABLE);
	apm = find_register(info, CDK2_SMM_REGISTER_ID_APM_ENABLE);
	if (!valid_enable_register(global) || !valid_enable_register(apm))
		return EFI_NOT_FOUND;
	if (global->address.address != apm->address.address ||
	    global->address.register_bit_offset == apm->address.register_bit_offset)
		return EFI_UNSUPPORTED;
	smi_enable_port = (UINT16)global->address.address;
	global_enable_bit = global->address.register_bit_offset;
	apm_enable_bit = apm->address.register_bit_offset;
	runtime_services = system->runtime_services;
	status = system->boot_services->install_multiple(&driver_handle,
		&smm_control2_guid, &smm_control, NULL);
	if (EFI_ERROR(status))
		return status;
	return system->boot_services->create_event_ex(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
		virtual_address_change, NULL, &virtual_address_change_guid,
		&virtual_address_event);
}
