/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* PI software-SMI dispatch using only register information handed off by coreboot. */

#include <cdk2/pch_smi_dispatch.h>
#include <guid/smm_register_info.h>
#include <stddef.h>

#define HOB_TYPE_GUID_EXTENSION 0x0004U
#define HOB_TYPE_END_OF_LIST 0xffffU
#define MAX_HOB_LIST_SIZE SIZE_1MB
#define SMM_CONTROL_PORT 0xb2U
#define SMM_DATA_PORT 0xb3U
#define SMM_SAVE_STATE_REGISTER_IO 512U
#define EFI_NATIVE_INTERFACE 0U

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

struct boot_services_view;
struct system_table_view {
	struct table_header header;
	CHAR16 *firmware_vendor;
	UINT32 firmware_revision;
	UINT32 padding;
	void *console_fields[6];
	void *runtime_services;
	struct boot_services_view *boot_services;
	UINTN table_count;
	struct config_table *tables;
};

typedef EFI_STATUS CDK2_MS_ABI locate_protocol_function(const EFI_GUID *guid,
	void *registration, void **protocol);
struct boot_services_view {
	UINT8 before_locate_protocol[320];
	locate_protocol_function *locate_protocol;
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

struct smm_base_protocol;
struct smm_system_table;
typedef EFI_STATUS CDK2_MS_ABI get_smst_function(
	const struct smm_base_protocol *protocol, struct smm_system_table **table);
struct smm_base_protocol {
	void *inside;
	get_smst_function *get_smst;
};

struct smm_save_state_io_info {
	UINT64 io_data;
	UINT16 io_port;
	UINT32 io_width;
	UINT32 io_type;
};
struct smm_cpu_protocol;
typedef EFI_STATUS CDK2_MS_ABI read_save_state_function(
	const struct smm_cpu_protocol *protocol, UINTN width, UINT32 reg,
	UINTN cpu_index, void *buffer);
struct smm_cpu_protocol {
	read_save_state_function *read_save_state;
	void *write_save_state;
};

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_function(EFI_MEMORY_TYPE type,
	UINTN size, void **buffer);
typedef EFI_STATUS CDK2_MS_ABI free_pool_function(void *buffer);
typedef EFI_STATUS CDK2_MS_ABI smm_locate_protocol_function(const EFI_GUID *guid,
	void *registration, void **protocol);
typedef EFI_STATUS CDK2_MS_ABI install_protocol_function(void **handle,
	const EFI_GUID *guid, UINT32 interface_type, void *interface);
typedef EFI_STATUS CDK2_MS_ABI smi_register_function(cdk2_smm_handler *handler,
	const EFI_GUID *handler_type, void **dispatch_handle);

struct smm_system_table {
	struct table_header header;
	CHAR16 *vendor;
	UINT32 revision;
	UINT32 padding;
	void *install_configuration_table;
	void *cpu_io[4];
	allocate_pool_function *allocate_pool;
	free_pool_function *free_pool;
	void *allocate_pages;
	void *free_pages;
	void *startup_ap;
	UINTN executing_cpu;
	UINTN number_of_cpus;
	UINTN *save_state_size;
	void **save_state;
	UINTN table_count;
	struct config_table *tables;
	install_protocol_function *install_protocol;
	void *uninstall_protocol;
	void *handle_protocol;
	void *register_protocol_notify;
	void *locate_handle;
	smm_locate_protocol_function *locate_protocol;
	void *manage;
	smi_register_function *register_smi_handler;
	void *unregister_smi_handler;
};

struct dispatch_context {
	struct dispatch_context *next;
	UINTN input;
	cdk2_smm_handler *handler;
};

static const EFI_GUID hob_list_guid = { 0x7739f24c, 0x93d7, 0x11d4,
	{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID register_info_guid = { 0xaa9bd7a7, 0xcafb, 0x4499,
	{ 0xa4, 0xa9, 0x0b, 0x34, 0x6b, 0x40, 0xa6, 0x22 } };
static const EFI_GUID smm_base_guid = { 0xf4ccbfb7, 0xf6e0, 0x47fd,
	{ 0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1, 0x91 } };
static const EFI_GUID smm_cpu_guid = { 0xeb346b97, 0x975f, 0x4a9f,
	{ 0x8b, 0x22, 0xf8, 0xe9, 0x2b, 0xb3, 0xd5, 0x69 } };
static const EFI_GUID sw_dispatch2_guid = { 0x18a3c6dc, 0x5eea, 0x48c8,
	{ 0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99 } };

static struct smm_system_table *smst;
static struct smm_cpu_protocol *smm_cpu;
static struct dispatch_context *handlers;
static UINT16 eos_port;
static UINT16 apm_status_port;
static UINT8 eos_bit;
static UINT8 apm_status_bit;
static void *root_dispatch_handle;
static void *protocol_handle;

#ifdef CDK2_PCH_SMI_DISPATCH_TEST
extern UINT8 cdk2_pch_smi_test_in8(UINT16 port);
extern UINT32 cdk2_pch_smi_test_in32(UINT16 port);
extern void cdk2_pch_smi_test_out32(UINT16 port, UINT32 value);
#define io_in8 cdk2_pch_smi_test_in8
#define io_in32 cdk2_pch_smi_test_in32
#define io_out32 cdk2_pch_smi_test_out32
#else
static UINT8 io_in8(UINT16 port)
{
	UINT8 value;
	__asm__ volatile("inb %w1, %b0" : "=a"(value) : "Nd"(port));
	return value;
}
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
#endif

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	const UINT8 *left = (const UINT8 *)a;
	const UINT8 *right = (const UINT8 *)b;
	UINTN index;
	for (index = 0; index < sizeof(*a); index++)
		if (left[index] != right[index])
			return 0;
	return 1;
}

static const void *find_guid_hob(const struct system_table_view *system,
	const EFI_GUID *wanted, UINTN *payload_size)
{
	const UINT8 *list = NULL;
	const struct hob_header *hob;
	UINTN index;
	UINTN walked = 0;
	if (system->table_count != 0U && system->tables == NULL)
		return NULL;
	for (index = 0; index < system->table_count; index++)
		if (guid_equal(&system->tables[index].guid, &hob_list_guid)) {
			list = system->tables[index].table;
			break;
		}
	if (list == NULL)
		return NULL;
	hob = (const struct hob_header *)(const void *)list;
	while (walked + sizeof(*hob) <= MAX_HOB_LIST_SIZE) {
		const struct guid_hob *guid;
		if (hob->type == HOB_TYPE_END_OF_LIST)
			return NULL;
		if (hob->length < sizeof(*hob) || hob->length > MAX_HOB_LIST_SIZE - walked)
			return NULL;
		if (hob->type == HOB_TYPE_GUID_EXTENSION && hob->length >= sizeof(*guid)) {
			guid = (const struct guid_hob *)(const void *)hob;
			if (guid_equal(&guid->name, wanted)) {
				*payload_size = hob->length - sizeof(*guid);
				return guid + 1;
			}
		}
		walked += hob->length;
		hob = (const struct hob_header *)(const void *)(list + walked);
	}
	return NULL;
}

static const struct cdk2_smm_generic_register *find_register(
	const struct cdk2_smm_register_info *info, UINT64 id)
{
	UINTN index;
	for (index = 0; index < info->count; index++)
		if (info->registers[index].id == id)
			return &info->registers[index];
	return NULL;
}

static int valid_status_register(const struct cdk2_smm_generic_register *reg)
{
	return reg != NULL && reg->value == 1U &&
		reg->address.address_space_id == CDK2_ACPI_SYSTEM_IO &&
		reg->address.register_bit_width == 1U &&
		reg->address.register_bit_offset < 32U &&
		reg->address.access_size == CDK2_ACPI_ACCESS_DWORD &&
		reg->address.address != 0U && reg->address.address <= MAX_UINT16;
}

static struct dispatch_context *find_input(UINTN input)
{
	struct dispatch_context *entry;
	for (entry = handlers; entry != NULL; entry = entry->next)
		if (entry->input == input)
			return entry;
	return NULL;
}

static EFI_STATUS CDK2_MS_ABI register_handler(
	const struct cdk2_smm_sw_dispatch2_protocol *protocol,
	cdk2_smm_handler *handler, struct cdk2_smm_sw_register_context *context,
	void **dispatch_handle)
{
	struct dispatch_context *entry;
	UINTN value;
	EFI_STATUS status;
	(void)protocol;
	if (handler == NULL || context == NULL || dispatch_handle == NULL || smst == NULL)
		return EFI_INVALID_PARAMETER;
	value = context->sw_smi_input_value;
	if (value == CDK2_SMM_SW_SMI_AUTO) {
		for (value = 1; value <= CDK2_SMM_SW_SMI_MAX; value++)
			if (find_input(value) == NULL)
				break;
		if (value > CDK2_SMM_SW_SMI_MAX)
			return EFI_OUT_OF_RESOURCES;
		context->sw_smi_input_value = value;
	}
	if (value == 0U || value > CDK2_SMM_SW_SMI_MAX || find_input(value) != NULL)
		return EFI_INVALID_PARAMETER;
	status = smst->allocate_pool(efi_runtime_services_data, sizeof(*entry),
		(void **)&entry);
	if (EFI_ERROR(status) || entry == NULL)
		return EFI_OUT_OF_RESOURCES;
	entry->input = value;
	entry->handler = handler;
	entry->next = handlers;
	handlers = entry;
	*dispatch_handle = entry;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI unregister_handler(
	const struct cdk2_smm_sw_dispatch2_protocol *protocol, void *dispatch_handle)
{
	struct dispatch_context **link;
	struct dispatch_context *entry;
	(void)protocol;
	if (dispatch_handle == NULL || smst == NULL)
		return EFI_INVALID_PARAMETER;
	for (link = &handlers; *link != NULL; link = &(*link)->next) {
		entry = *link;
		if (entry == dispatch_handle) {
			*link = entry->next;
			return smst->free_pool(entry);
		}
	}
	return EFI_INVALID_PARAMETER;
}

static struct cdk2_smm_sw_dispatch2_protocol dispatch_protocol = {
	register_handler, unregister_handler, CDK2_SMM_SW_SMI_MAX
};

static EFI_STATUS CDK2_MS_ABI dispatch_smi(void *dispatch_handle,
	const void *register_context, void *communication_buffer,
	UINTN *communication_buffer_size)
{
	struct cdk2_smm_sw_context sw = {0};
	struct cdk2_smm_sw_register_context child_context;
	struct smm_save_state_io_info io;
	struct dispatch_context *entry;
	UINTN size = sizeof(sw);
	UINTN cpu;
	EFI_STATUS status = EFI_SUCCESS;
	(void)dispatch_handle;
	(void)register_context;
	(void)communication_buffer;
	(void)communication_buffer_size;
	sw.command_port = io_in8(SMM_CONTROL_PORT);
	sw.data_port = io_in8(SMM_DATA_PORT);
	for (cpu = 0; cpu < smst->number_of_cpus; cpu++) {
		if (!EFI_ERROR(smm_cpu->read_save_state(smm_cpu, sizeof(io),
		    SMM_SAVE_STATE_REGISTER_IO, cpu, &io)) && io.io_port == SMM_CONTROL_PORT) {
			sw.sw_smi_cpu_index = cpu;
			break;
		}
	}
	if (sw.command_port != 0U) {
		entry = find_input(sw.command_port);
		if (entry != NULL) {
			child_context.sw_smi_input_value = entry->input;
			status = entry->handler(entry, &child_context, &sw, &size);
		}
	}
	io_out32(apm_status_port, io_in32(apm_status_port) | (UINT32)(1U << apm_status_bit));
	io_out32(eos_port, io_in32(eos_port) | (UINT32)(1U << eos_bit));
	return status;
}

EFI_STATUS CDK2_MS_ABI cdk2_pch_smi_dispatch_entry(void *image,
	struct system_table_view *system)
{
	const struct cdk2_smm_register_info *info;
	const struct cdk2_smm_generic_register *eos;
	const struct cdk2_smm_generic_register *apm_status;
	struct smm_base_protocol *smm_base;
	UINTN payload_size;
	UINTN required;
	EFI_STATUS status;
	(void)image;
	if (system == NULL || system->boot_services == NULL ||
	    system->boot_services->locate_protocol == NULL)
		return EFI_INVALID_PARAMETER;
	info = find_guid_hob(system, &register_info_guid, &payload_size);
	if (info == NULL)
		return EFI_UNSUPPORTED;
	if (payload_size < sizeof(*info) || info->revision != CDK2_SMM_REGISTER_INFO_REVISION ||
	    info->reserved != 0U || info->count == 0U ||
	    info->count > CDK2_SMM_REGISTER_MAX_COUNT)
		return EFI_COMPROMISED_DATA;
	required = sizeof(*info) + (UINTN)info->count * sizeof(info->registers[0]);
	if (required > payload_size)
		return EFI_COMPROMISED_DATA;
	eos = find_register(info, CDK2_SMM_REGISTER_ID_EOS);
	apm_status = find_register(info, CDK2_SMM_REGISTER_ID_APM_STATUS);
	if (!valid_status_register(eos) || !valid_status_register(apm_status))
		return EFI_NOT_FOUND;
	eos_port = (UINT16)eos->address.address;
	eos_bit = eos->address.register_bit_offset;
	apm_status_port = (UINT16)apm_status->address.address;
	apm_status_bit = apm_status->address.register_bit_offset;
	status = system->boot_services->locate_protocol(&smm_base_guid, NULL,
		(void **)&smm_base);
	if (EFI_ERROR(status) || smm_base == NULL || smm_base->get_smst == NULL)
		return EFI_NOT_FOUND;
	status = smm_base->get_smst(smm_base, &smst);
	if (EFI_ERROR(status) || smst == NULL)
		return status;
	status = smst->locate_protocol(&smm_cpu_guid, NULL, (void **)&smm_cpu);
	if (EFI_ERROR(status) || smm_cpu == NULL || smm_cpu->read_save_state == NULL)
		return EFI_NOT_FOUND;
	status = smst->register_smi_handler(dispatch_smi, NULL, &root_dispatch_handle);
	if (EFI_ERROR(status))
		return status;
	return smst->install_protocol(&protocol_handle, &sw_dispatch2_guid,
		EFI_NATIVE_INTERFACE, &dispatch_protocol);
}
