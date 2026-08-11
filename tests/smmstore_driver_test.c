/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

#include <stdio.h>
#include <string.h>

#define BLOCKS 8U
#define BLOCK_SIZE 256U

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
struct system_table_view;
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32, UINTN,
						  event_notify_fn *, void *,
						  const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI convert_pointer_fn(UINTN, void **);
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
struct hob_fixture {
	UINT16 type;
	UINT16 length;
	UINT32 reserved;
	EFI_GUID guid;
	SMMSTORE_INFO info;
	UINT16 end_type;
	UINT16 end_length;
	UINT32 end_reserved;
} __packed;

EFI_STATUS CDK2_MS_ABI cdk2_smmstore_fvb_entry(void *,
					       struct system_table_view *);
const struct cdk2_fvb_protocol *cdk2_smmstore_fvb_protocol(void);

static UINT8 flash[BLOCKS][BLOCK_SIZE];
static UINT8 communication[BLOCK_SIZE];
static UINTN installs;
static UINTN uninstalls;
static UINTN conversions;
static BOOLEAN fail_event;
static event_notify_fn *event_notify;

UINT32 cdk2_smmstore_arch_invoke(UINT8 apm_command, UINT8 command,
				 void *request_buffer)
{
	struct cdk2_smmstore_request *request = request_buffer;

	if (apm_command != 0xedU || request->block >= BLOCKS)
		return 1U;
	if (command == CDK2_SMMSTORE_RAW_CLEAR) {
		memset(flash[request->block], 0xff, BLOCK_SIZE);
		return 0;
	}
	if (request->offset >= BLOCK_SIZE ||
	    request->size > BLOCK_SIZE - request->offset)
		return 1U;
	if (command == CDK2_SMMSTORE_RAW_READ)
		memcpy(communication + request->offset,
		       flash[request->block] + request->offset, request->size);
	else if (command == CDK2_SMMSTORE_RAW_WRITE)
		memcpy(flash[request->block] + request->offset,
		       communication + request->offset, request->size);
	else
		return 1U;
	return 0;
}

static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{
	installs++;
	*handle = (void *)0x1234;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle, ...)
{
	(void)handle;
	uninstalls++;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI create_event_ex(UINT32 type, UINTN tpl,
					      event_notify_fn *notify,
					      void *context,
					      const EFI_GUID *group,
					      void **event)
{
	(void)context;
	(void)group;
	if (type != 0x200U || tpl != 16U)
		return EFI_INVALID_PARAMETER;
	event_notify = notify;
	*event = (void *)0x5678;
	return fail_event ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI convert_pointer(UINTN disposition, void **address)
{
	(void)disposition;
	(void)address;
	conversions++;
	return EFI_SUCCESS;
}

static void make_hob(struct hob_fixture *hob)
{
	static const EFI_GUID info_guid = {
		0xf585ca19U,
		0x881bU,
		0x44fbU,
		{0x3fU, 0x3dU, 0x81U, 0x89U, 0x7cU, 0x57U, 0xbbU, 0x01U}};

	memset(hob, 0, sizeof(*hob));
	hob->type = 4U;
	hob->length = sizeof(*hob) - 8U;
	hob->guid = info_guid;
	hob->info.com_buffer = (UINTN)communication;
	hob->info.com_buffer_size = sizeof(communication);
	hob->info.num_blocks = BLOCKS;
	hob->info.block_size = BLOCK_SIZE;
	hob->info.mmio_address = 0x400000U;
	hob->info.apm_cmd = 0xedU;
	hob->end_type = 0xffffU;
	hob->end_length = 8U;
}

static int expect(BOOLEAN condition, const char *expression, int line)
{
	if (condition)
		return 0;
	fprintf(stderr, "%s:%d: %s\n", __FILE__, line, expression);
	return 1;
}

#define EXPECT(condition)                                                      \
	(failures += expect((condition), #condition, __LINE__))

int main(void)
{
	static const EFI_GUID hob_list_guid = {
		0x7739f24cU,
		0x93d7U,
		0x11d4U,
		{0x9aU, 0x3aU, 0x00U, 0x90U, 0x27U, 0x3fU, 0xc1U, 0x4dU}};
	struct hob_fixture hob;
	struct config_table table;
	struct boot_services_view boot = {0};
	struct runtime_services_view runtime = {0};
	struct system_table_view system = {0};
	UINTN count;
	int failures = 0;

	make_hob(&hob);
	table.guid = hob_list_guid;
	table.table = &hob;
	boot.install_multiple = install_multiple;
	boot.uninstall_multiple = uninstall_multiple;
	boot.create_event_ex = create_event_ex;
	runtime.convert_pointer = convert_pointer;
	system.runtime_services = &runtime;
	system.boot_services = &boot;
	system.table_count = 1U;
	system.tables = &table;
	memset(flash, 0xff, sizeof(flash));
	EXPECT(cdk2_smmstore_fvb_entry((void *)1, &system) == EFI_SUCCESS);
	EXPECT(installs == 1U && event_notify != NULL);
	EXPECT(cdk2_variable_store_validate(
		       (struct cdk2_smmstore
				*)((UINT8 *)cdk2_smmstore_fvb_protocol() +
				   sizeof(struct cdk2_fvb_protocol)),
		       &count) == EFI_SUCCESS);
	event_notify((void *)0x5678, NULL);
	EXPECT(conversions == 10U);
	fail_event = TRUE;
	EXPECT(cdk2_smmstore_fvb_entry((void *)1, &system) == EFI_DEVICE_ERROR);
	EXPECT(uninstalls == 1U);
	system.table_count = 0;
	EXPECT(cdk2_smmstore_fvb_entry((void *)1, &system) == EFI_NOT_FOUND);
	if (failures == 0)
		puts("SMMSTORE runtime driver tests: PASS");
	return failures != 0;
}
