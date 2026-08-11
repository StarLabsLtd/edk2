/* SPDX-License-Identifier: GPL-2.0-only */

#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <cdk2/ftw_entry.h>
#include <guid/smmstore_info.h>

#define BLOCK_SIZE 128U
struct hob_header {
	UINT16 type, length;
	UINT32 reserved;
};
struct guid_hob {
	struct hob_header header;
	EFI_GUID name;
};
struct hob_list {
	struct guid_hob hob;
	SMMSTORE_INFO info;
	struct hob_header end;
};

static struct cdk2_boot_services_view boot;
static struct cdk2_ftw_system_table_view system;
static struct cdk2_config_table_view configuration;
static struct hob_list hobs;
static struct cdk2_fvb_protocol_view fvb;
static UINT8 media[8][BLOCK_SIZE], scratch[512], workspace[BLOCK_SIZE];
static void *handles[1] = { (void *)0x1234 };
static void (CDK2_MS_ABI * notification)(void *, void *);
static EFI_STATUS runtime_status, handles_status, event_status, register_status;
static EFI_STATUS read_status, install_status;
static UINTN allocations, allocation_fail_at, frees, closes, installs;

static void set_slot(UINTN offset, void *function)
{
	*(void **)((UINT8 *)&boot + offset) = function;
}
static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{
	(void)type;
	allocations++;
	if (allocations == allocation_fail_at)
		return EFI_OUT_OF_RESOURCES;
	if (allocations == 1U && size == sizeof(scratch))
		*buffer = scratch;
	else if (allocations == 2U && size == sizeof(workspace))
		*buffer = workspace;
	else
		return EFI_OUT_OF_RESOURCES;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{
	assert(buffer != NULL);
	frees++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
					   void (CDK2_MS_ABI *notify)(void *, void *), void *context, void **event)
{
	(void)context;
	assert(type == 0x200U && tpl == 8U);
	notification = notify;
	*event = (void *)0x55;
	return event_status;
}
static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{
	assert(event == (void *)0x55);
	closes++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI register_notify(const EFI_GUID *guid, void *event,
					      void **registration)
{
	assert(guid != NULL && event == (void *)0x55);
	*registration = (void *)0x66;
	return register_status;
}
static EFI_STATUS CDK2_MS_ABI locate_protocol(const EFI_GUID *guid, void *registration,
					      void **protocol)
{
	(void)guid;
	(void)registration;
	*protocol = (void *)1;
	return runtime_status;
}
static EFI_STATUS CDK2_MS_ABI locate_handles(UINT32 search, const EFI_GUID *guid,
					     void *key, UINTN *count, void ***buffer)
{
	(void)guid;
	(void)key;
	assert(search == 2U);
	*count = 1;
	*buffer = handles;
	return handles_status;
}
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle, const EFI_GUID *guid,
					      void **protocol)
{
	(void)guid;
	assert(handle == handles[0]);
	*protocol = &fvb;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI install_protocol(void **handle, const EFI_GUID *guid,
					       UINT32 type, void *protocol)
{
	(void)guid;
	(void)type;
	assert(protocol != NULL);
	installs++;
	*handle = (void *)0x77;
	return install_status;
}
static EFI_STATUS CDK2_MS_ABI get_address(void *self, UINT64 *base)
{
	assert(self == &fvb);
	*base = 0xff800000ULL;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_block(void *self, UINT64 lba, UINTN *size,
					UINTN *count)
{
	assert(self == &fvb && lba < 8U);
	*size = BLOCK_SIZE;
	*count = 8U - lba;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI read_block(void *self, UINT64 lba, UINTN offset,
					 UINTN *bytes, void *buffer)
{
	assert(self == &fvb && lba < 8U && offset + *bytes <= BLOCK_SIZE);
	if (EFI_ERROR(read_status))
		return read_status;
	memcpy(buffer, media[lba] + offset, *bytes);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI write_block(void *self, UINT64 lba, UINTN offset,
					  UINTN *bytes, const void *buffer)
{
	assert(self == &fvb && lba < 8U && offset + *bytes <= BLOCK_SIZE);
	memcpy(media[lba] + offset, buffer, *bytes);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI erase_blocks(void *self, ...)
{
	va_list args;
	UINT64 lba;
	UINTN count;
	assert(self == &fvb);
	va_start(args, self);
	lba = va_arg(args, UINT64);
	count = va_arg(args, UINTN);
	va_end(args);
	assert(lba + count <= 8U);
	memset(media[lba], 0xff, count * BLOCK_SIZE);
	return EFI_SUCCESS;
}

static void prepare(void)
{
	static const EFI_GUID hob_guid = { 0x7739f24c, 0x93d7, 0x11d4,
		{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
	};
	static const EFI_GUID info_guid = { 0xf585ca19, 0x881b, 0x44fb,
		{ 0x3f, 0x3d, 0x81, 0x89, 0x7c, 0x57, 0xbb, 0x01 }
	};
	memset(&boot, 0, sizeof(boot));
	memset(&system, 0, sizeof(system));
	memset(&hobs, 0, sizeof(hobs));
	memset(media, 0xff, sizeof(media));
	memset(&fvb, 0, sizeof(fvb));
	cdk2_ftw_entry_reset_for_test();
	runtime_status = EFI_SUCCESS;
	handles_status = EFI_SUCCESS;
	event_status = EFI_SUCCESS;
	register_status = EFI_SUCCESS;
	read_status = EFI_SUCCESS;
	install_status = EFI_SUCCESS;
	allocations = allocation_fail_at = frees = closes = installs = 0;
	notification = NULL;
	set_slot(64U, allocate_pool);
	set_slot(72U, free_pool);
	set_slot(80U, create_event);
	set_slot(112U, close_event);
	set_slot(128U, install_protocol);
	set_slot(152U, handle_protocol);
	set_slot(168U, register_notify);
	set_slot(312U, locate_handles);
	boot.locate_protocol = locate_protocol;
	fvb.get_physical_address = get_address;
	fvb.get_block_size = get_block;
	fvb.read = read_block;
	fvb.write = write_block;
	fvb.erase_blocks = erase_blocks;
	hobs.hob.header.type = 4U;
	hobs.hob.header.length = sizeof(hobs.hob) + sizeof(hobs.info);
	hobs.hob.name = info_guid;
	hobs.info.num_blocks = 8U;
	hobs.info.block_size = BLOCK_SIZE;
	hobs.info.mmio_address = 0xff800000ULL;
	hobs.end.type = 0xffffU;
	hobs.end.length = sizeof(hobs.end);
	configuration.guid = hob_guid;
	configuration.table =  &hobs;
	system.boot =  &boot;
	system.table_count = 1U;
	system.tables =  &configuration;
}

int main(void)
{
	prepare();
	system.table_count = 0;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_NOT_FOUND);
	prepare();
	runtime_status = EFI_NOT_FOUND;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_NOT_READY && notification == NULL);
	prepare();
	handles_status = EFI_NOT_FOUND;
	register_status = EFI_DEVICE_ERROR;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_DEVICE_ERROR && closes == 1U);
	prepare();
	allocation_fail_at = 1U;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_OUT_OF_RESOURCES && frees == 1U);
	prepare();
	allocation_fail_at = 2U;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_OUT_OF_RESOURCES && frees == 2U);
	prepare();
	read_status = EFI_DEVICE_ERROR;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_DEVICE_ERROR && frees == 3U);
	prepare();
	install_status = EFI_DEVICE_ERROR;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_DEVICE_ERROR && frees == 3U);
	prepare();
	handles_status = EFI_NOT_FOUND;
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_SUCCESS && notification != NULL);
	handles_status = EFI_SUCCESS;
	notification((void *)0x55, NULL);
	assert(installs == 1U && closes == 1U && media[3][0] == 0x2bU);
	prepare();
	assert(cdk2_ftw_entry((void *)1, &system) == EFI_SUCCESS && installs == 1U);
	return 0;
}
