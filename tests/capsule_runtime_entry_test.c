/* SPDX-License-Identifier: GPL-2.0-only */

#include <assert.h>
#include <string.h>
#include <cdk2/capsule_runtime_entry.h>
#include <cdk2/capsule_runtime.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, const EFI_GUID *, void **);

static EFI_STATUS install_status, uninstall_status, event_status[2];
static EFI_STATUS flush_status;
static UINTN installs, uninstalls, converts, events, closes;
static UINTN checks, sets, flushes, variables;
static BOOLEAN runtime_pointer_converted;
static void (CDK2_MS_ABI *notification[2])(void *, void *);
static CHAR16 last_name[32];
static void *expected_runtime;

struct fmp_image_descriptor {
	UINT8 image_index;
	EFI_GUID image_type;
	UINT64 image_id;
	CHAR16 *image_id_name;
	UINT32 version;
	CHAR16 *version_name;
	UINTN size;
	UINT64 attributes_supported, attributes_setting;
	UINT32 compatibilities, lowest_supported_version, last_attempt_version,
		last_attempt_status;
	UINT64 hardware_instance;
	void *dependencies;
};
struct fmp_protocol {
	EFI_STATUS(CDK2_MS_ABI *get_image_info)(void *, UINTN *, void *, UINT32 *,
		UINT8 *, UINTN *, UINT32 *, CHAR16 **);
	void *get_image;
	EFI_STATUS(CDK2_MS_ABI *set_image)(void *, UINT8, const void *, UINTN,
		const void *, void *, CHAR16 **);
	EFI_STATUS(CDK2_MS_ABI *check_image)(void *, UINT8, const void *, UINTN,
		UINT32 *);
	void *get_package_info, *set_package_info;
};
struct fmp_test_body {
	UINT32 version;
	UINT16 embedded_count, payload_count;
	UINT64 offset;
	UINT32 image_version;
	EFI_GUID image_type;
	UINT8 image_index, reserved[3];
	UINT32 image_size, vendor_size;
	UINT64 hardware_instance, capsule_support;
	UINT8 image[4];
} __packed;
struct fmp_test_capsule {
	struct cdk2_capsule_header outer;
	struct fmp_test_body body;
};
static struct fmp_protocol fmp;
static void *fmp_handles[1] = { (void *)9 };
static struct fmp_image_descriptor descriptor;

EFI_STATUS cdk2_capsule_cache_writeback_range_all_cpus(UINT64 address, UINT64 length)
{
	assert(address != 0U && length != 0U);
	flushes++;
	return flush_status;
}

static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{
	(void)type;
	assert(size == sizeof(descriptor));
	*buffer = &descriptor;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{
	assert(buffer != NULL);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI locate_handles(UINT32 type, const EFI_GUID *guid,
	void *key, UINTN *count, void ***buffer)
{
	(void)guid;
	(void)key;
	assert(type == 2U);
	*count = 1;
	*buffer = fmp_handles;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle, const EFI_GUID *guid,
	void **protocol)
{
	(void)guid;
	assert(handle == fmp_handles[0]);
	*protocol = &fmp;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_image_info(void *self, UINTN *size, void *buffer,
	UINT32 *version, UINT8 *count, UINTN *descriptor_size, UINT32 *package,
	CHAR16 **package_name)
{
	(void)self;
	(void)package_name;
	*version = 3U;
	*count = 1U;
	*descriptor_size = sizeof(descriptor);
	*package = 0U;
	if (buffer == NULL) {
		*size = sizeof(descriptor);
		return EFI_BUFFER_TOO_SMALL;
	}
	assert(*size >= sizeof(descriptor));
	memcpy(buffer, &descriptor, sizeof(descriptor));
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI check_image(void *self, UINT8 index,
	const void *image, UINTN size, UINT32 *updatable)
{
	(void)self;
	assert(index == 1U && image != NULL && size == 4U);
	checks++;
	*updatable = 1U;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI set_image(void *self, UINT8 index,
	const void *image, UINTN size, const void *vendor, void *progress,
	CHAR16 **abort_reason)
{
	(void)self;
	(void)vendor;
	(void)progress;
	assert(index == 1U && image != NULL && size == 4U);
	*abort_reason = NULL;
	sets++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI set_variable(CHAR16 *name, EFI_GUID *guid,
	UINT32 attributes, UINTN size, void *data)
{
	UINTN index = 0;

	(void)guid;
	assert(attributes == 7U && size == 8U && data != NULL);
	do {
		last_name[index] = name[index];
	} while (name[index++] != 0);
	variables++;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI crc32(void *table, UINTN size, cdk2_uint32_ptr crc)
{
	(void)table;
	(void)size;
	*crc = 0xabcdef01U;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{
	installs++;
	*handle = (void *)1;
	return install_status;
}
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{
	assert(handle == (void *)1);
	uninstalls++;
	return uninstall_status;
}
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context,
	cdk2_const_guid_ptr group, cdk2_void_ptr_ptr event)
{
	(void)context;
	assert(type == 0x200U && tpl == 16U && group != NULL);
	EFI_STATUS status = event_status[events];

	if (!EFI_ERROR(status)) {
		notification[events] = notify;
		*event = (void *)(events + 2U);
	}
	events++;
	return status;
}
static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{
	assert(event != NULL);
	closes++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI convert_pointer(UINTN disposition, void **pointer)
{
	(void)disposition;
	assert(pointer != NULL);
	if (*pointer == expected_runtime)
		runtime_pointer_converted = TRUE;
	converts++;
	return EFI_SUCCESS;
}

int main(void)
{
	struct cdk2_boot_services_view boot = { 0 };
	struct cdk2_runtime_services_view runtime = { 0 };
	struct cdk2_system_table_view system = { 0 };
	void *old_update = (void *)3, *old_query = (void *)4;
	struct fmp_test_capsule capsule = { 0 };
	struct { UINT64 length, address; } blocks[2];
	const struct cdk2_capsule_header *capsules[1] = { &capsule.outer };
	typedef EFI_STATUS CDK2_MS_ABI update_fn(
		const struct cdk2_capsule_header *const *, UINTN, UINT64);
	typedef EFI_STATUS CDK2_MS_ABI query_fn(
		const struct cdk2_capsule_header *const *, UINTN, UINT64 *, UINT32 *);

	boot.calculate_crc32 = crc32;
	boot.create_event_ex = create_event;
	boot.install_multiple = install;
	boot.uninstall_multiple = uninstall;
	boot.slots_before_locate_protocol[5] = allocate_pool;
	boot.slots_before_locate_protocol[6] = free_pool;
	boot.slots_before_locate_protocol[16] = handle_protocol;
	boot.slots_before_locate_protocol[36] = locate_handles;
	runtime.header.size = sizeof(runtime);
	runtime.header.crc32 = 7U;
	runtime.update_capsule = old_update;
	runtime.query_capsule = old_query;
	runtime.convert_pointer = convert_pointer;
	runtime.set_variable = set_variable;
	system.boot = &boot;
	system.runtime = &runtime;
	expected_runtime = &runtime;
	boot.slots_before_locate_protocol[11] = close_event;
	event_status[0] = EFI_DEVICE_ERROR;
	assert(cdk2_capsule_runtime_entry((void *)5, &system) == EFI_DEVICE_ERROR);
	assert(runtime.update_capsule == old_update && runtime.query_capsule == old_query &&
		runtime.header.crc32 == 7U && installs == 1U && uninstalls == 1U);
	event_status[0] = EFI_SUCCESS;
	install_status = EFI_DEVICE_ERROR;
	assert(cdk2_capsule_runtime_entry((void *)5, &system) == EFI_DEVICE_ERROR);
	assert(uninstalls == 1U && runtime.update_capsule == old_update &&
		runtime.query_capsule == old_query && runtime.header.crc32 == 7U);
	install_status = EFI_SUCCESS;
	events = 0;
	event_status[1] = EFI_DEVICE_ERROR;
	uninstall_status = EFI_DEVICE_ERROR;
	assert(cdk2_capsule_runtime_entry((void *)5, &system) == EFI_DEVICE_ERROR);
	assert(runtime.update_capsule != old_update && runtime.query_capsule != old_query &&
		runtime.header.crc32 == 0xabcdef01U && uninstalls == 2U && closes == 0U);
	/* A coherent retry starts from the original table fixture. */
	runtime.update_capsule = old_update;
	runtime.query_capsule = old_query;
	runtime.header.crc32 = 7U;
	events = 0;
	uninstall_status = EFI_SUCCESS;
	event_status[1] = EFI_SUCCESS;
	assert(cdk2_capsule_runtime_entry((void *)5, &system) == EFI_SUCCESS);
	assert(installs == 4U && runtime.update_capsule != old_update &&
		runtime.query_capsule != old_query && runtime.header.crc32 == 0xabcdef01U);
	fmp.get_image_info = get_image_info;
	fmp.check_image = check_image;
	fmp.set_image = set_image;
	descriptor.image_index = 1U;
	descriptor.image_type = (EFI_GUID) { .data1 = 0x12345678U };
	descriptor.hardware_instance = 7U;
	capsule.outer.guid = (EFI_GUID) { 0x6dcbd5ed, 0xe82d, 0x4c44,
		{ 0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a, 0xd9, 0x2a } };
	capsule.outer.header_size = sizeof(capsule.outer);
	capsule.outer.image_size = sizeof(capsule);
	capsule.body.version = 1U;
	capsule.body.payload_count = 1U;
	capsule.body.offset = 16U;
	capsule.body.image_version = 3U;
	memcpy(&capsule.body.image_type, &descriptor.image_type,
		sizeof(descriptor.image_type));
	capsule.body.image_index = 1U;
	capsule.body.image_size = sizeof(capsule.body.image);
	capsule.body.hardware_instance = 7U;
	blocks[0].length = sizeof(capsule.body.image);
	blocks[0].address = (UINT64)(UINTN)capsule.body.image;
	blocks[1].length = 0U;
	blocks[1].address = 0U;
	assert(((update_fn *)runtime.update_capsule)(capsules, 1U, 0U) == EFI_SUCCESS &&
		checks == 2U && sets == 1U);
	{
		UINT64 maximum = 0;
		UINT32 reset_type = 9U;

		assert(((query_fn *)runtime.query_capsule)(capsules, 1U, &maximum,
			&reset_type) == EFI_SUCCESS && maximum == 0x123400U &&
			reset_type == 0U);
	}
	capsule.body.capsule_support = 4U;
	assert(((query_fn *)runtime.query_capsule)(capsules, 1U,
		&(UINT64) { 0 }, &(UINT32) { 0 }) == EFI_INVALID_PARAMETER);
	capsule.body.capsule_support = 0U;
	capsule.outer.flags = CDK2_CAPSULE_PERSIST;
	flush_status = EFI_DEVICE_ERROR;
	assert(((update_fn *)runtime.update_capsule)(capsules, 1U,
		(UINT64)(UINTN)blocks) == EFI_DEVICE_ERROR && variables == 0U);
	flush_status = EFI_SUCCESS;
	flushes = 0U;
	for (UINTN sequence = 0; sequence < 12U; sequence++)
		assert(((update_fn *)runtime.update_capsule)(capsules, 1U,
			(UINT64)(UINTN)blocks) == EFI_SUCCESS);
	assert(variables == 12U && flushes == 36U && last_name[17] == L'1' &&
		last_name[18] == L'1' && last_name[19] == 0);
	assert(notification[0] != NULL && notification[1] != NULL);
	notification[1]((void *)3, NULL);
	assert(converts == 0U);
	capsule.outer.flags = 0U;
	assert(((update_fn *)runtime.update_capsule)(capsules, 1U, 0U) ==
		EFI_OUT_OF_RESOURCES);
	assert(sets == 1U);
	notification[0]((void *)2, NULL);
	assert(converts == 6U && runtime_pointer_converted);
	return 0;
}
