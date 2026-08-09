/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pcd.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const EFI_GUID signature = {
	0x3c7d193c, 0x682c, 0x4c14, { 0xa6, 0x8f, 0x55, 0x2d, 0xea, 0x4f, 0x43, 0x7e }
};
static const EFI_GUID space = {
	0x12345678, 0xabcd, 0xef01, { 1, 2, 3, 4, 5, 6, 7, 8 }
};
static const EFI_GUID module_space = {
	0xa1aff049, 0xfdeb, 0x442a, { 0xb3, 0x20, 0x13, 0xab, 0x4c, 0xb7, 0x2b, 0xbc }
};
static const EFI_GUID hob_list = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID pcd_hob = {
	0xea296d92, 0x0b69, 0x423c, { 0x8c, 0x28, 0x33, 0xb4, 0xe0, 0xa9, 0x12, 0x68 }
};
static unsigned int callbacks;
static unsigned int installs, uninstalls;
static uint64_t second_install_status;
static struct cdk2_pcd_protocol *published_native;
static struct cdk2_get_pcd_info_protocol *published_info;
static struct fixture *raw_fixture;
static size_t raw_fixture_size;
static uint8_t variable_data[8192];
static size_t variable_return_size = sizeof(variable_data);
static unsigned int variable_writes, variable_locks;
static uint64_t allocation_status;
static unsigned int allocations, frees;
static uint32_t section_authentication;
static unsigned int policy_registrations;
static int expose_policy;
static cdk2_pcd_event_notify_fn *policy_notify;
static void *policy_notify_context;
static unsigned int event_closes;

static uint64_t CDK2_MS_ABI mock_create_event(uint32_t type, size_t tpl,
	cdk2_pcd_event_notify_fn *notify, void *context, void **event)
{
	(void)type;
	(void)tpl;
	policy_notify = notify;
	policy_notify_context = context;
	*event = (void *)3;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_close_event(void *event)
{
	(void)event;
	event_closes++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_register_notify(const EFI_GUID *guid,
	void *event, void **registration)
{
	(void)guid;
	(void)event;
	*registration = (void *)4;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_register_policy(const void *policy)
{
	const uint8_t *bytes = policy;
	uint16_t size, name_offset;

	memcpy(&size, bytes + 4, sizeof(size));
	memcpy(&name_offset, bytes + 6, sizeof(name_offset));
	if (size <= name_offset || bytes[40] != 1U)
		return EFI_INVALID_PARAMETER;
	policy_registrations++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_locate(const EFI_GUID *guid, void *registration,
	void **interface)
{
	static struct { uint64_t revision; void *disable, *enabled;
		uint64_t (CDK2_MS_ABI *register_policy)(const void *); } policy = {
			0x20000U, NULL, NULL, mock_register_policy
		};
	(void)guid;
	(void)registration;
	if (!expose_policy)
		return EFI_NOT_FOUND;
	*interface = &policy;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_get_variable(const uint16_t *name,
	const EFI_GUID *guid, uint32_t *attributes, size_t *size, void *data)
{
	(void)name;
	(void)guid;
	(void)attributes;
	if (*size < variable_return_size) {
		*size = variable_return_size;
		return EFI_BUFFER_TOO_SMALL;
	}
	memcpy(data, variable_data, variable_return_size);
	*size = variable_return_size;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_set_variable(const uint16_t *name,
	const EFI_GUID *guid, uint32_t attributes, size_t size, const void *data)
{
	(void)name;
	(void)guid;
	(void)attributes;
	if (size > sizeof(variable_data))
		return EFI_INVALID_PARAMETER;
	memcpy(variable_data, data, size);
	variable_writes++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_lock_variable(const uint16_t *name,
	const EFI_GUID *guid)
{
	(void)name;
	(void)guid;
	variable_locks++;
	return EFI_SUCCESS;
}

struct fv_view {
	void *unused[3];
	uint64_t (CDK2_MS_ABI *read_section)(void *, const EFI_GUID *, uint8_t,
		size_t, void **, size_t *, uint32_t *);
};
struct config_view { EFI_GUID guid; void *table; };
struct system_view {
	uint8_t header[24];
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6], *runtime;
	struct cdk2_pcd_boot_services *boot;
	size_t table_count;
	struct config_view *tables;
};
struct runtime_view {
	uint8_t header[24];
	void *time_services[6];
	cdk2_pcd_get_variable_fn *get_variable;
	void *get_next_variable_name;
	cdk2_pcd_set_variable_fn *set_variable;
};

static uint64_t CDK2_MS_ABI mock_read_section(void *self, const EFI_GUID *file,
	uint8_t type, size_t instance, void **buffer, size_t *size, uint32_t *auth)
{
	(void)self;
	(void)file;
	if (type != 0x19 || instance != 0)
		return EFI_NOT_FOUND;
	*buffer = malloc(raw_fixture_size);
	assert(*buffer != NULL);
	memcpy(*buffer, raw_fixture, raw_fixture_size);
	*size = raw_fixture_size;
	*auth = section_authentication;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_allocate(uint32_t type, size_t size, void **buffer)
{
	(void)type;
	allocations++;
	if (allocation_status != EFI_SUCCESS)
		return allocation_status;
	*buffer = calloc(1, size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_free(void *buffer)
{
	free(buffer);
	frees++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_handle(void *handle, const EFI_GUID *guid,
	void **interface)
{
	static struct { uint32_t revision, pad; void *parent, *system, *device; }
		loaded = { 0, 0, NULL, NULL, (void *)2 };
	static struct fv_view fv = { { NULL, NULL, NULL }, mock_read_section };
	(void)guid;
	if (handle == (void *)1)
		*interface = &loaded;
	else if (handle == (void *)2)
		*interface = &fv;
	else
		return EFI_NOT_FOUND;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_install(void **handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)guid;
	*handle = (void *)1;
	installs++;
	if (installs == 1)
		published_native = interface;
	if (installs == 2)
		published_info = interface;
	return installs == 2 ? second_install_status : EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_uninstall(void *handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)handle;
	(void)guid;
	(void)interface;
	uninstalls++;
	return EFI_SUCCESS;
}

static void CDK2_MS_ABI changed(const EFI_GUID *guid, uint32_t token,
	void *value, size_t size)
{
	callbacks += guid == &space && token == 77 && value != NULL && size == 4;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "pcd test: %s\n", message);
	return condition ? 0 : 1;
}

struct fixture {
	struct cdk2_pcd_database_header header;
	uint64_t sku[2];
	uint32_t local[2];
	struct cdk2_pcd_ex_map map;
	EFI_GUID guid;
	uint32_t value;
	uint64_t wide;
};

struct pcd_hob_fixture {
	struct { uint16_t type, length; uint32_t reserved; } header;
	EFI_GUID guid;
	struct fixture database;
	struct { uint16_t type, length; uint32_t reserved; } end;
};

struct delta_fixture {
	struct fixture base;
	uint64_t sku, compared;
	uint32_t length, delta;
};

struct hii_fixture {
	struct cdk2_pcd_database_header header;
	uint32_t local;
	EFI_GUID guid;
	struct { uint32_t string_index, default_offset; uint16_t guid_index,
		variable_offset; uint32_t attributes; uint16_t property, reserved; } head;
	uint32_t default_value;
	uint16_t name[2];
};

struct pointer_fixture {
	struct cdk2_pcd_database_header header;
	uint32_t local[3];
	uint32_t scalar[2];
	uint32_t string_head;
	uint8_t string[16];
	uint16_t sizes[2];
};

struct ex_fixture {
	struct cdk2_pcd_database_header header;
	uint64_t sku;
	uint32_t local[3];
	struct cdk2_pcd_ex_map map[3];
	EFI_GUID guid[2];
	uint32_t value[3];
};

struct hii_pointer_fixture {
	struct cdk2_pcd_database_header header;
	uint32_t local;
	EFI_GUID guid;
	struct { uint32_t string_index, default_offset; uint16_t guid_index,
		variable_offset; uint32_t attributes; uint16_t property, reserved; } head;
	uint8_t defaults[16];
	uint16_t name[2];
	uint16_t sizes[2];
};

struct name_fixture {
	struct cdk2_pcd_database_header header;
	uint32_t local, value;
	struct { uint32_t space, name; } names[1];
	char strings[32];
};

static void make_name(struct name_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->header.signature = signature;
	fixture->header.build_version = CDK2_PCD_SERVICE_VERSION;
	fixture->header.length = fixture->header.length_all_skus = sizeof(*fixture);
	fixture->header.local_tokens_offset = offsetof(struct name_fixture, local);
	fixture->header.sku_offset = fixture->header.local_tokens_offset;
	fixture->header.ex_map_offset = fixture->header.guid_offset =
		offsetof(struct name_fixture, names);
	fixture->header.name_offset = offsetof(struct name_fixture, names);
	fixture->header.string_offset = offsetof(struct name_fixture, strings);
	fixture->header.size_offset = sizeof(*fixture);
	fixture->header.local_token_count = 1;
	fixture->local = 0x04000000U | offsetof(struct name_fixture, value);
	memcpy(fixture->strings, "gPkg\0Token", 11);
	fixture->names[0].space = 0;
	fixture->names[0].name = 5;
}

static void make_pointer(struct pointer_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->header.signature = signature;
	fixture->header.build_version = CDK2_PCD_SERVICE_VERSION;
	fixture->header.length = fixture->header.length_all_skus = sizeof(*fixture);
	fixture->header.local_tokens_offset = offsetof(struct pointer_fixture, local);
	fixture->header.ex_map_offset = fixture->header.guid_offset =
		fixture->header.name_offset = sizeof(*fixture);
	fixture->header.sku_offset = fixture->header.local_tokens_offset;
	fixture->header.string_offset = offsetof(struct pointer_fixture, string);
	fixture->header.size_offset = offsetof(struct pointer_fixture, sizes);
	fixture->header.local_token_count = 3;
	fixture->local[0] = 0x04000000U | offsetof(struct pointer_fixture, scalar[0]);
	fixture->local[1] = 0x04000000U | offsetof(struct pointer_fixture, scalar[1]);
	fixture->local[2] = 0x10000000U | offsetof(struct pointer_fixture, string_head);
	fixture->sizes[0] = fixture->sizes[1] = sizeof(fixture->string);
}

static void make_hii(struct hii_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->header.signature = signature;
	fixture->header.build_version = CDK2_PCD_SERVICE_VERSION;
	fixture->header.length = fixture->header.length_all_skus = sizeof(*fixture);
	fixture->header.local_tokens_offset = offsetof(struct hii_fixture, local);
	fixture->header.ex_map_offset = offsetof(struct hii_fixture, guid);
	fixture->header.guid_offset = offsetof(struct hii_fixture, guid);
	fixture->header.string_offset = offsetof(struct hii_fixture, name);
	fixture->header.size_offset = fixture->header.name_offset = sizeof(*fixture);
	fixture->header.sku_offset = fixture->header.local_tokens_offset;
	fixture->header.local_token_count = fixture->header.guid_count = 1;
	fixture->local = 0x84000000U | offsetof(struct hii_fixture, head);
	fixture->guid = space;
	fixture->head.default_offset = offsetof(struct hii_fixture, default_value);
	fixture->head.variable_offset = 4;
	fixture->head.attributes = 7;
	fixture->head.property = 1;
	fixture->name[0] = 'X';
}

static void make_hii_pointer(struct hii_pointer_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->header.signature = signature;
	fixture->header.build_version = CDK2_PCD_SERVICE_VERSION;
	fixture->header.length = fixture->header.length_all_skus = sizeof(*fixture);
	fixture->header.local_tokens_offset = offsetof(struct hii_pointer_fixture, local);
	fixture->header.ex_map_offset = fixture->header.guid_offset =
		offsetof(struct hii_pointer_fixture, guid);
	fixture->header.string_offset = offsetof(struct hii_pointer_fixture, name);
	fixture->header.size_offset = offsetof(struct hii_pointer_fixture, sizes);
	fixture->header.sku_offset = fixture->header.local_tokens_offset;
	fixture->header.name_offset = sizeof(*fixture);
	fixture->header.local_token_count = fixture->header.guid_count = 1;
	fixture->local = 0x90000000U | offsetof(struct hii_pointer_fixture, head);
	fixture->head.default_offset = offsetof(struct hii_pointer_fixture, defaults);
	fixture->head.variable_offset = 32;
	fixture->head.attributes = 7;
	fixture->name[0] = 'P';
	fixture->sizes[0] = fixture->sizes[1] = sizeof(fixture->defaults);
}

static void make_ex(struct ex_fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->header.signature = signature;
	fixture->header.build_version = CDK2_PCD_SERVICE_VERSION;
	fixture->header.length = fixture->header.length_all_skus = sizeof(*fixture);
	fixture->header.sku_offset = offsetof(struct ex_fixture, sku);
	fixture->header.local_tokens_offset = offsetof(struct ex_fixture, local);
	fixture->header.ex_map_offset = offsetof(struct ex_fixture, map);
	fixture->header.guid_offset = offsetof(struct ex_fixture, guid);
	fixture->header.string_offset = fixture->header.size_offset =
		fixture->header.name_offset = sizeof(*fixture);
	fixture->header.local_token_count = fixture->header.ex_token_count = 3;
	fixture->header.guid_count = 2;
	fixture->local[0] = 0x04000000U | offsetof(struct ex_fixture, value[0]);
	fixture->local[1] = 0x04000000U | offsetof(struct ex_fixture, value[1]);
	fixture->local[2] = 0x04000000U | offsetof(struct ex_fixture, value[2]);
	fixture->map[0] = (struct cdk2_pcd_ex_map){ 100, 1, 0 };
	fixture->map[1] = (struct cdk2_pcd_ex_map){ 50, 2, 0 };
	fixture->map[2] = (struct cdk2_pcd_ex_map){ 10, 3, 0 };
	fixture->guid[0] = space;
	fixture->guid[1] = (EFI_GUID){ 0xdeadbeef, 1, 2, { 3 } };
}

static void make_fixture(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->header.signature = signature;
	fixture->header.build_version = CDK2_PCD_SERVICE_VERSION;
	fixture->header.length = sizeof(*fixture);
	fixture->header.length_all_skus = sizeof(*fixture);
	fixture->header.sku_offset = offsetof(struct fixture, sku);
	fixture->header.local_tokens_offset = offsetof(struct fixture, local);
	fixture->header.ex_map_offset = offsetof(struct fixture, map);
	fixture->header.guid_offset = offsetof(struct fixture, guid);
	fixture->header.string_offset = sizeof(*fixture);
	fixture->header.size_offset = sizeof(*fixture);
	fixture->header.name_offset = sizeof(*fixture);
	fixture->header.local_token_count = 2;
	fixture->header.ex_token_count = 1;
	fixture->header.guid_count = 1;
	fixture->sku[0] = 0;
	fixture->sku[1] = 9;
	fixture->local[0] = 0x04000000U | offsetof(struct fixture, value);
	fixture->local[1] = 0x08000000U | offsetof(struct fixture, wide);
	fixture->map.external_token = 77;
	fixture->map.local_token = 1;
	fixture->guid = space;
	fixture->value = 0xaabbccdd;
	fixture->wide = 0x1122334455667788ULL;
}

int main(void)
{
	struct fixture fixture, bad;
	struct fixture pei;
	struct delta_fixture delta_fixture;
	struct hii_fixture hii;
	struct hii_pointer_fixture hii_pointer;
	struct pointer_fixture pointer;
	struct ex_fixture ex;
	struct name_fixture named;
	struct cdk2_pcd_context context;
	struct cdk2_pcd_boot_services boot_services;
	struct system_view system;
	struct runtime_view runtime;
	struct pcd_hob_fixture production_hob;
	struct config_view config;
	void *value;
	size_t size;
	uint32_t replacement = 42, token = 0;
	struct cdk2_pcd_info info;
	const EFI_GUID *next_space;
	EFI_GUID copied_space;
	uint8_t vpd[16] = { 0 };
	int failures = 0;

	make_fixture(&fixture);
	memset(&boot_services, 0, sizeof(boot_services));
	boot_services.install_multiple_protocols = mock_install;
	boot_services.uninstall_multiple_protocols = mock_uninstall;
	boot_services.handle_protocol = mock_handle;
	boot_services.locate_protocol = mock_locate;
	boot_services.allocate_pool = mock_allocate;
	boot_services.free_pool = mock_free;
	boot_services.create_event = mock_create_event;
	boot_services.close_event = mock_close_event;
	boot_services.register_protocol_notify = mock_register_notify;
	memset(&system, 0, sizeof(system));
	system.boot = &boot_services;
	memset(&runtime, 0, sizeof(runtime));
	runtime.get_variable = mock_get_variable;
	runtime.set_variable = mock_set_variable;
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"valid version-seven database accepted");
	failures += expect(cdk2_pcd_get(&context, NULL, 2, &value, &size) == EFI_SUCCESS &&
		size == 8 && *(uint64_t *)value == fixture.wide, "native token lookup");
	failures += expect(cdk2_pcd_get(&context, &space, 77, &value, &size) == EFI_SUCCESS &&
		*(uint32_t *)value == fixture.value, "dynamic-ex mapping");
	failures += expect(cdk2_pcd_get_info(&context, NULL, 2, &info.pcd_type,
		&info.pcd_size) == EFI_SUCCESS && info.pcd_type == 3 && info.pcd_size == 8,
		"GetInfo reports the actual UINT64 datum type");
	make_name(&named);
	failures += expect(cdk2_pcd_init(&context, &named, sizeof(named)) == EFI_SUCCESS,
		"generated-name fixture initialized");
	context.allocate_pool = mock_allocate;
	context.free_pool = mock_free;
	info.pcd_name = NULL;
	failures += expect(cdk2_pcd_get_name(&context, NULL, 1, &info.pcd_name) ==
		EFI_SUCCESS && strcmp(info.pcd_name, "gPkg.Token") == 0,
		"generated token-space and pcd names are returned");
	(void)mock_free(info.pcd_name);
	make_ex(&ex);
	failures += expect(cdk2_pcd_init(&context, &ex, sizeof(ex)) == EFI_SUCCESS,
		"unordered DynamicEx fixture accepted");
	token = 0;
	failures += expect(cdk2_pcd_next_token(&context, &space, &token) == EFI_SUCCESS &&
		token == 10, "DynamicEx iteration selects lowest succeeding token");
	token = 0;
	failures += expect(cdk2_pcd_next_token(&context, NULL, &token) == EFI_NOT_FOUND,
		"default iteration excludes DynamicEx-only tokens");
	make_pointer(&pointer);
	failures += expect(cdk2_pcd_init(&context, &pointer, sizeof(pointer)) == EFI_SUCCESS &&
		cdk2_pcd_get(&context, NULL, 3, &value, &size) == EFI_SUCCESS && size == 16,
		"compact size table indexes only preceding pointer tokens");
	size = 16;
	failures += expect(cdk2_pcd_set(&context, NULL, 3, &space, &size) == EFI_SUCCESS &&
		memcmp(pointer.string, &space, sizeof(space)) == 0,
		"late pointer token accepts its generated maximum size");
	size = 8;
	failures += expect(cdk2_pcd_set(&context, NULL, 3, &space, &size) == EFI_SUCCESS &&
		pointer.sizes[1] == 8, "pointer mutation updates compact current size");
	pointer.string_head = UINT32_MAX;
	failures += expect(cdk2_pcd_get(&context, NULL, 3, &value, &size) ==
		EFI_INVALID_PARAMETER, "overflowing pointer string index rejected");
	pointer.string_head = 0;
	size = 17;
	failures += expect(cdk2_pcd_set(&context, NULL, 3, &space, &size) ==
		EFI_INVALID_PARAMETER && size == 16, "oversized pointer reports generated maximum");
	/* Dynamic data may occupy the generated database's zero-filled tail. */
	make_fixture(&bad);
	bad.header.length = bad.header.length_all_skus = offsetof(struct fixture, value);
	bad.header.uninitialized_size = sizeof(bad) - offsetof(struct fixture, value);
	bad.header.string_offset = bad.header.size_offset = bad.header.name_offset =
		bad.header.length;
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) == EFI_SUCCESS &&
		cdk2_pcd_get(&context, NULL, 2, &value, &size) == EFI_SUCCESS &&
		size == sizeof(bad.wide), "uninitialized dynamic datum uses full capacity");
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"ordinary fixture restored after uninitialized-tail check");
	make_fixture(&pei);
	pei.value = 0x10203040;
	failures += expect(cdk2_pcd_merge_hob(&context, &pei, sizeof(pei)) == EFI_SUCCESS &&
		fixture.value == pei.value, "validated PEI HOB DynamicEx state merged");
	make_fixture(&fixture);
	make_fixture(&pei);
	fixture.map.local_token = pei.map.local_token = 2;
	pei.value = 0x31415926U;
	pei.wide = 0x8877665544332211ULL;
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS &&
		cdk2_pcd_merge_hob(&context, &pei, sizeof(pei)) == EFI_SUCCESS &&
		fixture.value == pei.value && fixture.wide == pei.wide,
		"PEI HOB merges default-space and DynamicEx state");
	make_fixture(&fixture);
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"ordinary fixture restored after PEI merge coverage");
	failures += expect(cdk2_pcd_register(&context, &space, 77, changed) == EFI_SUCCESS,
		"callback registration");
	size = sizeof(replacement);
	failures += expect(cdk2_pcd_set(&context, &space, 77, &replacement, &size) == EFI_SUCCESS &&
		fixture.value == replacement && callbacks == 1, "callback precedes mutation");
	failures += expect(cdk2_pcd_unregister(&context, &space, 77, changed) == EFI_SUCCESS,
		"callback cancellation");
	copied_space = space;
	failures += expect(cdk2_pcd_register(&context, &copied_space, 77, changed) ==
		EFI_SUCCESS, "callback owns an equal token-space GUID value");
	copied_space.data1++;
	size = sizeof(replacement);
	failures += expect(cdk2_pcd_set(&context, &space, 77, &replacement, &size) ==
		EFI_SUCCESS && callbacks == 2 &&
		cdk2_pcd_unregister(&context, &space, 77, changed) == EFI_SUCCESS,
		"callback survives caller GUID lifetime and cancels by value");
	token = 0;
	failures += expect(cdk2_pcd_next_token(&context, NULL, &token) == EFI_SUCCESS && token == 1,
		"native iteration starts at token one");
	failures += expect(cdk2_pcd_set_sku(&context, 9) == EFI_SUCCESS &&
		fixture.header.system_sku_id == 9, "supported SKU selected once");
	failures += expect(cdk2_pcd_set_sku(&context, 0) != EFI_SUCCESS,
		"SKU cannot change after selection");
	memset(&delta_fixture, 0, sizeof(delta_fixture));
	make_fixture(&delta_fixture.base);
	delta_fixture.base.header.length_all_skus = sizeof(delta_fixture);
	delta_fixture.sku = 7;
	delta_fixture.length = 24;
	delta_fixture.delta = ((uint32_t)0x5a << 24) |
		offsetof(struct fixture, value);
	failures += expect(cdk2_pcd_init(&context, &delta_fixture,
		sizeof(delta_fixture)) == EFI_SUCCESS &&
		cdk2_pcd_apply_sku_delta(&context, 7) == EFI_SUCCESS &&
		(delta_fixture.base.value & 0xff) == 0x5a,
		"bounded generated SKU delta applied");
	make_fixture(&delta_fixture.base);
	delta_fixture.base.header.length_all_skus = sizeof(delta_fixture);
	delta_fixture.sku = 7;
	delta_fixture.length = 24;
	delta_fixture.delta = ((uint32_t)0x6b << 24) |
		offsetof(struct fixture, value);
	failures += expect(cdk2_pcd_init(&context, &delta_fixture,
		sizeof(delta_fixture)) == EFI_SUCCESS, "SKU protocol fixture initialized");
	installs = uninstalls = 0;
	second_install_status = EFI_SUCCESS;
	failures += expect(cdk2_pcd_publish(&context, &boot_services) == EFI_SUCCESS,
		"SKU protocol fixture published");
	published_native->set_sku(7);
	failures += expect((delta_fixture.base.value & 0xff) == 0x6b &&
		delta_fixture.base.header.system_sku_id == 7,
		"SetSku protocol applies the selected SKU delta");
	delta_fixture.base.header.system_sku_id = 9;
	delta_fixture.base.value = 0xaabbccddU;
	published_native->set_sku(7);
	failures += expect(delta_fixture.base.value == 0xaabbccddU &&
		delta_fixture.base.header.system_sku_id == 9,
		"SetSku rejects reselection before mutating delta bytes");
	/* Restore the ordinary fixture for publication ABI checks. */
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"base database restored");
	installs = uninstalls = 0;
	second_install_status = EFI_SUCCESS;
	failures += expect(cdk2_pcd_publish(&context, &boot_services) == EFI_SUCCESS &&
		installs == 2 && published_native != NULL &&
		published_native->get32(1) == replacement,
		"four exact protocol interfaces published and callable");
	failures += expect(published_info != NULL &&
		published_info->get_info(2, &info) == EFI_SUCCESS && info.pcd_type == 3,
		"published GetInfo reports UINT64 rather than the zero enum");
#if SIZE_MAX > UINT32_MAX
	failures += expect(published_native->get32((size_t)UINT32_MAX + 2U) == 0 &&
		published_native->set32((size_t)UINT32_MAX + 2U, 1) == EFI_INVALID_PARAMETER &&
		published_native->callback_on_set(NULL, (size_t)UINT32_MAX + 2U, changed) ==
		EFI_INVALID_PARAMETER &&
		published_info->get_info((size_t)UINT32_MAX + 2U, &info) ==
		EFI_INVALID_PARAMETER,
		"protocol wrappers reject tokens before UINT32 narrowing");
#endif
	make_ex(&ex);
	failures += expect(cdk2_pcd_init(&context, &ex, sizeof(ex)) == EFI_SUCCESS,
		"token-space fixture restored");
	installs = 0;
	failures += expect(cdk2_pcd_publish(&context, &boot_services) == EFI_SUCCESS,
		"token-space fixture published");
	next_space = NULL;
	failures += expect(published_native->get_next_token_space(&next_space) ==
		EFI_SUCCESS && next_space != NULL && memcmp(next_space, &space,
		sizeof(space)) == 0 && published_native->get_next_token_space(&next_space) ==
		EFI_NOT_FOUND, "token spaces derive only from distinct DynamicEx map GUIDs");
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"base database restored after token-space fixture");
	installs = uninstalls = 0;
	second_install_status = EFI_OUT_OF_RESOURCES;
	failures += expect(cdk2_pcd_publish(&context, &boot_services) ==
		EFI_OUT_OF_RESOURCES && installs == 2 && uninstalls == 1,
		"second publication failure rolls back first pair");
	installs = uninstalls = 0;
	second_install_status = EFI_SUCCESS;
	raw_fixture = &fixture;
	raw_fixture_size = sizeof(fixture);
	allocations = frees = 0;
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) == EFI_SUCCESS &&
		installs == 2 && allocations == 1 && frees == 1,
		"entry expands authenticated RAW section and publishes");
	memset(&production_hob, 0, sizeof(production_hob));
	production_hob.header.type = 4;
	production_hob.header.length = offsetof(struct pcd_hob_fixture, end);
	production_hob.guid = pcd_hob;
	make_fixture(&production_hob.database);
	production_hob.database.value = 0x55667788U;
	production_hob.end.type = 0xffffU;
	production_hob.end.length = sizeof(production_hob.end);
	config.guid = hob_list;
	config.table = &production_hob;
	system.table_count = 1;
	system.tables = &config;
	installs = 0;
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) == EFI_SUCCESS &&
		((uint32_t (CDK2_MS_ABI *)(const EFI_GUID *, size_t))
		 published_native->get_ex[2])(&space, 77) == production_hob.database.value,
		"production entry merges the pei pcd database guid hob");
	system.table_count = 0;
	system.tables = NULL;
	allocations = frees = 0;
	allocation_status = EFI_OUT_OF_RESOURCES;
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) ==
		EFI_OUT_OF_RESOURCES && allocations == 1 && frees == 1,
		"entry frees RAW section when database expansion fails");
	allocation_status = EFI_SUCCESS;
	section_authentication = 1U;
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) == EFI_SUCCESS,
		"non-failure authentication metadata accepted");
	section_authentication = 8U;
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) ==
		EFI_SECURITY_VIOLATION, "authentication test-failure bit rejected");
	section_authentication = 0;
	make_hii(&hii);
	memset(variable_data, 0, sizeof(variable_data));
	variable_data[4] = 0x39;
	raw_fixture = (struct fixture *)&hii;
	raw_fixture_size = sizeof(hii);
	system.runtime = &runtime;
	installs = 0;
	expose_policy = 1;
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) == EFI_SUCCESS &&
		published_native->get32(1) == 0x39 && policy_registrations == 1,
		"driver entry wires production runtime HII variable services before publication");
	expose_policy = 0;
	policy_registrations = event_closes = 0;
	policy_notify = NULL;
	make_hii(&hii);
	raw_fixture = (struct fixture *)&hii;
	raw_fixture_size = sizeof(hii);
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) == EFI_SUCCESS &&
		policy_notify != NULL && policy_registrations == 0,
		"driver defers read-only locks until VariablePolicy is installed");
	expose_policy = 1;
	policy_notify((void *)3, policy_notify_context);
	failures += expect(policy_registrations == 1 && event_closes == 1,
		"VariablePolicy notification locks HII variables and closes itself");
	expose_policy = 0;
	make_fixture(&fixture);
	fixture.map.external_token = 0x00030006U;
	fixture.map.local_token = 1;
	fixture.guid = module_space;
	fixture.local[0] = 0x08000000U | offsetof(struct fixture, value);
	fixture.local[1] = 0x44000000U | offsetof(struct fixture, wide);
	{
		uint64_t address = (uintptr_t)vpd;
		uint32_t vpd_offset = 3;
		memcpy(&fixture.value, &address, sizeof(address));
		memcpy(&fixture.wide, &vpd_offset, sizeof(vpd_offset));
	}
	vpd[3] = 0x7c;
	raw_fixture = &fixture;
	raw_fixture_size = sizeof(fixture);
	installs = 0;
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) == EFI_SUCCESS &&
		published_native->get32(2) == 0x7c,
		"driver entry wires the generated VPD base before publication");
	system.runtime = NULL;
	make_hii(&hii);
	memset(variable_data, 0, sizeof(variable_data));
	variable_data[4] = 0x78;
	variable_data[sizeof(variable_data) - 1] = 0xa5;
	failures += expect(cdk2_pcd_init(&context, &hii, sizeof(hii)) == EFI_SUCCESS,
		"HII fixture initialized");
	context.allocate_pool = mock_allocate;
	context.free_pool = mock_free;
	(void)cdk2_pcd_configure_storage(&context, mock_get_variable, mock_set_variable,
		NULL, 0);
	{
		uint64_t hii_status = cdk2_pcd_get(&context, NULL, 1, &value, &size);
		failures += expect(hii_status == EFI_SUCCESS && size == 4 &&
			*(uint32_t *)value == 0x78,
		"HII datum read through runtime variable backend");
	}
	size = 4;
	failures += expect(cdk2_pcd_set(&context, NULL, 1, &replacement, &size) ==
		EFI_SUCCESS && variable_writes == 1 && variable_data[4] == replacement &&
		variable_data[sizeof(variable_data) - 1] == 0xa5,
		"HII write preserves a variable envelope larger than 4 KiB");
	failures += expect(cdk2_pcd_lock_read_only(&context, mock_lock_variable) ==
		EFI_SUCCESS && variable_locks == 1, "read-only HII variable policy locked");
	make_hii_pointer(&hii_pointer);
	memset(variable_data, 0, sizeof(variable_data));
	memcpy(variable_data + hii_pointer.head.variable_offset, &space, sizeof(space));
	failures += expect(cdk2_pcd_init(&context, &hii_pointer,
		sizeof(hii_pointer)) == EFI_SUCCESS, "HII pointer fixture initialized");
	context.allocate_pool = mock_allocate;
	context.free_pool = mock_free;
	(void)cdk2_pcd_configure_storage(&context, mock_get_variable,
		mock_set_variable, NULL, 0);
	{
		uint64_t pointer_status = cdk2_pcd_get(&context, NULL, 1, &value, &size);
		failures += expect(pointer_status == EFI_SUCCESS && size == sizeof(space) &&
			memcmp(value, &space, sizeof(space)) == 0,
		"HII pointer uses compact current size and variable storage");
	}
	size = sizeof(space);
	failures += expect(cdk2_pcd_set(&context, NULL, 1, &signature, &size) ==
		EFI_SUCCESS && memcmp(variable_data + hii_pointer.head.variable_offset,
		&signature, sizeof(signature)) == 0 &&
		hii_pointer.sizes[1] == sizeof(signature),
		"HII pointer records its compact current size");
	memset(variable_data, 0xa5, sizeof(variable_data));
	variable_return_size = 8;
	context.variable_capacity = 16;
	allocations = 0;
	size = sizeof(signature);
	failures += expect(cdk2_pcd_set(&context, NULL, 1, &signature, &size) ==
		EFI_SUCCESS && allocations == 1 && variable_data[8] == 0 &&
		variable_data[31] == 0,
		"HII variable extension grows storage and zeroes the preserved gap");
	if (context.variable != context.variable_inline)
		(void)mock_free(context.variable);
	variable_return_size = sizeof(variable_data);
	make_hii(&hii);
	hii.local = 0x44000000U | offsetof(struct hii_fixture, head);
	*(uint32_t *)&hii.head = 3;
	vpd[3] = 0xef;
	failures += expect(cdk2_pcd_init(&context, &hii, sizeof(hii)) == EFI_SUCCESS &&
		cdk2_pcd_configure_storage(&context, NULL, NULL, vpd, sizeof(vpd)) ==
		EFI_SUCCESS && cdk2_pcd_get(&context, NULL, 1, &value, &size) == EFI_SUCCESS &&
		*(uint32_t *)value == 0xef, "VPD datum resolves against bounded VPD window");
	size = 4;
	failures += expect(cdk2_pcd_set(&context, NULL, 1, &replacement, &size) !=
		EFI_SUCCESS, "VPD mutation rejected");
	make_hii_pointer(&hii_pointer);
	hii_pointer.local = 0x50000000U | offsetof(struct hii_pointer_fixture, head);
	hii_pointer.head.string_index = 3;
	hii_pointer.sizes[1] = 8;
	memcpy(vpd + 3, &space, 8);
	failures += expect(cdk2_pcd_init(&context, &hii_pointer,
		sizeof(hii_pointer)) == EFI_SUCCESS &&
		cdk2_pcd_configure_storage(&context, NULL, NULL, vpd, sizeof(vpd)) ==
		EFI_SUCCESS && cdk2_pcd_get(&context, NULL, 1, &value, &size) ==
		EFI_SUCCESS && size == 8 && memcmp(value, &space, size) == 0,
		"VPD pointer uses compact size metadata and bounded VPD storage");
	make_hii_pointer(&hii_pointer);
	hii_pointer.head.string_index = 1;
	failures += expect(cdk2_pcd_init(&context, &hii_pointer,
		sizeof(hii_pointer)) == EFI_SUCCESS &&
		cdk2_pcd_get(&context, NULL, 1, &value, &size) == EFI_INVALID_PARAMETER,
		"misaligned HII variable name is rejected");
	make_hii(&hii);
	hii.name[0] = 'X';
	hii.name[1] = 'Y';
	failures += expect(cdk2_pcd_init(&context, &hii, sizeof(hii)) == EFI_SUCCESS &&
		cdk2_pcd_get(&context, NULL, 1, &value, &size) == EFI_INVALID_PARAMETER,
		"unterminated HII variable name is rejected within database bounds");
	make_hii_pointer(&hii_pointer);
	hii_pointer.name[0] = 'X';
	hii_pointer.sizes[0] = hii_pointer.sizes[1] = 0xffffU;
	failures += expect(cdk2_pcd_init(&context, &hii_pointer,
		offsetof(struct hii_pointer_fixture, sizes)) == EFI_INVALID_PARAMETER,
		"combined HII pointer requires a complete four-byte header");

	make_fixture(&bad);
	bad.local[0] |= 0x20000000U;
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) == EFI_SUCCESS &&
		cdk2_pcd_get(&context, NULL, 1, &value, &size) == EFI_SUCCESS &&
		*(uint32_t *)value == bad.value,
		"SKU-enabled flag is excluded from the storage offset");
	make_fixture(&bad);
	bad.header.signature.data1++;
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) != EFI_SUCCESS,
		"bad signature rejected");
	make_fixture(&bad);
	bad.header.local_tokens_offset = UINT32_MAX;
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) != EFI_SUCCESS,
		"overflowing table rejected");
	make_fixture(&bad);
	bad.header.sku_offset = bad.header.local_tokens_offset + sizeof(uint64_t);
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) != EFI_SUCCESS,
		"SKU table ordering rejected before unsigned subtraction");
	make_fixture(&bad);
	bad.local[0] = 0x04000000U | (sizeof(bad) - 1);
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) != EFI_SUCCESS,
		"truncated datum rejected");
	return failures == 0 ? 0 : 1;
}
