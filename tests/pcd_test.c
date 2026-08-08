/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pcd.h>

#include <stdio.h>
#include <string.h>

static const EFI_GUID signature = {
	0x3c7d193c, 0x682c, 0x4c14, { 0xa6, 0x8f, 0x55, 0x2d, 0xea, 0x4f, 0x43, 0x7e }
};
static const EFI_GUID space = {
	0x12345678, 0xabcd, 0xef01, { 1, 2, 3, 4, 5, 6, 7, 8 }
};
static unsigned callbacks;
static unsigned installs, uninstalls;
static uint64_t second_install_status;
static struct cdk2_pcd_protocol *published_native;
static struct fixture *raw_fixture;
static size_t raw_fixture_size;
static uint8_t variable_data[16];
static unsigned variable_writes, variable_locks;

static uint64_t CDK2_MS_ABI mock_get_variable(const uint16_t *name,
	const EFI_GUID *guid, uint32_t *attributes, size_t *size, void *data)
{
	(void)name;
	(void)guid;
	(void)attributes;
	if (*size < sizeof(variable_data))
		return EFI_BUFFER_TOO_SMALL;
	memcpy(data, variable_data, sizeof(variable_data));
	*size = sizeof(variable_data);
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
struct system_view {
	uint8_t header[24];
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6], *runtime;
	struct cdk2_pcd_boot_services *boot;
};

static uint64_t CDK2_MS_ABI mock_read_section(void *self, const EFI_GUID *file,
	uint8_t type, size_t instance, void **buffer, size_t *size, uint32_t *auth)
{
	(void)self;
	(void)file;
	if (type != 0x19 || instance != 0)
		return EFI_NOT_FOUND;
	*buffer = raw_fixture;
	*size = raw_fixture_size;
	*auth = 0;
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
	fixture->header.size_offset = fixture->header.sku_offset =
		fixture->header.name_offset = sizeof(*fixture);
	fixture->header.local_token_count = fixture->header.guid_count = 1;
	fixture->local = 0x84000000U | offsetof(struct hii_fixture, head);
	fixture->guid = space;
	fixture->head.default_offset = offsetof(struct hii_fixture, default_value);
	fixture->head.variable_offset = 4;
	fixture->head.attributes = 7;
	fixture->head.property = 1;
	fixture->name[0] = 'X';
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
	struct cdk2_pcd_context context;
	struct cdk2_pcd_boot_services boot_services;
	struct system_view system;
	void *value;
	size_t size;
	uint32_t replacement = 42, token = 0;
	uint8_t vpd[16] = { 0 };
	int failures = 0;

	make_fixture(&fixture);
	memset(&boot_services, 0, sizeof(boot_services));
	boot_services.install_multiple_protocols = mock_install;
	boot_services.uninstall_multiple_protocols = mock_uninstall;
	boot_services.handle_protocol = mock_handle;
	memset(&system, 0, sizeof(system));
	system.boot = &boot_services;
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"valid version-seven database accepted");
	failures += expect(cdk2_pcd_get(&context, NULL, 2, &value, &size) == EFI_SUCCESS &&
		size == 8 && *(uint64_t *)value == fixture.wide, "native token lookup");
	failures += expect(cdk2_pcd_get(&context, &space, 77, &value, &size) == EFI_SUCCESS &&
		*(uint32_t *)value == fixture.value, "dynamic-ex mapping");
	make_fixture(&pei);
	pei.value = 0x10203040;
	failures += expect(cdk2_pcd_merge_hob(&context, &pei, sizeof(pei)) == EFI_SUCCESS &&
		fixture.value == pei.value, "validated PEI HOB DynamicEx state merged");
	failures += expect(cdk2_pcd_register(&context, &space, 77, changed) == EFI_SUCCESS,
		"callback registration");
	size = sizeof(replacement);
	failures += expect(cdk2_pcd_set(&context, &space, 77, &replacement, &size) == EFI_SUCCESS &&
		fixture.value == replacement && callbacks == 1, "callback precedes mutation");
	failures += expect(cdk2_pcd_unregister(&context, &space, 77, changed) == EFI_SUCCESS,
		"callback cancellation");
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
	/* Restore the ordinary fixture for publication ABI checks. */
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"base database restored");
	second_install_status = EFI_SUCCESS;
	failures += expect(cdk2_pcd_publish(&context, &boot_services) == EFI_SUCCESS &&
		installs == 2 && published_native != NULL &&
		published_native->get32(1) == replacement,
		"four exact protocol interfaces published and callable");
	installs = uninstalls = 0;
	second_install_status = EFI_OUT_OF_RESOURCES;
	failures += expect(cdk2_pcd_publish(&context, &boot_services) ==
		EFI_OUT_OF_RESOURCES && installs == 2 && uninstalls == 1,
		"second publication failure rolls back first pair");
	installs = uninstalls = 0;
	second_install_status = EFI_SUCCESS;
	raw_fixture = &fixture;
	raw_fixture_size = sizeof(fixture);
	failures += expect(cdk2_pcd_driver_entry((void *)1, &system) == EFI_SUCCESS &&
		installs == 2, "entry acquires authenticated RAW section and publishes");
	make_hii(&hii);
	memset(variable_data, 0, sizeof(variable_data));
	variable_data[4] = 0x78;
	failures += expect(cdk2_pcd_init(&context, &hii, sizeof(hii)) == EFI_SUCCESS &&
		cdk2_pcd_configure_storage(&context, mock_get_variable, mock_set_variable,
			NULL, 0) == EFI_SUCCESS &&
		cdk2_pcd_get(&context, NULL, 1, &value, &size) == EFI_SUCCESS &&
		size == 4 && *(uint32_t *)value == 0x78,
		"HII datum read through runtime variable backend");
	size = 4;
	failures += expect(cdk2_pcd_set(&context, NULL, 1, &replacement, &size) ==
		EFI_SUCCESS && variable_writes == 1 && variable_data[4] == replacement,
		"HII write preserves variable envelope");
	failures += expect(cdk2_pcd_lock_read_only(&context, mock_lock_variable) ==
		EFI_SUCCESS && variable_locks == 1, "read-only HII variable policy locked");
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

	make_fixture(&bad);
	bad.header.signature.data1++;
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) != EFI_SUCCESS,
		"bad signature rejected");
	make_fixture(&bad);
	bad.header.local_tokens_offset = UINT32_MAX;
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) != EFI_SUCCESS,
		"overflowing table rejected");
	make_fixture(&bad);
	bad.local[0] = 0x04000000U | (sizeof(bad) - 1);
	failures += expect(cdk2_pcd_init(&context, &bad, sizeof(bad)) != EFI_SUCCESS,
		"truncated datum rejected");
	return failures == 0 ? 0 : 1;
}
