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
	struct cdk2_pcd_context context;
	void *value;
	size_t size;
	uint32_t replacement = 42, token = 0;
	int failures = 0;

	make_fixture(&fixture);
	failures += expect(cdk2_pcd_init(&context, &fixture, sizeof(fixture)) == EFI_SUCCESS,
		"valid version-seven database accepted");
	failures += expect(cdk2_pcd_get(&context, NULL, 2, &value, &size) == EFI_SUCCESS &&
		size == 8 && *(uint64_t *)value == fixture.wide, "native token lookup");
	failures += expect(cdk2_pcd_get(&context, &space, 77, &value, &size) == EFI_SUCCESS &&
		*(uint32_t *)value == fixture.value, "dynamic-ex mapping");
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
