/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <cdk2/capsule_runtime.h>

static EFI_STATUS supported(const struct cdk2_capsule_header *h, void *p)
{
	(void)h;
	(void)p;
	return EFI_SUCCESS;
}
struct trace { UINTN process, persist, writeback, reset; EFI_STATUS error; };
static EFI_STATUS process(const struct cdk2_capsule_header *h, void *p)
{
	(void)h;
	((struct trace *)p)->process++;
	return EFI_SUCCESS;
}
static EFI_STATUS persist(UINTN n, UINT64 sg, void *p)
{
	(void)n;
	(void)sg;
	((struct trace *)p)->persist++;
	return ((struct trace *)p)->error;
}
static EFI_STATUS writeback(UINT64 sg, void *p)
{
	(void)sg;
	((struct trace *)p)->writeback++;
	return ((struct trace *)p)->error;
}
static void warm_reset(void *p)
{
	((struct trace *)p)->reset++;
}

int main(void)
{
	struct cdk2_capsule_policy p = { 4096, 8192, TRUE, TRUE, FALSE };
	struct cdk2_capsule_header h = { .header_size = sizeof(h), .image_size = sizeof(h) };
	const struct cdk2_capsule_header *a[] = { &h };
	UINT64 max = 0; UINT32 reset = 0; BOOLEAN need, initiate;
	struct trace t = {0};
	struct cdk2_capsule_runtime r = { .context = &t, .process = process,
		.persist = persist, .writeback = writeback, .warm_reset = warm_reset };

	assert(cdk2_capsule_query(a, 0, &p, supported, 0, &max, &reset) == EFI_INVALID_PARAMETER);
	h.flags = CDK2_CAPSULE_POPULATE;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_INVALID_PARAMETER);
	h.flags = CDK2_CAPSULE_PERSIST | CDK2_CAPSULE_POPULATE;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_SUCCESS &&
		max == 8192 && reset == 1U);
	assert(cdk2_capsule_preflight(a, 1, 0, FALSE, &p, supported, 0, &need, &initiate) == EFI_INVALID_PARAMETER);
	h.flags = 0;
	assert(cdk2_capsule_preflight(a, 1, 1, TRUE, &p, supported, 0, &need, &initiate) == EFI_OUT_OF_RESOURCES);
	h.image_size = sizeof(h) - 1;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_INVALID_PARAMETER);
	h.image_size = sizeof(h); h.flags = CDK2_CAPSULE_PERSIST | CDK2_CAPSULE_RESET;
	assert(cdk2_capsule_update(&r, a, 1, 1, &p, supported) == EFI_SUCCESS);
	assert(r.sequence == 1 && t.persist == 1 && t.writeback == 1 && t.reset == 1);
	t.error = EFI_DEVICE_ERROR;
	assert(cdk2_capsule_update(&r, a, 1, 1, &p, supported) == EFI_DEVICE_ERROR);
	assert(r.sequence == 1 && t.reset == 1 && t.persist == 1);
	t.error = EFI_SUCCESS; h.flags = BIT19;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_INVALID_PARAMETER);
	h.guid = (EFI_GUID) { 0x6dcbd5ed, 0xe82d, 0x4c44,
		{ 0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a, 0xd9, 0x2a } };
	h.flags = CDK2_CAPSULE_PERSIST | CDK2_CAPSULE_POPULATE;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) ==
		EFI_INVALID_PARAMETER);
	h.guid = (EFI_GUID) { 0 };
	h.flags = 0;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_SUCCESS &&
		max == 4096 && reset == 0U);
	h.image_size = 4097U;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) ==
		EFI_OUT_OF_RESOURCES);
	h.image_size = sizeof(h);
	{
		struct cdk2_capsule_header deferred = h;
		const struct cdk2_capsule_header *mixed[] = { &h, &deferred };
		deferred.flags = CDK2_CAPSULE_PERSIST;
		assert(cdk2_capsule_update(&r, mixed, 2, 1, &p, supported) == EFI_SUCCESS);
		assert(t.process == 0 && t.persist == 2);
	}
	r.exited_boot_services = TRUE;
	assert(cdk2_capsule_update(&r, a, 1, 0, &p, supported) == EFI_OUT_OF_RESOURCES);
	return 0;
}
