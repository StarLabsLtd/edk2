/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <cdk2/capsule_runtime.h>

static EFI_STATUS supported(const struct cdk2_capsule_header *h, void *p)
{
	(void)h; (void)p; return EFI_SUCCESS;
}

int main(void)
{
	struct cdk2_capsule_policy p = { 4096, 8192, TRUE, TRUE, FALSE };
	struct cdk2_capsule_header h = { .header_size = sizeof(h), .image_size = sizeof(h) };
	const struct cdk2_capsule_header *a[] = { &h };
	UINT64 max = 0; UINT32 reset = 0; BOOLEAN need, initiate;

	assert(cdk2_capsule_query(a, 0, &p, supported, 0, &max, &reset) == EFI_INVALID_PARAMETER);
	h.flags = CDK2_CAPSULE_POPULATE;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_INVALID_PARAMETER);
	h.flags = CDK2_CAPSULE_PERSIST | CDK2_CAPSULE_POPULATE;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_SUCCESS && max == 8192);
	assert(cdk2_capsule_preflight(a, 1, 0, FALSE, &p, supported, 0, &need, &initiate) == EFI_INVALID_PARAMETER);
	h.flags = 0;
	assert(cdk2_capsule_preflight(a, 1, 1, TRUE, &p, supported, 0, &need, &initiate) == EFI_OUT_OF_RESOURCES);
	h.image_size = sizeof(h) - 1;
	assert(cdk2_capsule_query(a, 1, &p, supported, 0, &max, &reset) == EFI_INVALID_PARAMETER);
	return 0;
}
