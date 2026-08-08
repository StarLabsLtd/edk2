/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_CAPSULE_RUNTIME_H
#define CDK2_CAPSULE_RUNTIME_H

#include <uefi.h>

#define CDK2_CAPSULE_PERSIST  BIT16
#define CDK2_CAPSULE_POPULATE BIT17
#define CDK2_CAPSULE_RESET    BIT18

struct cdk2_capsule_header {
	EFI_GUID guid;
	UINT32 header_size;
	UINT32 flags;
	UINT32 image_size;
};

struct cdk2_capsule_policy {
	UINT64 max_nonpopulate;
	UINT64 max_populate;
	BOOLEAN in_ram;
	BOOLEAN persist;
	BOOLEAN process_at_runtime;
};

typedef EFI_STATUS (*cdk2_capsule_support_fn)(const struct cdk2_capsule_header *, void *);

EFI_STATUS cdk2_capsule_query(const struct cdk2_capsule_header *const *capsules,
	UINTN count, const struct cdk2_capsule_policy *policy,
	cdk2_capsule_support_fn support, void *context, UINT64 *maximum_size,
	UINT32 *reset_type);
EFI_STATUS cdk2_capsule_preflight(const struct cdk2_capsule_header *const *capsules,
	UINTN count, UINT64 scatter_gather, BOOLEAN at_runtime,
	const struct cdk2_capsule_policy *policy, cdk2_capsule_support_fn support,
	void *context, BOOLEAN *needs_reset, BOOLEAN *initiate_reset);

#endif
