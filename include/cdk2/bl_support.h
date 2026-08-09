/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_BL_SUPPORT_H_
#define CDK2_BL_SUPPORT_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

struct cdk2_bl_support_policy {
	BOOLEAN hidpi;
	BOOLEAN wide_cap;
	uint32_t threshold_horizontal;
	uint32_t threshold_vertical;
	uint32_t cap_width;
	uint32_t cap_height;
};

typedef uint32_t cdk2_bl_get32(void *context, uint32_t token);
typedef uint64_t cdk2_bl_get64(void *context, uint32_t token);
typedef const void *cdk2_bl_get_ptr(void *context, uint32_t token);
typedef size_t cdk2_bl_get_size(void *context, uint32_t token);
typedef EFI_STATUS cdk2_bl_set32(void *context, uint32_t token, uint32_t value);
typedef EFI_STATUS cdk2_bl_set64(void *context, uint32_t token, uint64_t value);
typedef EFI_STATUS cdk2_bl_set_ptr(void *context, uint32_t token,
	const void *value, size_t size);

struct cdk2_bl_support_ops {
	cdk2_bl_get32 *get32;
	cdk2_bl_get64 *get64;
	cdk2_bl_get_ptr *get_ptr;
	cdk2_bl_get_size *get_size;
	cdk2_bl_set32 *set32;
	cdk2_bl_set64 *set64;
	cdk2_bl_set_ptr *set_ptr;
	void *context;
};

BOOLEAN cdk2_bl_support_viewport(uint32_t horizontal, uint32_t vertical,
	const struct cdk2_bl_support_policy *policy, uint32_t *viewport_horizontal,
	uint32_t *viewport_vertical);
EFI_STATUS cdk2_bl_support_apply(const void *hob_list, size_t hob_size,
	const struct cdk2_bl_support_policy *policy,
	const struct cdk2_bl_support_ops *ops);
EFI_STATUS CDK2_MS_ABI cdk2_bl_support_entry(void *image_handle,
	void *system_table);

#endif
