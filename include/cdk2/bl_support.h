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

struct cdk2_bl_support_ops {
	EFI_STATUS (*set32)(void *, uint32_t, uint32_t);
	EFI_STATUS (*set64)(void *, uint32_t, uint64_t);
	EFI_STATUS (*set_ptr)(void *, uint32_t, const void *, size_t);
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
