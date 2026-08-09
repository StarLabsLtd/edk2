/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/bl_support.h>
#include <pi/hob.h>

#define TOKEN_SETUP_HORIZONTAL 23U
#define TOKEN_SETUP_VERTICAL 24U
#define TOKEN_VIDEO_HORIZONTAL 29U
#define TOKEN_VIDEO_VERTICAL 30U
#define TOKEN_PCIE_BASE 33U
#define TOKEN_PCIE_SIZE 34U
#define TOKEN_TPM_INSTANCE 47U

static const EFI_GUID graphics_info_guid = {
	0x39f62cce, 0x6825, 0x4669, { 0xbb, 0x56, 0x54, 0x1a, 0xba, 0x75, 0x3a, 0x07 }
};
static const EFI_GUID board_info_guid = {
	0x0ad3d31b, 0xb3d8, 0x4506, { 0xae, 0x71, 0x2e, 0xf1, 0x10, 0x06, 0xd9, 0x0f }
};
static const EFI_GUID tpm12_guid = {
	0x8b01e5b6, 0x4f19, 0x46e8, { 0xab, 0x93, 0x1c, 0x53, 0x67, 0x1b, 0x90, 0xcc }
};
static const EFI_GUID tpm20_guid = {
	0x286bf25a, 0xc2c3, 0x408c, { 0xb3, 0xb4, 0x25, 0xe6, 0x75, 0x8b, 0x73, 0x17 }
};

struct graphics_info {
	uint64_t framebuffer_base;
	uint32_t framebuffer_size;
	uint32_t version;
	uint32_t horizontal;
	uint32_t vertical;
};

struct board_info {
	uint8_t revision, reserved[2], reset_value;
	uint64_t pm_evt_base, pm_gpe_en_base, pm_ctrl_reg_base, pm_timer_reg_base;
	uint64_t reset_reg_address, pcie_base, pcie_size;
	uint8_t tpm20_present, tpm12_present;
};

static int same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	const uint8_t *a = (const uint8_t *)left, *b = (const uint8_t *)right;
	size_t index;

	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return 0;
	return 1;
}

static EFI_STATUS find_guid_hob(const void *list, size_t size,
	const EFI_GUID *guid, const void **data, size_t *data_size)
{
	const uint8_t *bytes = list;
	size_t walked = 0;

	if (list == NULL || guid == NULL || data == NULL || data_size == NULL)
		return EFI_INVALID_PARAMETER;
	while (walked + sizeof(EFI_HOB_GENERIC_HEADER) <= size) {
		const EFI_HOB_GENERIC_HEADER *header = (const void *)(bytes + walked);

		if (header->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST)
			return EFI_NOT_FOUND;
		if (header->hob_length < sizeof(*header) || header->hob_length > size - walked)
			return EFI_COMPROMISED_DATA;
		if (header->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			const EFI_HOB_GUID_TYPE *hob = (const void *)header;

			if (header->hob_length < sizeof(*hob))
				return EFI_COMPROMISED_DATA;
			if (same_guid(&hob->name, guid)) {
				*data = hob + 1;
				*data_size = header->hob_length - sizeof(*hob);
				return EFI_SUCCESS;
			}
		}
		walked += header->hob_length;
	}
	return EFI_COMPROMISED_DATA;
}

BOOLEAN cdk2_bl_support_viewport(uint32_t horizontal, uint32_t vertical,
	const struct cdk2_bl_support_policy *policy, uint32_t *viewport_horizontal,
	uint32_t *viewport_vertical)
{
	uint64_t candidate;

	if (policy == NULL || viewport_horizontal == NULL || viewport_vertical == NULL ||
	    horizontal == 0 || vertical == 0)
		return FALSE;
	*viewport_horizontal = horizontal;
	*viewport_vertical = vertical;
	if (!policy->hidpi || horizontal < policy->threshold_horizontal ||
	    vertical < policy->threshold_vertical || (horizontal & 1U) != 0 ||
	    (vertical & 1U) != 0)
		return FALSE;
	if (policy->wide_cap && policy->cap_width != 0 && policy->cap_height != 0 &&
	    (uint64_t)horizontal * policy->cap_height >
	    (uint64_t)vertical * policy->cap_width) {
		candidate = (uint64_t)vertical * policy->cap_width / policy->cap_height;
		candidate &= ~1ULL;
		if (candidate != 0 && candidate < horizontal)
			horizontal = (uint32_t)candidate;
	}
	*viewport_horizontal = horizontal / 2U;
	*viewport_vertical = vertical / 2U;
	return TRUE;
}

EFI_STATUS cdk2_bl_support_apply(const void *hob_list, size_t hob_size,
	const struct cdk2_bl_support_policy *policy,
	const struct cdk2_bl_support_ops *ops)
{
	const struct graphics_info *graphics;
	const struct board_info *board;
	const void *data;
	size_t size;
	uint32_t horizontal, vertical;
	EFI_STATUS status;

	if (policy == NULL || ops == NULL || ops->set32 == NULL || ops->set64 == NULL ||
	    ops->set_ptr == NULL)
		return EFI_INVALID_PARAMETER;
	status = find_guid_hob(hob_list, hob_size, &graphics_info_guid, &data, &size);
	if (status == EFI_SUCCESS) {
		if (size < sizeof(*graphics))
			return EFI_COMPROMISED_DATA;
		graphics = data;
		horizontal = graphics->horizontal;
		vertical = graphics->vertical;
		(void)cdk2_bl_support_viewport(horizontal, vertical, policy,
			&horizontal, &vertical);
		status = ops->set32(ops->context, TOKEN_VIDEO_HORIZONTAL, horizontal);
		if (!EFI_ERROR(status))
			status = ops->set32(ops->context, TOKEN_VIDEO_VERTICAL, vertical);
		if (!EFI_ERROR(status))
			status = ops->set32(ops->context, TOKEN_SETUP_HORIZONTAL, horizontal);
		if (!EFI_ERROR(status))
			status = ops->set32(ops->context, TOKEN_SETUP_VERTICAL, vertical);
		if (EFI_ERROR(status))
			return status;
	} else if (status != EFI_NOT_FOUND) {
		return status;
	}
	status = find_guid_hob(hob_list, hob_size, &board_info_guid, &data, &size);
	if (status == EFI_SUCCESS) {
		if (size < sizeof(*board))
			return EFI_COMPROMISED_DATA;
		board = data;
		status = ops->set64(ops->context, TOKEN_PCIE_BASE, board->pcie_base);
		if (!EFI_ERROR(status))
			status = ops->set64(ops->context, TOKEN_PCIE_SIZE, board->pcie_size);
		if (!EFI_ERROR(status) && board->tpm12_present)
			status = ops->set_ptr(ops->context, TOKEN_TPM_INSTANCE,
				&tpm12_guid, sizeof(tpm12_guid));
		else if (!EFI_ERROR(status) && board->tpm20_present)
			status = ops->set_ptr(ops->context, TOKEN_TPM_INSTANCE,
				&tpm20_guid, sizeof(tpm20_guid));
		return status;
	}
	return status == EFI_NOT_FOUND ? EFI_SUCCESS : status;
}
