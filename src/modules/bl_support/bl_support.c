/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/bl_support.h>
#include <guid/acpi_board_info.h>
#include <guid/graphics_info_hob.h>
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

typedef char graphics_hob_abi_assert[
	offsetof(EFI_PEI_GRAPHICS_INFO_HOB, graphics_mode.horizontal_resolution) == 16 ? 1 : -1];
typedef char board_hob_abi_assert[offsetof(ACPI_BOARD_INFO, pcie_base_address) == 48 ? 1 : -1];
typedef char board_hob_size_assert[sizeof(ACPI_BOARD_INFO) == 72 ? 1 : -1];

static int same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	const uint8_t *a = (const uint8_t *)left, *b = (const uint8_t *)right;
	size_t index;

	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return 0;
	return 1;
}

static EFI_STATUS validate_hobs(const void *list, size_t size, const void **graphics,
	size_t *graphics_size, const void **board, size_t *board_size)
{
	const uint8_t *bytes = list;
	size_t walked = 0;

	if (list == NULL || graphics == NULL || graphics_size == NULL || board == NULL ||
	    board_size == NULL || ((uintptr_t)list & 7U) != 0)
		return EFI_INVALID_PARAMETER;
	*graphics = NULL; *board = NULL;
	while (walked + sizeof(EFI_HOB_GENERIC_HEADER) <= size) {
		const EFI_HOB_GENERIC_HEADER *header = (const void *)(bytes + walked);

		if (header->reserved != 0 || header->hob_length < sizeof(*header) ||
		    (header->hob_length & 7U) != 0 || header->hob_length > size - walked)
			return EFI_COMPROMISED_DATA;
		if (header->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST)
			return header->hob_length == sizeof(*header) && walked + sizeof(*header) == size ?
				EFI_SUCCESS : EFI_COMPROMISED_DATA;
		if (header->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			const EFI_HOB_GUID_TYPE *hob = (const void *)header;

			if (header->hob_length < sizeof(*hob))
				return EFI_COMPROMISED_DATA;
			if (same_guid(&hob->name, &graphics_info_guid) && *graphics == NULL) {
				*graphics = hob + 1; *graphics_size = header->hob_length - sizeof(*hob);
			} else if (same_guid(&hob->name, &board_info_guid) && *board == NULL) {
				*board = hob + 1; *board_size = header->hob_length - sizeof(*hob);
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
	if (policy->wide_cap && policy->cap_width != 0 && policy->cap_height != 0 &&
	    (uint64_t)horizontal * policy->cap_height >
	    (uint64_t)vertical * policy->cap_width) {
		candidate = (uint64_t)vertical * policy->cap_width / policy->cap_height;
		candidate &= ~1ULL;
		if (candidate != 0 && candidate < *viewport_horizontal)
			*viewport_horizontal = (uint32_t)candidate;
	}
	if (!policy->hidpi || horizontal <= policy->threshold_horizontal ||
	    vertical <= policy->threshold_vertical || (*viewport_horizontal & 1U) != 0 ||
	    (*viewport_vertical & 1U) != 0)
		return FALSE;
	*viewport_horizontal /= 2U;
	*viewport_vertical /= 2U;
	return TRUE;
}

EFI_STATUS cdk2_bl_support_apply(const void *hob_list, size_t hob_size,
	const struct cdk2_bl_support_policy *policy,
	const struct cdk2_bl_support_ops *ops)
{
	const EFI_PEI_GRAPHICS_INFO_HOB *graphics;
	const ACPI_BOARD_INFO *board;
	const void *graphics_data, *board_data, *old_ptr;
	size_t graphics_size = 0, board_size = 0, old_ptr_size = 0;
	uint32_t physical_horizontal = 0, physical_vertical = 0;
	uint32_t setup_horizontal = 0, setup_vertical = 0;
	uint32_t old32[4]; uint64_t old64[2]; EFI_GUID old_guid;
	unsigned int committed = 0;
	unsigned int board_index;
	size_t index;
	EFI_STATUS status;

	if (policy == NULL || ops == NULL || ops->get32 == NULL || ops->get64 == NULL ||
	    ops->get_ptr == NULL || ops->get_size == NULL || ops->set32 == NULL ||
	    ops->set64 == NULL || ops->set_ptr == NULL)
		return EFI_INVALID_PARAMETER;
	status = validate_hobs(hob_list, hob_size, &graphics_data, &graphics_size,
		&board_data, &board_size);
	if (EFI_ERROR(status))
		return status;
	graphics = graphics_data; board = board_data;
	if (graphics != NULL) {
		if (graphics_size < sizeof(*graphics) ||
		    graphics->frame_buffer_size == 0 ||
		    graphics->frame_buffer_base + graphics->frame_buffer_size <
		    graphics->frame_buffer_base || graphics->graphics_mode.version != 0 ||
		    graphics->graphics_mode.horizontal_resolution == 0 ||
		    graphics->graphics_mode.vertical_resolution == 0 ||
		    (int)graphics->graphics_mode.pixel_format < 0 ||
		    graphics->graphics_mode.pixel_format >= pixel_format_max ||
		    graphics->graphics_mode.pixels_per_scan_line <
		    graphics->graphics_mode.horizontal_resolution)
			return EFI_COMPROMISED_DATA;
		physical_horizontal = graphics->graphics_mode.horizontal_resolution;
		physical_vertical = graphics->graphics_mode.vertical_resolution;
		(void)cdk2_bl_support_viewport(physical_horizontal, physical_vertical, policy,
			&setup_horizontal, &setup_vertical);
	}
	if (board != NULL) {
		if (board_size < sizeof(*board) || board->reserved0[0] != 0 ||
		    board->reserved0[1] != 0 || board->tpm12_present > 1 ||
		    board->tpm20_present > 1 || board->pcie_base_address + board->pcie_base_size <
		    board->pcie_base_address)
			return EFI_COMPROMISED_DATA;
	}
	if (graphics != NULL) {
		old32[0] = ops->get32(ops->context, TOKEN_VIDEO_HORIZONTAL);
		old32[1] = ops->get32(ops->context, TOKEN_VIDEO_VERTICAL);
		old32[2] = ops->get32(ops->context, TOKEN_SETUP_HORIZONTAL);
		old32[3] = ops->get32(ops->context, TOKEN_SETUP_VERTICAL);
	}
	if (board != NULL) {
		const uint8_t *source;
		uint8_t *destination = (uint8_t *)&old_guid;

		old64[0] = ops->get64(ops->context, TOKEN_PCIE_BASE);
		old64[1] = ops->get64(ops->context, TOKEN_PCIE_SIZE);
		old_ptr_size = ops->get_size(ops->context, TOKEN_TPM_INSTANCE);
		old_ptr = ops->get_ptr(ops->context, TOKEN_TPM_INSTANCE);
		if (old_ptr_size > sizeof(old_guid))
			return EFI_BAD_BUFFER_SIZE;
		if (old_ptr_size != 0 && old_ptr == NULL)
			return EFI_COMPROMISED_DATA;
		source = old_ptr;
		for (index = 0; index < old_ptr_size; index++)
			destination[index] = source[index];
	}
	if (graphics != NULL) {
		status = ops->set32(ops->context, TOKEN_VIDEO_HORIZONTAL, physical_horizontal);
		if (EFI_ERROR(status))
			goto rollback;
		committed++;
		status = ops->set32(ops->context, TOKEN_VIDEO_VERTICAL, physical_vertical);
		if (EFI_ERROR(status))
			goto rollback;
		committed++;
		status = ops->set32(ops->context, TOKEN_SETUP_HORIZONTAL, setup_horizontal);
		if (EFI_ERROR(status))
			goto rollback;
		committed++;
		status = ops->set32(ops->context, TOKEN_SETUP_VERTICAL, setup_vertical);
		if (EFI_ERROR(status))
			goto rollback;
		committed++;
	}
	if (board != NULL) {
		status = ops->set64(ops->context, TOKEN_PCIE_BASE, board->pcie_base_address);
		if (EFI_ERROR(status))
			goto rollback;
		committed++;
		status = ops->set64(ops->context, TOKEN_PCIE_SIZE, board->pcie_base_size);
		if (EFI_ERROR(status))
			goto rollback;
		committed++;
		if (board->tpm12_present)
			status = ops->set_ptr(ops->context, TOKEN_TPM_INSTANCE,
				&tpm12_guid, sizeof(tpm12_guid));
		else if (board->tpm20_present)
			status = ops->set_ptr(ops->context, TOKEN_TPM_INSTANCE,
				&tpm20_guid, sizeof(tpm20_guid));
		if (EFI_ERROR(status))
			goto rollback;
	}
	return EFI_SUCCESS;
rollback:
	/* Best-effort reverse rollback; preserve the original setter failure. */
	while (committed != 0) {
		committed--;
		if (graphics != NULL && committed < 4) {
			static const uint32_t tokens[] = { TOKEN_VIDEO_HORIZONTAL,
				TOKEN_VIDEO_VERTICAL, TOKEN_SETUP_HORIZONTAL, TOKEN_SETUP_VERTICAL };
			(void)ops->set32(ops->context, tokens[committed], old32[committed]);
		} else if (board != NULL && committed < (graphics != NULL ? 6U : 2U)) {
			static const uint32_t tokens[] = { TOKEN_PCIE_BASE, TOKEN_PCIE_SIZE };
			board_index = committed - (graphics != NULL ? 4U : 0U);
			(void)ops->set64(ops->context, tokens[board_index], old64[board_index]);
		}
	}
	return status;
}
