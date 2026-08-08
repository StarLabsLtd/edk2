/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter.h>
#include <stdio.h>

static UINTN reads[2], resets;
static UINTN notifications;
static EFI_STATUS notified(struct cdk2_split_key_data *key)
{
	notifications++;
	return key->key.unicode == L'K' ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}
static EFI_STATUS read_key(void *context, struct cdk2_split_key *key)
{
	UINTN index = (UINTN)context - 1U;
	reads[index]++;
	if (index == 0U && reads[index] == 1U)
		return EFI_SUCCESS;
	if (index == 0U)
		return EFI_NOT_READY;
	key->unicode = L'K';
	return EFI_SUCCESS;
}
static EFI_STATUS reset(void *context, BOOLEAN extended)
{ (void)context; (void)extended; resets++; return resets == 2U ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS pointer_state(void *context, struct cdk2_split_pointer_state *state)
{
	UINTN index = (UINTN)context;
	*state = (struct cdk2_split_pointer_state) {
		.x = (INT32)(index * 10U), .y = (INT32)index, .left = index == 1U,
		.right = index == 2U
	};
	return EFI_SUCCESS;
}
static EFI_STATUS absolute_state(void *context, struct cdk2_split_absolute_state *state)
{
	(void)context;
	*state = (struct cdk2_split_absolute_state) { 50U, 25U, 0U, 3U };
	return EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "con splitter input test: %s\n", message); return !condition; }

int main(void)
{
	struct cdk2_split_text_in text = { 0 };
	struct cdk2_split_key key;
	struct cdk2_split_key_data key_data = { 0 };
	struct cdk2_split_key_data match = { .key = { 0U, L'K' } };
	void *notify_handle;
	UINT8 toggle = 4U;
	struct cdk2_split_pointer pointer = {
		.devices = {
			{ pointer_state, (void *)1, 10U, 1U, 1U },
			{ pointer_state, (void *)2, 20U, 2U, 1U },
		},
		.device_count = 2U, .resolution_x = 20U, .resolution_y = 2U,
		.resolution_z = 1U,
	};
	struct cdk2_split_pointer_state relative;
	struct cdk2_split_absolute absolute = {
		.devices = { { absolute_state, (void *)1, 0U, 0U, 0U, 100U, 50U, 0U } },
		.device_count = 1U, .min_x = 10U, .min_y = 20U, .max_x = 210U, .max_y = 120U,
	};
	struct cdk2_split_absolute_state position;
	int failures = 0;
	struct cdk2_split_pointer rebuilt_pointer = { 0 };
	struct cdk2_split_pointer_device pointer_one = {
		pointer_state, (void *)1, 10U, 1U, 1U
	};
	struct cdk2_split_pointer_device pointer_two = {
		pointer_state, (void *)2, 20U, 2U, 1U
	};

	failures += expect(cdk2_split_text_in_add(&text, read_key, reset, (void *)1) ==
		EFI_SUCCESS && cdk2_split_text_in_add(&text, read_key, reset, (void *)2) ==
		EFI_SUCCESS, "text devices were not admitted");
	failures += expect(cdk2_split_text_in_read(&text, &key) == EFI_SUCCESS &&
		key.unicode == L'K' && reads[0] == 2U && reads[1] == 1U,
		"partial key handling did not continue to the next device");
	failures += expect(cdk2_split_text_in_reset(&text, TRUE) == EFI_DEVICE_ERROR &&
		resets == 2U, "reset did not visit every input and return the last error");
	reads[0] = reads[1] = 0U;
	failures += expect(cdk2_split_text_in_set_state(&text, &toggle) == EFI_SUCCESS &&
		cdk2_split_text_in_register_notify(&text, &match, notified,
			&notify_handle) == EFI_SUCCESS &&
		cdk2_split_text_in_read_ex(&text, &key_data) == EFI_SUCCESS &&
		key_data.key.unicode == L'K' && key_data.state.toggle_state == 4U &&
		notifications == 1U &&
		cdk2_split_text_in_unregister_notify(&text, notify_handle) == EFI_SUCCESS,
		"TextInEx state or key notification semantics are wrong");
	failures += expect(cdk2_split_pointer_get_state(&pointer, &relative) == EFI_SUCCESS &&
		relative.x == 40 && relative.y == 4 && relative.left && relative.right,
		"relative pointer scaling/aggregation is wrong");
	failures += expect(cdk2_split_absolute_get_state(&absolute, &position) == EFI_SUCCESS &&
		position.x == 110U && position.y == 70U && position.buttons == 3U,
		"absolute pointer scaling is wrong");
	failures += expect(cdk2_split_pointer_add(&rebuilt_pointer, &pointer_one) == EFI_SUCCESS &&
		cdk2_split_pointer_add(&rebuilt_pointer, &pointer_two) == EFI_SUCCESS &&
		cdk2_split_pointer_remove(&rebuilt_pointer, (void *)2) == EFI_SUCCESS &&
		rebuilt_pointer.device_count == 1U && rebuilt_pointer.resolution_x == 10U,
		"relative pointer mode was not rebuilt after removal");
	return failures == 0 ? 0 : 1;
}
