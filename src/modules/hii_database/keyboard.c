/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

static BOOLEAN same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *left_bytes = (const UINT8 *)left;
	const UINT8 *right_bytes = (const UINT8 *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++)
		if (left_bytes[index] != right_bytes[index])
			return FALSE;
	return TRUE;
}

EFI_STATUS cdk2_hii_add_keyboard_layout(struct cdk2_hii_database *database,
	const EFI_GUID *layout)
{
	UINTN index;

	if (database == NULL || layout == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < database->keyboard_layout_count; index++)
		if (same_guid(&database->keyboard_layouts[index], layout))
			return EFI_SUCCESS;
	if (database->keyboard_layout_count == CDK2_HII_MAX_KEYBOARD_LAYOUTS)
		return EFI_OUT_OF_RESOURCES;
	database->keyboard_layouts[database->keyboard_layout_count++] = *layout;
	if (database->keyboard_layout_count == 1U)
		database->current_keyboard_layout = 0U;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_find_keyboard_layouts(struct cdk2_hii_database *database,
	UINT16 *count, EFI_GUID *layouts)
{
	UINTN capacity;

	if (database == NULL || count == NULL)
		return EFI_INVALID_PARAMETER;
	capacity = *count;
	*count = (UINT16)database->keyboard_layout_count;
	if (layouts == NULL || capacity < database->keyboard_layout_count)
		return EFI_BUFFER_TOO_SMALL;
	__builtin_memcpy(layouts, database->keyboard_layouts,
		database->keyboard_layout_count * sizeof(*layouts));
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_get_keyboard_layout(struct cdk2_hii_database *database,
	EFI_GUID *layout)
{
	if (database == NULL || layout == NULL)
		return EFI_INVALID_PARAMETER;
	if (database->keyboard_layout_count == 0U)
		return EFI_NOT_FOUND;
	*layout = database->keyboard_layouts[database->current_keyboard_layout];
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_set_keyboard_layout(struct cdk2_hii_database *database,
	const EFI_GUID *layout)
{
	UINTN index;

	if (database == NULL || layout == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < database->keyboard_layout_count; index++)
		if (same_guid(&database->keyboard_layouts[index], layout)) {
			database->current_keyboard_layout = index;
			if (database->keyboard_notify != NULL)
				database->keyboard_notify(database->keyboard_notify_context,
					layout);
			return EFI_SUCCESS;
		}
	return EFI_NOT_FOUND;
}

void cdk2_hii_set_keyboard_notify(struct cdk2_hii_database *database,
	void (*notify)(void *context, const EFI_GUID *layout), void *context)
{
	if (database == NULL)
		return;
	database->keyboard_notify = notify;
	database->keyboard_notify_context = context;
}
