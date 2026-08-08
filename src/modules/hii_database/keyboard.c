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

EFI_STATUS cdk2_hii_add_keyboard_layout_record(struct cdk2_hii_database *database,
	void *package_handle, const void *layout, UINT16 layout_size)
{
	const UINT8 *bytes = layout;
	EFI_GUID guid;
	void *copy;
	UINTN index;

	if (database == NULL || database->ops == NULL || layout == NULL ||
	    layout_size < 23U || bytes[0] != (UINT8)layout_size ||
	    bytes[1] != (UINT8)(layout_size >> 8) ||
	    23U + (UINTN)bytes[22] * 14U > layout_size)
		return EFI_INVALID_PARAMETER;
	__builtin_memcpy(&guid, bytes + 2U, sizeof(guid));
	for (index = 0; index < database->keyboard_layout_count; index++)
		if (same_guid(&database->keyboard_layouts[index], &guid))
			return EFI_INVALID_PARAMETER;
	if (database->keyboard_layout_count == CDK2_HII_MAX_KEYBOARD_LAYOUTS)
		return EFI_OUT_OF_RESOURCES;
	if (database->ops->allocate(database->context, layout_size, &copy) != EFI_SUCCESS)
		return EFI_OUT_OF_RESOURCES;
	__builtin_memcpy(copy, layout, layout_size);
	index = database->keyboard_layout_count++;
	database->keyboard_layouts[index] = guid;
	database->keyboard_records[index] = (struct cdk2_hii_keyboard_record) {
		.package_handle = package_handle, .data = copy, .size = layout_size,
		.active = TRUE
	};
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_copy_keyboard_layout(struct cdk2_hii_database *database,
	const EFI_GUID *layout, UINT16 *layout_size, void *layout_buffer)
{
	UINTN index, selected;

	if (database == NULL || layout_size == NULL)
		return EFI_INVALID_PARAMETER;
	if (database->keyboard_layout_count == 0U)
		return EFI_NOT_FOUND;
	selected = database->current_keyboard_layout;
	if (layout != NULL) {
		for (selected = 0; selected < database->keyboard_layout_count; selected++)
			if (same_guid(&database->keyboard_layouts[selected], layout))
				break;
		if (selected == database->keyboard_layout_count)
			return EFI_NOT_FOUND;
	}
	index = selected;
	if (!database->keyboard_records[index].active)
		return EFI_NOT_FOUND;
	if (layout_buffer == NULL || *layout_size < database->keyboard_records[index].size) {
		*layout_size = database->keyboard_records[index].size;
		return EFI_BUFFER_TOO_SMALL;
	}
	*layout_size = database->keyboard_records[index].size;
	__builtin_memcpy(layout_buffer, database->keyboard_records[index].data,
		*layout_size);
	return EFI_SUCCESS;
}

void cdk2_hii_remove_keyboard_layouts(struct cdk2_hii_database *database,
	void *package_handle)
{
	UINTN read, write = 0U, old_count;

	if (database == NULL || database->keyboard_records == NULL)
		return;
	old_count = database->keyboard_layout_count;
	for (read = 0; read < old_count; read++) {
		if (database->keyboard_records[read].active &&
		    database->keyboard_records[read].package_handle == package_handle) {
			database->ops->release(database->context,
				database->keyboard_records[read].data);
			continue;
		}
		if (write != read) {
			database->keyboard_layouts[write] = database->keyboard_layouts[read];
			database->keyboard_records[write] = database->keyboard_records[read];
		}
		write++;
	}
	database->keyboard_layout_count = write;
	while (write < old_count) {
		database->keyboard_records[write++] =
			(struct cdk2_hii_keyboard_record) { 0 };
	}
	if (database->keyboard_layout_count == 0U)
		database->current_keyboard_layout = 0U;
	else if (database->current_keyboard_layout >= database->keyboard_layout_count)
		database->current_keyboard_layout = database->keyboard_layout_count - 1U;
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
