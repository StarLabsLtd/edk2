/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

#define HII_NOTIFY_NEW 1U
#define HII_NOTIFY_REMOVE 2U
#define HII_NOTIFY_EXPORT 4U
#define HII_NOTIFY_ADD 8U

static BOOLEAN same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left, *b = (const UINT8 *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return FALSE;
	return TRUE;
}

static UINT32 package_length(const struct cdk2_hii_package_header *package)
{
	return package->length_and_type & 0x00ffffffU;
}

static UINT8 package_type(const struct cdk2_hii_package_header *package)
{
	return (UINT8)(package->length_and_type >> 24);
}

static EFI_STATUS validate_list(const void *buffer, UINT32 *size)
{
	const struct cdk2_hii_package_list_header *list = buffer;
	const struct cdk2_hii_package_header *package;
	UINT32 offset, length;

	if (buffer == NULL || size == NULL)
		return EFI_INVALID_PARAMETER;
	if (list->length < sizeof(*list) + sizeof(*package))
		return EFI_INVALID_PARAMETER;
	offset = sizeof(*list);
	while (offset < list->length) {
		package = (const void *)((const UINT8 *)buffer + offset);
		length = package_length(package);
		if (length < sizeof(*package) || length > list->length - offset)
			return EFI_INVALID_PARAMETER;
		offset += length;
		if (package_type(package) == CDK2_HII_PACKAGE_END) {
			if (length != sizeof(*package) || offset != list->length)
				return EFI_INVALID_PARAMETER;
			*size = list->length;
			return EFI_SUCCESS;
		}
	}
	return EFI_INVALID_PARAMETER;
}

static BOOLEAN list_has_package(const struct cdk2_hii_list *list, UINT8 type,
	const EFI_GUID *guid)
{
	const struct cdk2_hii_package_list_header *header = list->data;
	const struct cdk2_hii_package_header *package;
	const EFI_GUID *package_guid;
	UINT32 offset = sizeof(*header);

	if (type == 0U)
		return guid == NULL;
	while (offset < list->size) {
		package = (const void *)((const UINT8 *)list->data + offset);
		package_guid = package_type(package) == 1U && package_length(package) >=
			sizeof(*package) + sizeof(*package_guid) ?
			(const void *)(package + 1) : NULL;
		if (package_type(package) == type && (guid == NULL ||
		    (package_guid != NULL && same_guid(package_guid, guid))))
			return TRUE;
		offset += package_length(package);
	}
	return FALSE;
}

static void notify_list(struct cdk2_hii_database *database,
	struct cdk2_hii_list *list, UINTN operation)
{
	const struct cdk2_hii_package_list_header *header = list->data;
	const struct cdk2_hii_package_header *package;
	const EFI_GUID *package_guid;
	struct cdk2_hii_notify *notify;
	UINT32 offset = sizeof(*header);
	UINTN index;

	while (offset < list->size) {
		package = (const void *)((const UINT8 *)list->data + offset);
		package_guid = package_type(package) == 1U && package_length(package) >=
			sizeof(*package) + sizeof(*package_guid) ?
			(const void *)(package + 1) : NULL;
		for (index = 0; index < CDK2_HII_MAX_NOTIFIES; index++) {
			notify = &database->notifies[index];
			if (notify->active && (notify->notify_mask & operation) != 0U &&
			    (notify->package_type == 0U ||
			     notify->package_type == package_type(package)) &&
			    (!notify->use_guid || (package_guid != NULL &&
			     same_guid(&notify->package_guid, package_guid))))
				(void)notify->callback(notify->context, package_type(package),
					package_guid, package, list, operation);
		}
		offset += package_length(package);
	}
}

EFI_STATUS cdk2_hii_database_init(struct cdk2_hii_database *database,
	const struct cdk2_hii_database_ops *ops, void *context)
{
	if (database == NULL || ops == NULL || ops->allocate == NULL ||
	    ops->release == NULL)
		return EFI_INVALID_PARAMETER;
	__builtin_memset(database, 0, sizeof(*database));
	database->ops = ops;
	database->context = context;
	if (ops->allocate(context, sizeof(*database->strings) * CDK2_HII_MAX_STRINGS,
			(void **)&database->strings) != EFI_SUCCESS)
		return EFI_OUT_OF_RESOURCES;
	__builtin_memset(database->strings, 0,
		sizeof(*database->strings) * CDK2_HII_MAX_STRINGS);
	database->next_string_id = 1U;
	if (ops->allocate(context, sizeof(*database->images) * CDK2_HII_MAX_IMAGES,
			(void **)&database->images) != EFI_SUCCESS) {
		ops->release(context, database->strings);
		return EFI_OUT_OF_RESOURCES;
	}
	__builtin_memset(database->images, 0,
		sizeof(*database->images) * CDK2_HII_MAX_IMAGES);
	database->next_image_id = 1U;
	if (ops->allocate(context, sizeof(*database->glyphs) * CDK2_HII_MAX_GLYPHS,
			(void **)&database->glyphs) != EFI_SUCCESS) {
		ops->release(context, database->images);
		ops->release(context, database->strings);
		return EFI_OUT_OF_RESOURCES;
	}
	__builtin_memset(database->glyphs, 0,
		sizeof(*database->glyphs) * CDK2_HII_MAX_GLYPHS);
	if (ops->allocate(context, sizeof(*database->keyboard_records) *
			CDK2_HII_MAX_KEYBOARD_LAYOUTS,
			(void **)&database->keyboard_records) != EFI_SUCCESS) {
		ops->release(context, database->glyphs);
		ops->release(context, database->images);
		ops->release(context, database->strings);
		return EFI_OUT_OF_RESOURCES;
	}
	__builtin_memset(database->keyboard_records, 0,
		sizeof(*database->keyboard_records) * CDK2_HII_MAX_KEYBOARD_LAYOUTS);
	if (ops->allocate(context,
			sizeof(*database->config_routes) * CDK2_HII_MAX_CONFIG_ROUTES,
			(void **)&database->config_routes) != EFI_SUCCESS) {
		ops->release(context, database->keyboard_records);
		ops->release(context, database->glyphs);
		ops->release(context, database->images);
		ops->release(context, database->strings);
		return EFI_OUT_OF_RESOURCES;
	}
	__builtin_memset(database->config_routes, 0,
		sizeof(*database->config_routes) * CDK2_HII_MAX_CONFIG_ROUTES);
	if (ops->allocate(context, sizeof(*database->keywords) * CDK2_HII_MAX_KEYWORDS,
			(void **)&database->keywords) != EFI_SUCCESS) {
		ops->release(context, database->config_routes);
		ops->release(context, database->keyboard_records);
		ops->release(context, database->glyphs);
		ops->release(context, database->images);
		ops->release(context, database->strings);
		return EFI_OUT_OF_RESOURCES;
	}
	__builtin_memset(database->keywords, 0,
		sizeof(*database->keywords) * CDK2_HII_MAX_KEYWORDS);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_new_package_list(struct cdk2_hii_database *database,
	const void *package_list, void *driver_handle, void **handle)
{
	struct cdk2_hii_list *list = NULL;
	EFI_STATUS status;
	UINT32 size;
	UINTN index;

	if (database == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	status = validate_list(package_list, &size);
	if (EFI_ERROR(status))
		return status;
	for (index = 0; index < CDK2_HII_MAX_LISTS; index++)
		if (!database->lists[index].active) {
			list = &database->lists[index];
			break;
		}
	if (list == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = database->ops->allocate(database->context, size, &list->data);
	if (EFI_ERROR(status))
		return status;
	__builtin_memcpy(list->data, package_list, size);
	list->size = size;
	list->driver_handle = driver_handle;
	list->active = TRUE;
	*handle = list;
	status = cdk2_hii_ingest_package_list(database, list);
	if (EFI_ERROR(status)) {
		cdk2_hii_remove_strings(database, list);
		cdk2_hii_remove_images(database, list);
		cdk2_hii_remove_glyphs(database, list);
		cdk2_hii_remove_keyboard_layouts(database, list);
		cdk2_hii_remove_keywords(database, list);
		database->ops->release(database->context, list->data);
		*list = (struct cdk2_hii_list) { 0 };
		*handle = NULL;
		return status;
	}
	notify_list(database, list, HII_NOTIFY_NEW);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_remove_package_list(struct cdk2_hii_database *database,
	void *handle)
{
	struct cdk2_hii_list *list = handle;

	if (database == NULL || list < database->lists ||
	    list >= database->lists + CDK2_HII_MAX_LISTS || !list->active)
		return EFI_NOT_FOUND;
	notify_list(database, list, HII_NOTIFY_REMOVE);
	cdk2_hii_remove_strings(database, list);
	cdk2_hii_remove_images(database, list);
	cdk2_hii_remove_glyphs(database, list);
	cdk2_hii_remove_keyboard_layouts(database, list);
	cdk2_hii_remove_keywords(database, list);
	database->ops->release(database->context, list->data);
	*list = (struct cdk2_hii_list) { 0 };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_get_package_list_handle(struct cdk2_hii_database *database,
	void *package_handle, void **driver_handle)
{
	struct cdk2_hii_list *list = package_handle;

	if (database == NULL || driver_handle == NULL || list < database->lists ||
	    list >= database->lists + CDK2_HII_MAX_LISTS || !list->active)
		return EFI_INVALID_PARAMETER;
	*driver_handle = list->driver_handle;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_update_package_list(struct cdk2_hii_database *database,
	void *handle, const void *package_list)
{
	struct cdk2_hii_list *list = handle;
	struct cdk2_hii_list *staged = NULL;
	EFI_STATUS status;
	UINT32 size;
	UINTN index;

	if (database == NULL || list < database->lists ||
	    list >= database->lists + CDK2_HII_MAX_LISTS || !list->active)
		return EFI_NOT_FOUND;
	status = validate_list(package_list, &size);
	if (EFI_ERROR(status))
		return status;
	for (index = 0; index < CDK2_HII_MAX_LISTS; index++)
		if (!database->lists[index].active) {
			staged = &database->lists[index];
			break;
		}
	if (staged == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = database->ops->allocate(database->context, size, &staged->data);
	if (EFI_ERROR(status))
		return status;
	__builtin_memcpy(staged->data, package_list, size);
	staged->size = size;
	staged->driver_handle = list->driver_handle;
	staged->active = TRUE;
	status = cdk2_hii_ingest_package_list(database, staged);
	if (EFI_ERROR(status)) {
		cdk2_hii_remove_strings(database, staged);
		cdk2_hii_remove_images(database, staged);
		cdk2_hii_remove_glyphs(database, staged);
		cdk2_hii_remove_keyboard_layouts(database, staged);
		cdk2_hii_remove_keywords(database, staged);
		database->ops->release(database->context, staged->data);
		*staged = (struct cdk2_hii_list) { 0 };
		return status;
	}
	notify_list(database, list, HII_NOTIFY_REMOVE);
	cdk2_hii_remove_strings(database, list);
	cdk2_hii_remove_images(database, list);
	cdk2_hii_remove_glyphs(database, list);
	cdk2_hii_remove_keyboard_layouts(database, list);
	cdk2_hii_remove_keywords(database, list);
	database->ops->release(database->context, list->data);
	list->data = staged->data;
	list->size = staged->size;
	for (index = 0; index < CDK2_HII_MAX_STRINGS; index++)
		if (database->strings[index].active &&
		    database->strings[index].package_handle == staged)
			database->strings[index].package_handle = list;
	for (index = 0; index < CDK2_HII_MAX_IMAGES; index++)
		if (database->images[index].active &&
		    database->images[index].package_handle == staged)
			database->images[index].package_handle = list;
	for (index = 0; index < CDK2_HII_MAX_GLYPHS; index++)
		if (database->glyphs[index].active &&
		    database->glyphs[index].package_handle == staged)
			database->glyphs[index].package_handle = list;
	for (index = 0; index < database->keyboard_layout_count; index++)
		if (database->keyboard_records[index].active &&
		    database->keyboard_records[index].package_handle == staged)
			database->keyboard_records[index].package_handle = list;
	for (index = 0; index < CDK2_HII_MAX_KEYWORDS; index++)
		if (database->keywords[index].active &&
		    database->keywords[index].package_handle == staged)
			database->keywords[index].package_handle = list;
	*staged = (struct cdk2_hii_list) { 0 };
	notify_list(database, list, HII_NOTIFY_ADD);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_export_package_lists(struct cdk2_hii_database *database,
	void *handle, UINTN *size, void *buffer)
{
	struct cdk2_hii_list *list;
	UINTN needed = 0U, offset = 0U, index;

	if (database == NULL || size == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < CDK2_HII_MAX_LISTS; index++) {
		list = &database->lists[index];
		if (list->active && (handle == NULL || handle == list))
			needed += list->size;
	}
	if (handle != NULL && needed == 0U)
		return EFI_NOT_FOUND;
	if (buffer == NULL || *size < needed) {
		*size = needed;
		return EFI_BUFFER_TOO_SMALL;
	}
	for (index = 0; index < CDK2_HII_MAX_LISTS; index++) {
		list = &database->lists[index];
		if (!list->active || (handle != NULL && handle != list))
			continue;
		__builtin_memcpy((UINT8 *)buffer + offset, list->data, list->size);
		offset += list->size;
		notify_list(database, list, HII_NOTIFY_EXPORT);
	}
	*size = needed;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_list_package_lists(struct cdk2_hii_database *database,
	UINT8 package_type, const EFI_GUID *package_guid, UINTN *count,
	void **handles)
{
	UINTN found = 0U, capacity, index;

	if (database == NULL || count == NULL)
		return EFI_INVALID_PARAMETER;
	capacity = *count;
	for (index = 0; index < CDK2_HII_MAX_LISTS; index++)
		if (database->lists[index].active && list_has_package(&database->lists[index],
				package_type, package_guid)) {
			if (handles != NULL && found < capacity)
				handles[found] = &database->lists[index];
			found++;
		}
	*count = found;
	return handles == NULL || capacity < found ? EFI_BUFFER_TOO_SMALL : EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_register_package_notify(struct cdk2_hii_database *database,
	UINT8 package_type, const EFI_GUID *package_guid, cdk2_hii_notify_fn *callback,
	void *context, UINTN notify_mask, void **notify_handle)
{
	UINTN index;

	if (database == NULL || callback == NULL || notify_handle == NULL ||
	    notify_mask == 0U)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < CDK2_HII_MAX_NOTIFIES; index++)
		if (!database->notifies[index].active) {
			database->notifies[index] = (struct cdk2_hii_notify) {
				.package_type = package_type,
				.callback = callback, .context = context,
				.notify_mask = notify_mask, .use_guid = package_guid != NULL,
				.active = TRUE
			};
			if (package_guid != NULL)
				database->notifies[index].package_guid = *package_guid;
			*notify_handle = &database->notifies[index];
			return EFI_SUCCESS;
		}
	return EFI_OUT_OF_RESOURCES;
}

EFI_STATUS cdk2_hii_unregister_package_notify(struct cdk2_hii_database *database,
	void *notify_handle)
{
	struct cdk2_hii_notify *notify = notify_handle;

	if (database == NULL || notify < database->notifies ||
	    notify >= database->notifies + CDK2_HII_MAX_NOTIFIES || !notify->active)
		return EFI_NOT_FOUND;
	*notify = (struct cdk2_hii_notify) { 0 };
	return EFI_SUCCESS;
}
