/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

static UINTN length(const CHAR16 *text)
{
	UINTN result = 0U;
	while (text[result] != 0U)
		result++;
	return result;
}

static CHAR16 folded(CHAR16 character)
{
	return character >= L'A' && character <= L'Z' ?
		(CHAR16)(character + (L'a' - L'A')) : character;
}

static BOOLEAN equal(const CHAR16 *left, const CHAR16 *right)
{
	UINTN index = 0U;
	while (left[index] != 0U && folded(left[index]) == folded(right[index]))
		index++;
	return folded(left[index]) == folded(right[index]);
}

static EFI_STATUS duplicate(struct cdk2_hii_database *database,
	const CHAR16 *source, CHAR16 **destination)
{
	EFI_STATUS status;
	UINTN bytes = (length(source) + 1U) * sizeof(CHAR16);
	status = database->ops->allocate(database->context, bytes,
		(void **)destination);
	if (!EFI_ERROR(status))
		__builtin_memcpy(*destination, source, bytes);
	return status;
}

static struct cdk2_hii_keyword *find_keyword(struct cdk2_hii_database *database,
	const CHAR16 *name_space, const CHAR16 *keyword)
{
	UINTN index;
	for (index = 0; index < CDK2_HII_MAX_KEYWORDS; index++)
		if (database->keywords[index].active &&
		    equal(database->keywords[index].name_space, name_space) &&
		    equal(database->keywords[index].keyword, keyword))
			return &database->keywords[index];
	return NULL;
}

EFI_STATUS cdk2_hii_register_keyword(struct cdk2_hii_database *database,
	const CHAR16 *name_space, const CHAR16 *keyword, const CHAR16 *value,
	BOOLEAN read_only)
{
	struct cdk2_hii_keyword *entry = NULL;
	EFI_STATUS status;
	UINTN index;

	if (database == NULL || name_space == NULL || keyword == NULL || value == NULL ||
	    name_space[0] == 0U || keyword[0] == 0U)
		return EFI_INVALID_PARAMETER;
	if (find_keyword(database, name_space, keyword) != NULL)
		return EFIERR(20);
	for (index = 0; index < CDK2_HII_MAX_KEYWORDS; index++)
		if (!database->keywords[index].active) {
			entry = &database->keywords[index];
			break;
		}
	if (entry == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = duplicate(database, name_space, &entry->name_space);
	if (EFI_ERROR(status))
		return status;
	status = duplicate(database, keyword, &entry->keyword);
	if (EFI_ERROR(status))
		goto cleanup_namespace;
	status = duplicate(database, value, &entry->value);
	if (EFI_ERROR(status))
		goto cleanup_keyword;
	entry->read_only = read_only;
	entry->active = TRUE;
	return EFI_SUCCESS;

cleanup_keyword:
	database->ops->release(database->context, entry->keyword);
cleanup_namespace:
	database->ops->release(database->context, entry->name_space);
	*entry = (struct cdk2_hii_keyword) { 0 };
	return status;
}

EFI_STATUS cdk2_hii_register_package_keyword(struct cdk2_hii_database *database,
	void *package_handle, const CHAR16 *name_space, const CHAR16 *keyword,
	UINT16 prompt_id, UINT16 varstore_id, UINT16 varstore_info, UINT16 width,
	UINT8 opcode, UINT8 numeric_size, BOOLEAN read_only)
{
	struct cdk2_hii_keyword *entry = NULL;
	EFI_STATUS status;
	UINTN index;

	if (database == NULL || package_handle == NULL || name_space == NULL ||
	    keyword == NULL || name_space[0] == 0U || keyword[0] == 0U ||
	    prompt_id == 0U || varstore_id == 0U || width == 0U)
		return EFI_INVALID_PARAMETER;
	for (index = 0U; index < CDK2_HII_MAX_KEYWORDS; index++)
		if (!database->keywords[index].active) {
			entry = &database->keywords[index];
			break;
		}
	if (entry == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = duplicate(database, name_space, &entry->name_space);
	if (EFI_ERROR(status))
		return status;
	status = duplicate(database, keyword, &entry->keyword);
	if (EFI_ERROR(status))
		goto cleanup_namespace;
	status = duplicate(database, L"", &entry->value);
	if (EFI_ERROR(status))
		goto cleanup_keyword;
	entry->package_handle = package_handle;
	entry->prompt_id = prompt_id;
	entry->varstore_id = varstore_id;
	entry->varstore_info = varstore_info;
	entry->width = width;
	entry->opcode = opcode;
	entry->numeric_size = numeric_size;
	entry->read_only = read_only;
	entry->active = TRUE;
	return EFI_SUCCESS;

cleanup_keyword:
	database->ops->release(database->context, entry->keyword);
cleanup_namespace:
	database->ops->release(database->context, entry->name_space);
	*entry = (struct cdk2_hii_keyword) { 0 };
	return status;
}

void cdk2_hii_remove_keywords(struct cdk2_hii_database *database,
	void *package_handle)
{
	UINTN index;

	for (index = 0U; index < CDK2_HII_MAX_KEYWORDS; index++)
		if (database->keywords[index].active &&
		    database->keywords[index].package_handle == package_handle) {
			database->ops->release(database->context,
				database->keywords[index].name_space);
			database->ops->release(database->context,
				database->keywords[index].keyword);
			database->ops->release(database->context,
				database->keywords[index].value);
			database->keywords[index] = (struct cdk2_hii_keyword) { 0 };
		}
}

EFI_STATUS cdk2_hii_get_keyword_data(struct cdk2_hii_database *database,
	const CHAR16 *name_space, const CHAR16 *keyword, CHAR16 **value)
{
	struct cdk2_hii_keyword *entry;

	if (database == NULL || name_space == NULL || keyword == NULL || value == NULL)
		return EFI_INVALID_PARAMETER;
	entry = find_keyword(database, name_space, keyword);
	return entry == NULL ? EFI_NOT_FOUND : duplicate(database, entry->value, value);
}

EFI_STATUS cdk2_hii_set_keyword_data(struct cdk2_hii_database *database,
	const CHAR16 *name_space, const CHAR16 *keyword, const CHAR16 *value)
{
	struct cdk2_hii_keyword *entry;
	CHAR16 *copy;
	EFI_STATUS status;

	if (database == NULL || name_space == NULL || keyword == NULL || value == NULL)
		return EFI_INVALID_PARAMETER;
	entry = find_keyword(database, name_space, keyword);
	if (entry == NULL)
		return EFI_NOT_FOUND;
	if (entry->read_only)
		return EFIERR(8);
	status = duplicate(database, value, &copy);
	if (EFI_ERROR(status))
		return status;
	database->ops->release(database->context, entry->value);
	entry->value = copy;
	return EFI_SUCCESS;
}
