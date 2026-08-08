/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

static UINTN ascii_length(const CHAR8 *string)
{
	UINTN length = 0U;
	while (string[length] != 0)
		length++;
	return length;
}

static UINTN string_length(const CHAR16 *string)
{
	UINTN length = 0U;
	while (string[length] != 0U)
		length++;
	return length;
}

static BOOLEAN same_language(const CHAR8 *left, const CHAR8 *right)
{
	UINTN index = 0U;
	while (left[index] != 0 && left[index] == right[index])
		index++;
	return left[index] == 0 && right[index] == 0;
}

static BOOLEAN valid_handle(struct cdk2_hii_database *database, void *handle)
{
	struct cdk2_hii_list *list = handle;
	return list >= database->lists && list < database->lists + CDK2_HII_MAX_LISTS &&
		list->active;
}

static UINTN font_size(const struct cdk2_hii_font_info *font)
{
	return font == NULL ? 0U : offsetof(struct cdk2_hii_font_info, name) +
		(string_length(font->name) + 1U) * sizeof(CHAR16);
}

static EFI_STATUS copy_value(struct cdk2_hii_database *database,
	const CHAR16 *string, const struct cdk2_hii_font_info *font,
	CHAR16 **text_copy, struct cdk2_hii_font_info **font_copy)
{
	EFI_STATUS status;
	UINTN bytes, font_bytes;

	bytes = (string_length(string) + 1U) * sizeof(CHAR16);
	status = database->ops->allocate(database->context, bytes, (void **)text_copy);
	if (EFI_ERROR(status))
		return status;
	__builtin_memcpy(*text_copy, string, bytes);
	*font_copy = NULL;
	font_bytes = font_size(font);
	if (font_bytes != 0U) {
		status = database->ops->allocate(database->context, font_bytes,
			(void **)font_copy);
		if (EFI_ERROR(status)) {
			database->ops->release(database->context, *text_copy);
			*text_copy = NULL;
			return status;
		}
		__builtin_memcpy(*font_copy, font, font_bytes);
	}
	return EFI_SUCCESS;
}

static struct cdk2_hii_string *find_string(struct cdk2_hii_database *database,
	void *handle, UINT16 id, const CHAR8 *language)
{
	UINTN index;
	for (index = 0; index < CDK2_HII_MAX_STRINGS; index++)
		if (database->strings[index].active &&
		    database->strings[index].package_handle == handle &&
		    database->strings[index].id == id &&
		    same_language(database->strings[index].language, language))
			return &database->strings[index];
	return NULL;
}

EFI_STATUS cdk2_hii_set_string(struct cdk2_hii_database *database,
	void *package_handle, UINT16 string_id, const CHAR8 *language,
	const CHAR16 *string, const struct cdk2_hii_font_info *font)
{
	struct cdk2_hii_string *entry = NULL;
	struct cdk2_hii_font_info *font_copy;
	CHAR16 *text_copy;
	EFI_STATUS status;
	UINTN index, language_size;

	if (database == NULL || !valid_handle(database, package_handle) ||
	    string_id == 0U || language == NULL || string == NULL)
		return EFI_INVALID_PARAMETER;
	language_size = ascii_length(language);
	if (language_size == 0U || language_size > CDK2_HII_MAX_LANGUAGE)
		return EFI_INVALID_PARAMETER;
	entry = find_string(database, package_handle, string_id, language);
	if (entry == NULL)
		for (index = 0; index < CDK2_HII_MAX_STRINGS; index++)
			if (!database->strings[index].active) {
				entry = &database->strings[index];
				break;
			}
	if (entry == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = copy_value(database, string, font, &text_copy, &font_copy);
	if (EFI_ERROR(status))
		return status;
	if (entry->active) {
		database->ops->release(database->context, entry->text);
		if (entry->font != NULL)
			database->ops->release(database->context, entry->font);
	} else {
		entry->package_handle = package_handle;
		entry->id = string_id;
		__builtin_memcpy(entry->language, language, language_size + 1U);
		entry->active = TRUE;
	}
	entry->text = text_copy;
	entry->font = font_copy;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_new_string(struct cdk2_hii_database *database,
	void *package_handle, UINT16 *string_id, const CHAR8 *language,
	const CHAR16 *string, const struct cdk2_hii_font_info *font)
{
	EFI_STATUS status;
	UINT16 candidate;

	if (database == NULL || string_id == NULL)
		return EFI_INVALID_PARAMETER;
	candidate = *string_id;
	if (candidate == 0U) {
		candidate = database->next_string_id++;
		if (candidate == 0U)
			return EFI_OUT_OF_RESOURCES;
	}
	status = cdk2_hii_set_string(database, package_handle, candidate, language,
		string, font);
	if (!EFI_ERROR(status))
		*string_id = candidate;
	return status;
}

EFI_STATUS cdk2_hii_get_string(struct cdk2_hii_database *database,
	const CHAR8 *language, void *package_handle, UINT16 string_id,
	CHAR16 *string, UINTN *string_size, struct cdk2_hii_font_info **font)
{
	struct cdk2_hii_string *entry;
	EFI_STATUS status;
	UINTN bytes, font_bytes;

	if (database == NULL || language == NULL || string_size == NULL ||
	    !valid_handle(database, package_handle))
		return EFI_INVALID_PARAMETER;
	entry = find_string(database, package_handle, string_id, language);
	if (entry == NULL)
		return EFI_NOT_FOUND;
	bytes = (string_length(entry->text) + 1U) * sizeof(CHAR16);
	if (string == NULL || *string_size < bytes) {
		*string_size = bytes;
		return EFI_BUFFER_TOO_SMALL;
	}
	__builtin_memcpy(string, entry->text, bytes);
	*string_size = bytes;
	if (font != NULL) {
		*font = NULL;
		font_bytes = font_size(entry->font);
		if (font_bytes != 0U) {
			status = database->ops->allocate(database->context, font_bytes,
				(void **)font);
			if (EFI_ERROR(status))
				return status;
			__builtin_memcpy(*font, entry->font, font_bytes);
		}
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_get_languages(struct cdk2_hii_database *database,
	void *package_handle, CHAR8 *languages, UINTN *size)
{
	CHAR8 result[CDK2_HII_MAX_STRINGS * (CDK2_HII_MAX_LANGUAGE + 1U)];
	UINTN used = 0U, index, prior, length;
	BOOLEAN duplicate;

	if (database == NULL || size == NULL || !valid_handle(database, package_handle))
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < CDK2_HII_MAX_STRINGS; index++) {
		if (!database->strings[index].active ||
		    database->strings[index].package_handle != package_handle)
			continue;
		duplicate = FALSE;
		for (prior = 0; prior < index; prior++)
			if (database->strings[prior].active &&
			    database->strings[prior].package_handle == package_handle &&
			    same_language(database->strings[prior].language,
				database->strings[index].language))
				duplicate = TRUE;
		if (duplicate)
			continue;
		if (used != 0U)
			result[used++] = ';';
		length = ascii_length(database->strings[index].language);
		__builtin_memcpy(result + used, database->strings[index].language, length);
		used += length;
	}
	result[used++] = 0;
	if (languages == NULL || *size < used) {
		*size = used;
		return EFI_BUFFER_TOO_SMALL;
	}
	__builtin_memcpy(languages, result, used);
	*size = used;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_get_secondary_languages(struct cdk2_hii_database *database,
	void *package_handle, const CHAR8 *primary_language, CHAR8 *languages,
	UINTN *size)
{
	EFI_STATUS status;
	UINTN index, used = 0U, length;

	if (primary_language == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_hii_get_languages(database, package_handle, NULL, size);
	if (status != EFI_BUFFER_TOO_SMALL)
		return status;
	if (languages == NULL)
		return status;
	for (index = 0; index < CDK2_HII_MAX_STRINGS; index++) {
		if (!database->strings[index].active ||
		    database->strings[index].package_handle != package_handle ||
		    same_language(database->strings[index].language, primary_language))
			continue;
		if (used != 0U)
			languages[used++] = ';';
		length = ascii_length(database->strings[index].language);
		if (used + length + 1U > *size)
			return EFI_BUFFER_TOO_SMALL;
		__builtin_memcpy(languages + used, database->strings[index].language,
			length);
		used += length;
	}
	languages[used++] = 0;
	*size = used;
	return EFI_SUCCESS;
}

void cdk2_hii_remove_strings(struct cdk2_hii_database *database,
	void *package_handle)
{
	UINTN index;

	if (database == NULL)
		return;
	for (index = 0; index < CDK2_HII_MAX_STRINGS; index++) {
		if (!database->strings[index].active ||
		    database->strings[index].package_handle != package_handle)
			continue;
		database->ops->release(database->context, database->strings[index].text);
		if (database->strings[index].font != NULL)
			database->ops->release(database->context,
				database->strings[index].font);
		database->strings[index] = (struct cdk2_hii_string) { 0 };
	}
}
