/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

static UINTN text_length(const CHAR16 *text)
{
	UINTN length = 0U;
	while (text[length] != 0U)
		length++;
	return length;
}

static BOOLEAN match(const CHAR16 *text, const CHAR16 *token)
{
	UINTN index = 0U;
	while (token[index] != 0U && text[index] == token[index])
		index++;
	return token[index] == 0U;
}

static EFI_STATUS parse_hex(const CHAR16 **cursor, UINTN *value)
{
	UINTN result = 0U, digit, count = 0U;
	CHAR16 character;

	while ((character = **cursor) != 0U && character != L'&') {
		if (character >= L'0' && character <= L'9')
			digit = character - L'0';
		else if (character >= L'A' && character <= L'F')
			digit = character - L'A' + 10U;
		else if (character >= L'a' && character <= L'f')
			digit = character - L'a' + 10U;
		else
			return EFI_INVALID_PARAMETER;
		if (result > (~(UINTN)0 - digit) / 16U)
			return EFI_INVALID_PARAMETER;
		result = result * 16U + digit;
		(*cursor)++;
		count++;
	}
	if (count == 0U)
		return EFI_INVALID_PARAMETER;
	*value = result;
	return EFI_SUCCESS;
}

static CHAR16 hex_digit(UINT8 value)
{
	return value < 10U ? (CHAR16)(L'0' + value) : (CHAR16)(L'A' + value - 10U);
}

static EFI_STATUS hex_value(CHAR16 character, UINTN *value)
{
	if (character >= L'0' && character <= L'9')
		*value = character - L'0';
	else if (character >= L'A' && character <= L'F')
		*value = character - L'A' + 10U;
	else if (character >= L'a' && character <= L'f')
		*value = character - L'a' + 10U;
	else
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_block_to_config(struct cdk2_hii_database *database,
	const CHAR16 *request, const UINT8 *block, UINTN block_size,
	CHAR16 **configuration, const CHAR16 **progress)
{
	const CHAR16 *cursor, *value_start;
	CHAR16 *result, *output;
	EFI_STATUS status;
	UINTN offset, width, request_length, extra = 0U, index;

	if (database == NULL || request == NULL || block == NULL ||
	    configuration == NULL || progress == NULL)
		return EFI_INVALID_PARAMETER;
	cursor = request;
	while (*cursor != 0U) {
		if (match(cursor, L"&OFFSET=")) {
			cursor += 8U;
			status = parse_hex(&cursor, &offset);
			if (EFI_ERROR(status) || !match(cursor, L"&WIDTH="))
				goto malformed;
			cursor += 7U;
			status = parse_hex(&cursor, &width);
			if (EFI_ERROR(status) || offset > block_size || width > block_size - offset)
				goto malformed;
			if (width > (~(UINTN)0 - extra - 7U) / 2U)
				return EFI_OUT_OF_RESOURCES;
			extra += 7U + width * 2U;
		} else {
			cursor++;
		}
	}
	request_length = text_length(request);
	status = database->ops->allocate(database->context,
		(request_length + extra + 1U) * sizeof(CHAR16), (void **)&result);
	if (EFI_ERROR(status))
		return status;
	cursor = request;
	output = result;
	while (*cursor != 0U) {
		if (!match(cursor, L"&OFFSET=")) {
			*output++ = *cursor++;
			continue;
		}
		value_start = cursor;
		cursor += 8U;
		(void)parse_hex(&cursor, &offset);
		while (value_start < cursor)
			*output++ = *value_start++;
		value_start = cursor;
		cursor += 7U;
		(void)parse_hex(&cursor, &width);
		while (value_start < cursor)
			*output++ = *value_start++;
		*output++ = L'&'; *output++ = L'V'; *output++ = L'A'; *output++ = L'L';
		*output++ = L'U'; *output++ = L'E'; *output++ = L'=';
		for (index = 0; index < width; index++) {
			*output++ = hex_digit((UINT8)(block[offset + index] >> 4));
			*output++ = hex_digit((UINT8)(block[offset + index] & 0xfU));
		}
	}
	*output = 0U;
	*configuration = result;
	*progress = cursor;
	return EFI_SUCCESS;

malformed:
	*progress = cursor;
	return EFI_INVALID_PARAMETER;
}

EFI_STATUS cdk2_hii_config_to_block(const CHAR16 *configuration, UINT8 *block,
	UINTN *block_size, const CHAR16 **progress)
{
	const CHAR16 *cursor;
	EFI_STATUS status;
	UINTN offset, width, index, high, low, required = 0U;

	if (configuration == NULL || block_size == NULL || progress == NULL)
		return EFI_INVALID_PARAMETER;
	cursor = configuration;
	while (*cursor != 0U) {
		if (!match(cursor, L"&OFFSET=")) {
			cursor++;
			continue;
		}
		cursor += 8U;
		status = parse_hex(&cursor, &offset);
		if (EFI_ERROR(status) || !match(cursor, L"&WIDTH="))
			goto malformed;
		cursor += 7U;
		status = parse_hex(&cursor, &width);
		if (EFI_ERROR(status) || !match(cursor, L"&VALUE="))
			goto malformed;
		cursor += 7U;
		if (offset > ~(UINTN)0 - width)
			goto malformed;
		if (offset + width > required)
			required = offset + width;
		if (block == NULL || *block_size < required) {
			*block_size = required;
			*progress = cursor;
			return EFI_BUFFER_TOO_SMALL;
		}
		for (index = 0; index < width; index++) {
			if (hex_value(cursor[0], &high) != EFI_SUCCESS ||
			    hex_value(cursor[1], &low) != EFI_SUCCESS)
				goto malformed;
			block[offset + index] = (UINT8)(high * 16U + low);
			cursor += 2U;
		}
	}
	*block_size = required;
	*progress = cursor;
	return EFI_SUCCESS;

malformed:
	*progress = cursor;
	return EFI_INVALID_PARAMETER;
}
