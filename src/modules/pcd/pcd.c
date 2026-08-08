/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pcd.h>

#include <string.h>

#define PCD_TYPE_MASK 0xd0000000U
#define PCD_TYPE_DATA 0x00000000U
#define PCD_TYPE_STRING 0x10000000U
#define PCD_DATUM_MASK 0x0f000000U
#define PCD_OFFSET_MASK 0x00efffffU
#define PCD_BOOLEAN 0x00100000U
#define PCD_NOT_FOUND ((1ULL << 63) | 14ULL)
#define PCD_INVALID_PARAMETER ((1ULL << 63) | 2ULL)
#define PCD_UNSUPPORTED ((1ULL << 63) | 3ULL)
#define PCD_BUFFER_TOO_SMALL ((1ULL << 63) | 5ULL)
#define PCD_OUT_OF_RESOURCES ((1ULL << 63) | 9ULL)
#define PCD_ALREADY_STARTED ((1ULL << 63) | 20ULL)

static const EFI_GUID database_guid = {
	0x3c7d193c, 0x682c, 0x4c14, { 0xa6, 0x8f, 0x55, 0x2d, 0xea, 0x4f, 0x43, 0x7e }
};

static int bounds(size_t offset, size_t count, size_t width, size_t limit)
{
	return width == 0 || (count <= (limit - (offset <= limit ? offset : limit)) / width);
}

static int same_guid(const EFI_GUID *a, const EFI_GUID *b)
{
	return a != NULL && b != NULL && memcmp(a, b, sizeof(*a)) == 0;
}

static uint32_t *local_table(struct cdk2_pcd_context *context)
{
	return (uint32_t *)(context->database + context->header->local_tokens_offset);
}

static struct cdk2_pcd_ex_map *ex_table(struct cdk2_pcd_context *context)
{
	return (struct cdk2_pcd_ex_map *)(context->database + context->header->ex_map_offset);
}

static EFI_GUID *guid_table(struct cdk2_pcd_context *context)
{
	return (EFI_GUID *)(context->database + context->header->guid_offset);
}

uint64_t cdk2_pcd_init(struct cdk2_pcd_context *context, void *database,
	size_t capacity)
{
	struct cdk2_pcd_database_header *header = database;
	size_t i;

	if (context == NULL || database == NULL || capacity < sizeof(*header))
		return PCD_INVALID_PARAMETER;
	if (!same_guid(&header->signature, &database_guid) ||
	    header->build_version != CDK2_PCD_SERVICE_VERSION ||
	    header->length < sizeof(*header) || header->length > capacity ||
	    header->length_all_skus < header->length ||
	    header->length_all_skus > capacity ||
	    !bounds(header->local_tokens_offset, header->local_token_count,
		    sizeof(uint32_t), header->length) ||
	    !bounds(header->ex_map_offset, header->ex_token_count,
		    sizeof(struct cdk2_pcd_ex_map), header->length) ||
	    !bounds(header->guid_offset, header->guid_count,
		    sizeof(EFI_GUID), header->length) ||
	    header->string_offset > header->length || header->size_offset > header->length ||
	    header->sku_offset > header->length || header->name_offset > header->length)
		return PCD_INVALID_PARAMETER;
	memset(context, 0, sizeof(*context));
	context->database = database;
	context->capacity = capacity;
	context->header = header;
	for (i = 0; i < header->local_token_count; i++) {
		uint32_t entry = local_table(context)[i];
		uint32_t offset = entry & PCD_OFFSET_MASK;
		size_t width = 1;

		if ((entry & PCD_TYPE_MASK) != PCD_TYPE_DATA &&
		    (entry & PCD_TYPE_MASK) != PCD_TYPE_STRING)
			continue;
		if ((entry & PCD_TYPE_MASK) == PCD_TYPE_STRING)
			width = sizeof(uint32_t);
		else if ((entry & PCD_DATUM_MASK) == 0x08000000U)
			width = 8;
		else if ((entry & PCD_DATUM_MASK) == 0x04000000U)
			width = 4;
		else if ((entry & PCD_DATUM_MASK) == 0x02000000U)
			width = 2;
		if (!bounds(offset, 1, width, header->length))
			return PCD_INVALID_PARAMETER;
	}
	return EFI_SUCCESS;
}

static uint64_t resolve(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, uint16_t *local)
{
	size_t i;

	if (context == NULL || context->header == NULL || token == 0 || local == NULL)
		return PCD_INVALID_PARAMETER;
	if (space == NULL) {
		if (token > context->header->local_token_count)
			return PCD_NOT_FOUND;
		*local = (uint16_t)token;
		return EFI_SUCCESS;
	}
	for (i = 0; i < context->header->ex_token_count; i++) {
		struct cdk2_pcd_ex_map *map = &ex_table(context)[i];

		if (map->guid_index >= context->header->guid_count ||
		    map->local_token == 0 || map->local_token > context->header->local_token_count)
			return PCD_INVALID_PARAMETER;
		if (map->external_token == token &&
		    same_guid(space, &guid_table(context)[map->guid_index])) {
			*local = map->local_token;
			return EFI_SUCCESS;
		}
	}
	return PCD_NOT_FOUND;
}

static uint64_t locate(struct cdk2_pcd_context *context, uint16_t local,
	void **value, size_t *size)
{
	uint32_t entry = local_table(context)[local - 1];
	uint32_t offset = entry & PCD_OFFSET_MASK;
	size_t width;

	if ((entry & PCD_TYPE_MASK) == PCD_TYPE_STRING) {
		uint32_t string_index = *(uint32_t *)(context->database + offset);
		uint16_t *sizes = (uint16_t *)(context->database + context->header->size_offset);
		size_t size_index = (size_t)(local - 1) * 2;

		if (!bounds(context->header->size_offset, size_index + 2,
			    sizeof(uint16_t), context->header->length) ||
		    !bounds(context->header->string_offset, string_index + sizes[size_index + 1],
			    1, context->header->length))
			return PCD_INVALID_PARAMETER;
		*value = context->database + context->header->string_offset + string_index;
		*size = sizes[size_index + 1];
		return EFI_SUCCESS;
	}
	if ((entry & PCD_TYPE_MASK) != PCD_TYPE_DATA)
		return PCD_UNSUPPORTED;
	width = (entry & PCD_BOOLEAN) ? 1 :
		(entry & PCD_DATUM_MASK) == 0x08000000U ? 8 :
		(entry & PCD_DATUM_MASK) == 0x04000000U ? 4 :
		(entry & PCD_DATUM_MASK) == 0x02000000U ? 2 : 1;
	*value = context->database + offset;
	*size = width;
	return EFI_SUCCESS;
}

uint64_t cdk2_pcd_get(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, void **value, size_t *size)
{
	uint16_t local;
	uint64_t status;

	if (value == NULL || size == NULL)
		return PCD_INVALID_PARAMETER;
	status = resolve(context, space, token, &local);
	return status == EFI_SUCCESS ? locate(context, local, value, size) : status;
}

uint64_t cdk2_pcd_set(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, const void *value, size_t *size)
{
	void *destination;
	size_t current, i;
	uint64_t status = cdk2_pcd_get(context, space, token, &destination, &current);

	if (value == NULL || size == NULL)
		return PCD_INVALID_PARAMETER;
	if (status != EFI_SUCCESS)
		return status;
	if (*size > current || (*size != current && current <= 8)) {
		*size = current;
		return PCD_BUFFER_TOO_SMALL;
	}
	for (i = 0; i < CDK2_PCD_MAX_CALLBACKS; i++)
		if (context->callbacks[i].callback != NULL &&
		    context->callbacks[i].token == token &&
		    ((space == NULL && context->callbacks[i].space == NULL) ||
		     same_guid(space, context->callbacks[i].space)))
			context->callbacks[i].callback(space, token, (void *)value, *size);
	memcpy(destination, value, *size);
	return EFI_SUCCESS;
}

uint64_t cdk2_pcd_register(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, cdk2_pcd_callback callback)
{
	size_t i, empty = CDK2_PCD_MAX_CALLBACKS;
	uint16_t local;

	if (callback == NULL || resolve(context, space, token, &local) != EFI_SUCCESS)
		return PCD_INVALID_PARAMETER;
	for (i = 0; i < CDK2_PCD_MAX_CALLBACKS; i++) {
		if (context->callbacks[i].callback == callback &&
		    context->callbacks[i].token == token && context->callbacks[i].space == space)
			return PCD_ALREADY_STARTED;
		if (empty == CDK2_PCD_MAX_CALLBACKS && context->callbacks[i].callback == NULL)
			empty = i;
	}
	if (empty == CDK2_PCD_MAX_CALLBACKS)
		return PCD_OUT_OF_RESOURCES;
	context->callbacks[empty] = (struct cdk2_pcd_callback_slot){ space, token, callback };
	return EFI_SUCCESS;
}

uint64_t cdk2_pcd_unregister(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, cdk2_pcd_callback callback)
{
	size_t i;

	for (i = 0; context != NULL && i < CDK2_PCD_MAX_CALLBACKS; i++)
		if (context->callbacks[i].callback == callback &&
		    context->callbacks[i].token == token && context->callbacks[i].space == space) {
			memset(&context->callbacks[i], 0, sizeof(context->callbacks[i]));
			return EFI_SUCCESS;
		}
	return PCD_NOT_FOUND;
}

uint64_t cdk2_pcd_next_token(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t *token)
{
	size_t i;

	if (context == NULL || token == NULL)
		return PCD_INVALID_PARAMETER;
	if (space == NULL) {
		if (*token >= context->header->local_token_count)
			return PCD_NOT_FOUND;
		(*token)++;
		return EFI_SUCCESS;
	}
	for (i = 0; i < context->header->ex_token_count; i++) {
		struct cdk2_pcd_ex_map *map = &ex_table(context)[i];
		if (map->external_token > *token && map->guid_index < context->header->guid_count &&
		    same_guid(space, &guid_table(context)[map->guid_index])) {
			*token = map->external_token;
			return EFI_SUCCESS;
		}
	}
	return PCD_NOT_FOUND;
}

uint64_t cdk2_pcd_set_sku(struct cdk2_pcd_context *context, uint64_t sku)
{
	uint64_t *table;
	size_t count, i;

	if (context == NULL || context->header == NULL)
		return PCD_INVALID_PARAMETER;
	if (context->header->system_sku_id != 0 && context->header->system_sku_id != sku)
		return PCD_ALREADY_STARTED;
	count = (context->header->local_tokens_offset - context->header->sku_offset) /
		sizeof(uint64_t);
	table = (uint64_t *)(context->database + context->header->sku_offset);
	for (i = 0; i < count; i++)
		if (table[i] == sku) {
			context->header->system_sku_id = sku;
			return EFI_SUCCESS;
		}
	return PCD_NOT_FOUND;
}

uint64_t cdk2_pcd_apply_sku_delta(struct cdk2_pcd_context *context,
	uint64_t sku)
{
	size_t cursor;

	if (context == NULL || context->header == NULL)
		return PCD_INVALID_PARAMETER;
	cursor = context->header->length;
	while (cursor < context->header->length_all_skus) {
		uint64_t entry_sku, compared;
		uint32_t length;
		size_t delta;

		if (!bounds(cursor, 1, 20, context->header->length_all_skus))
			return PCD_INVALID_PARAMETER;
		memcpy(&entry_sku, context->database + cursor, sizeof(entry_sku));
		memcpy(&compared, context->database + cursor + 8, sizeof(compared));
		memcpy(&length, context->database + cursor + 16, sizeof(length));
		if (length < 20 || !bounds(cursor, 1, length,
			    context->header->length_all_skus) || (length - 20) % 4 != 0)
			return PCD_INVALID_PARAMETER;
		if (entry_sku == sku) {
			if (compared != 0 && compared != context->header->system_sku_id)
				return PCD_UNSUPPORTED;
			for (delta = cursor + 20; delta < cursor + length; delta += 4) {
				uint32_t item;
				uint32_t offset;

				memcpy(&item, context->database + delta, sizeof(item));
				offset = item & 0x00ffffffU;
				if (offset >= context->header->length)
					return PCD_INVALID_PARAMETER;
				context->database[offset] = (uint8_t)(item >> 24);
			}
			context->header->system_sku_id = sku;
			return EFI_SUCCESS;
		}
		cursor += length;
	}
	return PCD_NOT_FOUND;
}
