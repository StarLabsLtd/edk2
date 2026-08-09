/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pcd.h>

#include <string.h>

#define PCD_TYPE_MASK 0xd0000000U
#define PCD_TYPE_DATA 0x00000000U
#define PCD_TYPE_STRING 0x10000000U
#define PCD_TYPE_VPD 0x40000000U
#define PCD_TYPE_HII 0x80000000U
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

static size_t datum_type(uint32_t entry)
{
	if ((entry & PCD_BOOLEAN) != 0)
		return 4;
	if ((entry & PCD_DATUM_MASK) == 0)
		return 5;
	return (entry & PCD_DATUM_MASK) == 0x02000000U ? 1 :
		(entry & PCD_DATUM_MASK) == 0x04000000U ? 2 :
		(entry & PCD_DATUM_MASK) == 0x08000000U ? 3 : 0;
}

static uint64_t grow_variable(struct cdk2_pcd_context *context, size_t required)
{
	void *buffer;
	void *old;
	size_t old_capacity;
	uint64_t status;

	if (required <= context->variable_capacity)
		return EFI_SUCCESS;
	if (context->allocate_pool == NULL || context->free_pool == NULL)
		return PCD_OUT_OF_RESOURCES;
	status = context->allocate_pool(4U, required, &buffer);
	if (status != EFI_SUCCESS)
		return status;
	old = context->variable;
	old_capacity = context->variable_capacity;
	memcpy(buffer, old, old_capacity);
	context->variable = buffer;
	context->variable_capacity = required;
	if (old != context->variable_inline)
		(void)context->free_pool(old);
	return EFI_SUCCESS;
}

static int valid_variable_name(struct cdk2_pcd_context *context,
	uint32_t string_index)
{
	size_t offset, available, index;
	uint16_t character;

	if ((string_index & 1U) != 0 ||
	    string_index > context->header->length - context->header->string_offset)
		return 0;
	offset = context->header->string_offset + string_index;
	available = (context->header->length - offset) / sizeof(character);
	for (index = 0; index < available; index++) {
		memcpy(&character, context->database + offset + index * sizeof(character),
			sizeof(character));
		if (character == 0)
			return 1;
	}
	return 0;
}

static uint64_t pointer_sizes(struct cdk2_pcd_context *context, uint16_t local,
	uint16_t **maximum, uint16_t **current)
{
	size_t i, index = 0;
	uint16_t *sizes;

	for (i = 0; i + 1 < local; i++)
		if ((local_table(context)[i] & PCD_DATUM_MASK) == 0 &&
		    (local_table(context)[i] & PCD_BOOLEAN) == 0)
			index += 2;
	if (!bounds(context->header->size_offset, index + 2, sizeof(*sizes),
		context->header->length))
		return PCD_INVALID_PARAMETER;
	sizes = (uint16_t *)(context->database + context->header->size_offset);
	*maximum = &sizes[index];
	*current = &sizes[index + 1];
	return EFI_SUCCESS;
}

struct variable_head {
	uint32_t string_index, default_offset;
	uint16_t guid_index, variable_offset;
	uint32_t attributes;
	uint16_t property, reserved;
};

static uint64_t storage_location(struct cdk2_pcd_context *context,
	uint32_t entry, size_t width, void **value)
{
	uint32_t offset = entry & PCD_OFFSET_MASK;

	if (((entry & PCD_TYPE_MASK) & ~PCD_TYPE_STRING) == PCD_TYPE_VPD) {
		uint32_t vpd_offset;

		if (!bounds(offset, 1, sizeof(vpd_offset), context->header->length))
			return PCD_INVALID_PARAMETER;
		memcpy(&vpd_offset, context->database + offset, sizeof(vpd_offset));
		if (context->vpd == NULL || !bounds(vpd_offset, 1, width, context->vpd_size))
			return PCD_NOT_FOUND;
		*value = context->vpd + vpd_offset;
		return EFI_SUCCESS;
	}
	if ((entry & PCD_TYPE_HII) != 0) {
		struct variable_head *head;
		uint16_t *name;
		size_t variable_size = context->variable_capacity;
		uint32_t attributes = 0;
		uint64_t status;

		if (!bounds(offset, 1, sizeof(*head), context->header->length))
			return PCD_INVALID_PARAMETER;
		head = (struct variable_head *)(context->database + offset);
		if (head->guid_index >= context->header->guid_count ||
		    !valid_variable_name(context, head->string_index) ||
		    width > SIZE_MAX - head->variable_offset)
			return PCD_INVALID_PARAMETER;
		name = (uint16_t *)(context->database + context->header->string_offset +
			head->string_index);
		status = context->get_variable == NULL ? PCD_NOT_FOUND :
			context->get_variable(name, &guid_table(context)[head->guid_index],
				&attributes, &variable_size, context->variable);
		if (status == EFI_BUFFER_TOO_SMALL) {
			status = grow_variable(context, variable_size);
			if (status != EFI_SUCCESS)
				return status;
			status = context->get_variable(name,
				&guid_table(context)[head->guid_index], &attributes,
				&variable_size, context->variable);
		}
		if (status != EFI_SUCCESS && status != PCD_NOT_FOUND)
			return status;
		if (status == EFI_SUCCESS && variable_size >= head->variable_offset + width) {
			*value = context->variable + head->variable_offset;
			return EFI_SUCCESS;
		}
		if (!bounds(head->default_offset, 1, width, context->header->length))
			return PCD_INVALID_PARAMETER;
		*value = context->database + head->default_offset;
		return EFI_SUCCESS;
	}
	return PCD_UNSUPPORTED;
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
	    header->uninitialized_size > capacity - header->length ||
	    header->length_all_skus < header->length ||
	    header->length_all_skus > capacity ||
	    header->ex_token_count > header->local_token_count ||
	    !bounds(header->local_tokens_offset, header->local_token_count,
		    sizeof(uint32_t), header->length) ||
	    !bounds(header->ex_map_offset, header->ex_token_count,
		    sizeof(struct cdk2_pcd_ex_map), header->length) ||
	    !bounds(header->guid_offset, header->guid_count,
		    sizeof(EFI_GUID), header->length) ||
	    header->string_offset > header->length || header->size_offset > header->length ||
	    header->sku_offset > header->local_tokens_offset ||
	    header->name_offset > header->length)
		return PCD_INVALID_PARAMETER;
	memset(context, 0, sizeof(*context));
	context->database = database;
	context->capacity = header->length + header->uninitialized_size;
	context->header = header;
	context->variable = context->variable_inline;
	context->variable_capacity = sizeof(context->variable_inline);
	for (i = 0; i < header->local_token_count; i++) {
		uint32_t entry = local_table(context)[i];
		uint32_t offset = entry & PCD_OFFSET_MASK;
		size_t width = 1;
		size_t limit = context->capacity;

		if ((entry & PCD_TYPE_MASK) != PCD_TYPE_DATA &&
		    (entry & PCD_TYPE_MASK) != PCD_TYPE_STRING &&
		    (entry & PCD_TYPE_MASK) != PCD_TYPE_HII &&
		    (entry & PCD_TYPE_MASK) != (PCD_TYPE_HII | PCD_TYPE_STRING) &&
		    (entry & PCD_TYPE_MASK) != PCD_TYPE_VPD &&
		    (entry & PCD_TYPE_MASK) != (PCD_TYPE_VPD | PCD_TYPE_STRING))
			continue;
		if ((entry & PCD_TYPE_STRING) != 0) {
			width = sizeof(uint32_t);
			limit = context->header->length;
		} else if ((entry & PCD_DATUM_MASK) == 0x08000000U)
			width = 8;
		else if ((entry & PCD_DATUM_MASK) == 0x04000000U)
			width = 4;
		else if ((entry & PCD_DATUM_MASK) == 0x02000000U)
			width = 2;
		if (!bounds(offset, 1, width, limit))
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
	size_t width = (entry & PCD_BOOLEAN) ? 1 :
		(entry & PCD_DATUM_MASK) == 0x08000000U ? 8 :
		(entry & PCD_DATUM_MASK) == 0x04000000U ? 4 :
		(entry & PCD_DATUM_MASK) == 0x02000000U ? 2 : 1;

	if ((entry & PCD_TYPE_STRING) != 0) {
		uint32_t string_index = *(uint32_t *)(context->database + offset);
		uint16_t *maximum, *current;
		uint64_t status = pointer_sizes(context, local, &maximum, &current);

		if (status != EFI_SUCCESS || *current > *maximum ||
		    (((entry & PCD_TYPE_MASK) & ~PCD_TYPE_STRING) == PCD_TYPE_DATA &&
		     (string_index > context->header->length -
			context->header->string_offset ||
		      *maximum > context->header->length -
			context->header->string_offset - string_index)))
			return PCD_INVALID_PARAMETER;
		if (((entry & PCD_TYPE_MASK) & ~PCD_TYPE_STRING) != PCD_TYPE_DATA) {
			status = storage_location(context, entry, *current, value);
			if (status != EFI_SUCCESS)
				return status;
		} else
			*value = context->database + context->header->string_offset + string_index;
		*size = *current;
		return EFI_SUCCESS;
	}
	if ((entry & PCD_TYPE_MASK) != PCD_TYPE_DATA) {
		uint64_t status = storage_location(context, entry, width, value);

		*size = width;
		return status;
	}
	if (!bounds(offset, 1, width, context->capacity))
		return PCD_INVALID_PARAMETER;
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

uint64_t cdk2_pcd_get_info(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, size_t *type, size_t *size)
{
	uint16_t local;
	void *value;
	uint64_t status;

	if (type == NULL || size == NULL)
		return PCD_INVALID_PARAMETER;
	status = resolve(context, space, token, &local);
	if (status != EFI_SUCCESS)
		return status;
	status = locate(context, local, &value, size);
	if (status == EFI_SUCCESS)
		*type = datum_type(local_table(context)[local - 1]);
	return status;
}

struct pcd_name_index {
	uint32_t space, name;
};

static size_t bounded_ascii_length(const uint8_t *text, size_t available)
{
	size_t length;

	for (length = 0; length < available && text[length] != 0; length++)
		;
	return length;
}

uint64_t cdk2_pcd_get_name(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, char **name)
{
	struct pcd_name_index *index;
	uint16_t local;
	const uint8_t *strings, *space_name, *pcd_name;
	size_t string_size, space_size, pcd_size, total;
	void *allocation;
	uint64_t status;

	if (name == NULL)
		return PCD_INVALID_PARAMETER;
	*name = NULL;
	status = resolve(context, space, token, &local);
	if (status != EFI_SUCCESS || context->header->name_offset == 0 ||
	    context->header->name_offset == context->header->length)
		return status;
	if (!bounds(context->header->name_offset, local,
		    sizeof(*index), context->header->length) ||
	    context->header->string_offset > context->header->length)
		return PCD_INVALID_PARAMETER;
	index = (struct pcd_name_index *)(context->database +
		context->header->name_offset) + local - 1;
	strings = context->database + context->header->string_offset;
	string_size = context->header->length - context->header->string_offset;
	if (index->space >= string_size || index->name >= string_size)
		return PCD_INVALID_PARAMETER;
	space_name = strings + index->space;
	pcd_name = strings + index->name;
	space_size = bounded_ascii_length(space_name, string_size - index->space);
	pcd_size = bounded_ascii_length(pcd_name, string_size - index->name);
	if (space_size == string_size - index->space ||
	    pcd_size == string_size - index->name ||
	    space_size > SIZE_MAX - pcd_size - 2)
		return PCD_INVALID_PARAMETER;
	total = space_size + pcd_size + 2;
	if (context->allocate_pool == NULL ||
	    context->allocate_pool(4U, total, &allocation) != EFI_SUCCESS)
		return PCD_OUT_OF_RESOURCES;
	memcpy(allocation, space_name, space_size);
	((char *)allocation)[space_size] = '.';
	memcpy((char *)allocation + space_size + 1, pcd_name, pcd_size + 1);
	*name = allocation;
	return EFI_SUCCESS;
}

uint64_t cdk2_pcd_set(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, const void *value, size_t *size)
{
	void *destination;
	size_t current, i;
	uint16_t local;
	uint32_t entry;
	uint64_t status = cdk2_pcd_get(context, space, token, &destination, &current);

	if (value == NULL || size == NULL)
		return PCD_INVALID_PARAMETER;
	if (status != EFI_SUCCESS)
		return status;
	status = resolve(context, space, token, &local);
	if (status != EFI_SUCCESS)
		return status;
	entry = local_table(context)[local - 1];
	if (((entry & PCD_TYPE_MASK) & ~PCD_TYPE_STRING) == PCD_TYPE_VPD)
		return PCD_INVALID_PARAMETER;
	if ((entry & PCD_TYPE_STRING) != 0) {
		uint16_t *maximum, *stored;

		status = pointer_sizes(context, local, &maximum, &stored);
		if (status != EFI_SUCCESS)
			return status;
		if (*size > *maximum || *size == (size_t)-1) {
			*size = *maximum;
			return PCD_INVALID_PARAMETER;
		}
		current = *maximum;
	} else if (*size > current || *size != current) {
		*size = current;
		return PCD_BUFFER_TOO_SMALL;
	}
	for (i = 0; i < CDK2_PCD_MAX_CALLBACKS; i++)
		if (context->callbacks[i].callback != NULL &&
		    context->callbacks[i].token == token &&
		    ((space == NULL && !context->callbacks[i].has_space) ||
		     (space != NULL && context->callbacks[i].has_space &&
		      same_guid(space, &context->callbacks[i].space))))
			context->callbacks[i].callback(space, token, (void *)value, *size);
	if ((entry & PCD_TYPE_HII) != 0) {
		struct variable_head *head = (struct variable_head *)(context->database +
			(entry & PCD_OFFSET_MASK));
		uint16_t *name = (uint16_t *)(context->database +
			context->header->string_offset + head->string_index);
		size_t variable_size = context->variable_capacity;
		uint32_t attributes = head->attributes;

		if (context->set_variable == NULL)
			return PCD_UNSUPPORTED;
		status = context->get_variable == NULL ? PCD_NOT_FOUND :
			context->get_variable(name, &guid_table(context)[head->guid_index],
				&attributes, &variable_size, context->variable);
		if (status == EFI_BUFFER_TOO_SMALL) {
			status = grow_variable(context, variable_size);
			if (status != EFI_SUCCESS)
				return status;
			status = context->get_variable(name,
				&guid_table(context)[head->guid_index], &attributes,
				&variable_size, context->variable);
		}
		if (status != EFI_SUCCESS && status != PCD_NOT_FOUND)
			return status;
		if (status == PCD_NOT_FOUND) {
			status = grow_variable(context, head->variable_offset + *size);
			if (status != EFI_SUCCESS)
				return status;
			memset(context->variable, 0, context->variable_capacity);
			variable_size = head->variable_offset + *size;
		}
		if (variable_size < head->variable_offset + *size) {
			status = grow_variable(context, head->variable_offset + *size);
			if (status != EFI_SUCCESS)
				return status;
		}
		if (!bounds(head->variable_offset, 1, *size, context->variable_capacity))
			return PCD_INVALID_PARAMETER;
		if (variable_size < head->variable_offset) {
			memset(context->variable + variable_size, 0,
				head->variable_offset - variable_size);
			variable_size = head->variable_offset;
		}
		if (variable_size < head->variable_offset + *size)
			variable_size = head->variable_offset + *size;
		memcpy(context->variable + head->variable_offset, value, *size);
		status = context->set_variable(name,
			&guid_table(context)[head->guid_index], head->attributes,
			variable_size, context->variable);
		if (status == EFI_SUCCESS &&
		    (entry & PCD_TYPE_MASK) == (PCD_TYPE_HII | PCD_TYPE_STRING)) {
			uint16_t *maximum, *stored;

			if (pointer_sizes(context, local, &maximum, &stored) == EFI_SUCCESS)
				*stored = (uint16_t)*size;
		}
		return status;
	}
	memcpy(destination, value, *size);
	if ((entry & PCD_TYPE_MASK) == PCD_TYPE_STRING) {
		uint16_t *maximum, *stored;

		(void)pointer_sizes(context, local, &maximum, &stored);
		*stored = (uint16_t)*size;
	}
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
		    context->callbacks[i].token == token &&
		    ((space == NULL && !context->callbacks[i].has_space) ||
		     (space != NULL && context->callbacks[i].has_space &&
		      same_guid(space, &context->callbacks[i].space))))
			return PCD_ALREADY_STARTED;
		if (empty == CDK2_PCD_MAX_CALLBACKS && context->callbacks[i].callback == NULL)
			empty = i;
	}
	if (empty == CDK2_PCD_MAX_CALLBACKS)
		return PCD_OUT_OF_RESOURCES;
	context->callbacks[empty].has_space = space != NULL;
	if (space != NULL)
		context->callbacks[empty].space = *space;
	context->callbacks[empty].token = token;
	context->callbacks[empty].callback = callback;
	return EFI_SUCCESS;
}

uint64_t cdk2_pcd_unregister(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, cdk2_pcd_callback callback)
{
	size_t i;

	for (i = 0; context != NULL && i < CDK2_PCD_MAX_CALLBACKS; i++)
		if (context->callbacks[i].callback == callback &&
		    context->callbacks[i].token == token &&
		    ((space == NULL && !context->callbacks[i].has_space) ||
		     (space != NULL && context->callbacks[i].has_space &&
		      same_guid(space, &context->callbacks[i].space)))) {
			memset(&context->callbacks[i], 0, sizeof(context->callbacks[i]));
			return EFI_SUCCESS;
		}
	return PCD_NOT_FOUND;
}

uint64_t cdk2_pcd_next_token(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t *token)
{
	size_t i;
	uint32_t candidate = 0;

	if (context == NULL || token == NULL)
		return PCD_INVALID_PARAMETER;
	if (space == NULL) {
		size_t ordinary = context->header->local_token_count -
			context->header->ex_token_count;

		if (*token >= ordinary)
			return PCD_NOT_FOUND;
		(*token)++;
		return EFI_SUCCESS;
	}
	for (i = 0; i < context->header->ex_token_count; i++) {
		struct cdk2_pcd_ex_map *map = &ex_table(context)[i];
		if (map->external_token > *token && map->guid_index < context->header->guid_count &&
		    same_guid(space, &guid_table(context)[map->guid_index]) &&
		    (candidate == 0 || map->external_token < candidate))
			candidate = map->external_token;
	}
	if (candidate == 0)
		return PCD_NOT_FOUND;
	*token = candidate;
	return EFI_SUCCESS;
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

uint64_t cdk2_pcd_configure_storage(struct cdk2_pcd_context *context,
	cdk2_pcd_get_variable_fn *get_variable,
	cdk2_pcd_set_variable_fn *set_variable, uint8_t *vpd, size_t vpd_size)
{
	if (context == NULL || context->header == NULL || (vpd == NULL && vpd_size != 0))
		return PCD_INVALID_PARAMETER;
	context->get_variable = get_variable;
	context->set_variable = set_variable;
	context->vpd = vpd;
	context->vpd_size = vpd_size;
	return EFI_SUCCESS;
}

uint64_t cdk2_pcd_merge_hob(struct cdk2_pcd_context *context,
	void *pei_database, size_t pei_size)
{
	struct cdk2_pcd_context pei;
	size_t i;
	uint64_t status;

	status = cdk2_pcd_init(&pei, pei_database, pei_size);
	if (status != EFI_SUCCESS)
		return status;
	for (i = 1; i <= (size_t)(pei.header->local_token_count -
		pei.header->ex_token_count);
	     i++) {
		void *value;
		size_t size;

		status = cdk2_pcd_get(&pei, NULL, (uint32_t)i, &value, &size);
		if (status != EFI_SUCCESS)
			return status;
		status = cdk2_pcd_set(context, NULL, (uint32_t)i, value, &size);
		if (status != EFI_SUCCESS && status != PCD_NOT_FOUND)
			return status;
	}
	for (i = 0; i < pei.header->ex_token_count; i++) {
		struct cdk2_pcd_ex_map *map = &ex_table(&pei)[i];
		EFI_GUID *space;
		void *value;
		size_t size;

		if (map->guid_index >= pei.header->guid_count)
			return PCD_INVALID_PARAMETER;
		space = &guid_table(&pei)[map->guid_index];
		status = cdk2_pcd_get(&pei, space, map->external_token, &value, &size);
		if (status != EFI_SUCCESS)
			return status;
		status = cdk2_pcd_set(context, space, map->external_token, value, &size);
		if (status != EFI_SUCCESS && status != PCD_NOT_FOUND)
			return status;
	}
	return EFI_SUCCESS;
}

uint64_t cdk2_pcd_lock_read_only(struct cdk2_pcd_context *context,
	cdk2_pcd_lock_variable_fn *lock_variable)
{
	size_t i;

	if (context == NULL || context->header == NULL || lock_variable == NULL)
		return PCD_INVALID_PARAMETER;
	for (i = 0; i < context->header->local_token_count; i++) {
		uint32_t entry = local_table(context)[i];
		uint32_t offset = entry & PCD_OFFSET_MASK;
		struct variable_head *head;
		uint16_t *name;
		uint64_t status;

		if ((entry & PCD_TYPE_HII) == 0)
			continue;
		if (!bounds(offset, 1, sizeof(*head), context->header->length))
			return PCD_INVALID_PARAMETER;
		head = (struct variable_head *)(context->database + offset);
		if ((head->property & 1U) == 0)
			continue;
		if (head->guid_index >= context->header->guid_count ||
		    !valid_variable_name(context, head->string_index))
			return PCD_INVALID_PARAMETER;
		name = (uint16_t *)(context->database + context->header->string_offset +
			head->string_index);
		status = lock_variable(name, &guid_table(context)[head->guid_index]);
		if (status != EFI_SUCCESS)
			return status;
	}
	context->lock_variable = lock_variable;
	return EFI_SUCCESS;
}
