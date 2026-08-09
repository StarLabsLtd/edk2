/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/device_path.h>

static void copy_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *out = destination;
	const UINT8 *in = source;
	UINTN index;
	for (index = 0; index < size; index++)
		out[index] = in[index];
}

static void zero_bytes(void *buffer, UINTN size)
{
	UINT8 *bytes = buffer;
	UINTN index;
	for (index = 0; index < size; index++)
		bytes[index] = 0;
}

static BOOLEAN allocator_valid(const struct cdk2_device_path_allocator *allocator)
{
	return allocator != NULL && allocator->allocate != NULL && allocator->free != NULL;
}

static BOOLEAN end_entire(const struct cdk2_device_path *node)
{
	return node->type == CDK2_DEVICE_PATH_END_TYPE &&
		node->subtype == CDK2_DEVICE_PATH_END_ENTIRE;
}

static BOOLEAN end_instance(const struct cdk2_device_path *node)
{
	return node->type == CDK2_DEVICE_PATH_END_TYPE &&
		node->subtype == CDK2_DEVICE_PATH_END_INSTANCE;
}

static void set_end(struct cdk2_device_path *node, UINT8 subtype)
{
	node->type = CDK2_DEVICE_PATH_END_TYPE;
	node->subtype = subtype;
	node->length[0] = CDK2_DEVICE_PATH_HEADER_SIZE;
	node->length[1] = 0;
}

UINT16 cdk2_device_path_node_length(const struct cdk2_device_path *node)
{
	return node == NULL ? 0 : (UINT16)node->length[0] | (UINT16)node->length[1] << 8;
}

EFI_STATUS cdk2_device_path_size(const struct cdk2_device_path *path,
	UINTN limit, UINTN *size)
{
	UINTN used = 0;
	UINT16 length;
	if (path == NULL || size == NULL || limit < CDK2_DEVICE_PATH_HEADER_SIZE ||
	    limit > CDK2_DEVICE_PATH_MAX_SIZE)
		return EFI_INVALID_PARAMETER;
	for (;;) {
		if (used > limit - CDK2_DEVICE_PATH_HEADER_SIZE)
			return EFI_COMPROMISED_DATA;
		length = cdk2_device_path_node_length((const void *)((const UINT8 *)path + used));
		if (length < CDK2_DEVICE_PATH_HEADER_SIZE || length > limit - used)
			return EFI_COMPROMISED_DATA;
		used += length;
		if (end_entire((const void *)((const UINT8 *)path + used - length))) {
			*size = used;
			return EFI_SUCCESS;
		}
	}
}

static EFI_STATUS path_size(const struct cdk2_device_path *path, UINTN *size)
{
	return cdk2_device_path_size(path, CDK2_DEVICE_PATH_MAX_SIZE, size);
}

EFI_STATUS cdk2_device_path_duplicate(const struct cdk2_device_path *path,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **copy)
{
	UINTN size;
	EFI_STATUS status;
	if (!allocator_valid(allocator) || copy == NULL)
		return EFI_INVALID_PARAMETER;
	*copy = NULL;
	status = path_size(path, &size);
	if (EFI_ERROR(status))
		return status;
	status = allocator->allocate(allocator->context, size, (void **)copy);
	if (!EFI_ERROR(status))
		copy_bytes(*copy, path, size);
	return status;
}

EFI_STATUS cdk2_device_path_append(const struct cdk2_device_path *first,
	const struct cdk2_device_path *second,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **result)
{
	UINTN first_size;
	UINTN second_size;
	UINTN total;
	EFI_STATUS status;
	if (first == NULL)
		return cdk2_device_path_duplicate(second, allocator, result);
	if (second == NULL)
		return cdk2_device_path_duplicate(first, allocator, result);
	if (!allocator_valid(allocator) || result == NULL)
		return EFI_INVALID_PARAMETER;
	status = path_size(first, &first_size);
	if (EFI_ERROR(status))
		return status;
	status = path_size(second, &second_size);
	if (EFI_ERROR(status))
		return status;
	if (first_size > MAX_UINTN - second_size + CDK2_DEVICE_PATH_HEADER_SIZE)
		return EFI_OUT_OF_RESOURCES;
	total = first_size + second_size - CDK2_DEVICE_PATH_HEADER_SIZE;
	*result = NULL;
	status = allocator->allocate(allocator->context, total, (void **)result);
	if (EFI_ERROR(status))
		return status;
	copy_bytes(*result, first, first_size - CDK2_DEVICE_PATH_HEADER_SIZE);
	copy_bytes((UINT8 *)*result + first_size - CDK2_DEVICE_PATH_HEADER_SIZE,
		second, second_size);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_device_path_create_node(UINT8 type, UINT8 subtype, UINT16 length,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **node)
{
	EFI_STATUS status;
	if (!allocator_valid(allocator) || node == NULL ||
	    length < CDK2_DEVICE_PATH_HEADER_SIZE)
		return EFI_INVALID_PARAMETER;
	*node = NULL;
	status = allocator->allocate(allocator->context, length, (void **)node);
	if (EFI_ERROR(status))
		return status;
	zero_bytes(*node, length);
	(*node)->type = type;
	(*node)->subtype = subtype;
	(*node)->length[0] = (UINT8)length;
	(*node)->length[1] = (UINT8)(length >> 8);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_device_path_append_node(const struct cdk2_device_path *path,
	const struct cdk2_device_path *node,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **result)
{
	struct cdk2_device_path *temporary;
	UINT16 length;
	EFI_STATUS status;
	if (node == NULL || !allocator_valid(allocator) || result == NULL)
		return EFI_INVALID_PARAMETER;
	length = cdk2_device_path_node_length(node);
	if (length < CDK2_DEVICE_PATH_HEADER_SIZE)
		return EFI_COMPROMISED_DATA;
	status = allocator->allocate(allocator->context,
		length + CDK2_DEVICE_PATH_HEADER_SIZE, (void **)&temporary);
	if (EFI_ERROR(status))
		return status;
	copy_bytes(temporary, node, length);
	set_end((void *)((UINT8 *)temporary + length), CDK2_DEVICE_PATH_END_ENTIRE);
	status = cdk2_device_path_append(path, temporary, allocator, result);
	allocator->free(allocator->context, temporary);
	return status;
}

EFI_STATUS cdk2_device_path_append_instance(const struct cdk2_device_path *path,
	const struct cdk2_device_path *instance,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **result)
{
	UINTN path_length;
	UINTN instance_length;
	UINTN total;
	EFI_STATUS status;
	if (path == NULL)
		return cdk2_device_path_duplicate(instance, allocator, result);
	if (instance == NULL || !allocator_valid(allocator) || result == NULL)
		return EFI_INVALID_PARAMETER;
	status = path_size(path, &path_length);
	if (EFI_ERROR(status))
		return status;
	status = path_size(instance, &instance_length);
	if (EFI_ERROR(status))
		return status;
	if (path_length > MAX_UINTN - instance_length)
		return EFI_OUT_OF_RESOURCES;
	total = path_length + instance_length;
	status = allocator->allocate(allocator->context, total, (void **)result);
	if (EFI_ERROR(status))
		return status;
	copy_bytes(*result, path, path_length);
	set_end((void *)((UINT8 *)*result + path_length - CDK2_DEVICE_PATH_HEADER_SIZE),
		CDK2_DEVICE_PATH_END_INSTANCE);
	copy_bytes((UINT8 *)*result + path_length, instance, instance_length);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_device_path_next_instance(const struct cdk2_device_path **path,
	UINTN *size, const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **instance)
{
	const struct cdk2_device_path *node;
	UINTN used = 0;
	UINT16 length;
	EFI_STATUS status;
	if (path == NULL || *path == NULL || size == NULL || instance == NULL ||
	    !allocator_valid(allocator))
		return EFI_INVALID_PARAMETER;
	for (;;) {
		if (used > CDK2_DEVICE_PATH_MAX_SIZE - CDK2_DEVICE_PATH_HEADER_SIZE)
			return EFI_COMPROMISED_DATA;
		node = (const void *)((const UINT8 *)*path + used);
		length = cdk2_device_path_node_length(node);
		if (length < CDK2_DEVICE_PATH_HEADER_SIZE ||
		    used > CDK2_DEVICE_PATH_MAX_SIZE - length)
			return EFI_COMPROMISED_DATA;
		used += length;
		if (end_instance(node) || end_entire(node))
			break;
	}
	status = allocator->allocate(allocator->context, used, (void **)instance);
	if (EFI_ERROR(status))
		return status;
	copy_bytes(*instance, *path, used);
	set_end((void *)((UINT8 *)*instance + used - CDK2_DEVICE_PATH_HEADER_SIZE),
		CDK2_DEVICE_PATH_END_ENTIRE);
	*size = used;
	*path = end_entire(node) ? NULL : (const void *)((const UINT8 *)*path + used);
	return EFI_SUCCESS;
}

BOOLEAN cdk2_device_path_is_multi_instance(const struct cdk2_device_path *path)
{
	UINTN used = 0;
	UINT16 length;
	if (path == NULL)
		return FALSE;
	for (;;) {
		if (used > CDK2_DEVICE_PATH_MAX_SIZE - CDK2_DEVICE_PATH_HEADER_SIZE)
			return FALSE;
		length = cdk2_device_path_node_length((const void *)((const UINT8 *)path + used));
		if (length < CDK2_DEVICE_PATH_HEADER_SIZE ||
		    used > CDK2_DEVICE_PATH_MAX_SIZE - length)
			return FALSE;
		if (end_instance((const void *)((const UINT8 *)path + used)))
			return TRUE;
		if (end_entire((const void *)((const UINT8 *)path + used)))
			return FALSE;
		used += length;
	}
}
