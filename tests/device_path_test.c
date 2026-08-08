/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/device_path.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static UINT32 allocations;
static UINT32 frees;
static BOOLEAN fail_allocation;

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	(void)context;
	if (fail_allocation)
		return EFI_OUT_OF_RESOURCES;
	*buffer = malloc(size);
	if (*buffer == NULL)
		return EFI_OUT_OF_RESOURCES;
	allocations++;
	return EFI_SUCCESS;
}

static void release(void *context, void *buffer)
{
	(void)context;
	free(buffer);
	frees++;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "device-path test: %s\n", message);
	return !condition;
}

static void set_node(struct cdk2_device_path *node, UINT8 type, UINT8 subtype,
	UINT16 length)
{
	node->type = type;
	node->subtype = subtype;
	node->length[0] = (UINT8)length;
	node->length[1] = (UINT8)(length >> 8);
}

int main(void)
{
	struct cdk2_device_path_allocator allocator = {
		.allocate = allocate, .free = release,
	};
	UINT8 first_bytes[12] = {0};
	UINT8 second_bytes[10] = {0};
	struct cdk2_device_path *first = (void *)first_bytes;
	struct cdk2_device_path *second = (void *)second_bytes;
	struct cdk2_device_path *result;
	struct cdk2_device_path *node;
	const struct cdk2_device_path *cursor;
	UINTN size;
	int failures = 0;

	set_node(first, 1, 1, 8);
	set_node((void *)(first_bytes + 8), CDK2_DEVICE_PATH_END_TYPE,
		CDK2_DEVICE_PATH_END_ENTIRE, 4);
	set_node(second, 2, 3, 6);
	set_node((void *)(second_bytes + 6), CDK2_DEVICE_PATH_END_TYPE,
		CDK2_DEVICE_PATH_END_ENTIRE, 4);
	failures += expect(cdk2_device_path_size(first, sizeof(first_bytes), &size) ==
		EFI_SUCCESS && size == sizeof(first_bytes), "valid path size failed");
	first->length[0] = 3;
	failures += expect(cdk2_device_path_size(first, sizeof(first_bytes), &size) ==
		EFI_COMPROMISED_DATA, "short node accepted");
	first->length[0] = 8;
	failures += expect(cdk2_device_path_duplicate(first, &allocator, &result) ==
		EFI_SUCCESS && memcmp(result, first, sizeof(first_bytes)) == 0,
		"duplicate failed");
	release(NULL, result);
	failures += expect(cdk2_device_path_append(first, second, &allocator, &result) ==
		EFI_SUCCESS && cdk2_device_path_size(result, 18, &size) == EFI_SUCCESS &&
		size == 18, "append failed");
	release(NULL, result);
	failures += expect(cdk2_device_path_create_node(3, 4, 9, &allocator, &node) ==
		EFI_SUCCESS && cdk2_device_path_node_length(node) == 9 &&
		((UINT8 *)node)[8] == 0, "create node failed");
	failures += expect(cdk2_device_path_append_node(first, node, &allocator, &result) ==
		EFI_SUCCESS && cdk2_device_path_size(result, 21, &size) == EFI_SUCCESS &&
		size == 21, "append node failed");
	release(NULL, node);
	release(NULL, result);
	failures += expect(cdk2_device_path_append_instance(first, second, &allocator,
		&result) == EFI_SUCCESS && cdk2_device_path_is_multi_instance(result),
		"append instance failed");
	cursor = result;
	failures += expect(cdk2_device_path_next_instance(&cursor, &size, &allocator,
		&node) == EFI_SUCCESS && size == sizeof(first_bytes) && cursor != NULL &&
		!cdk2_device_path_is_multi_instance(node), "first instance failed");
	release(NULL, node);
	failures += expect(cdk2_device_path_next_instance(&cursor, &size, &allocator,
		&node) == EFI_SUCCESS && size == sizeof(second_bytes) && cursor == NULL,
		"final instance failed");
	release(NULL, node);
	release(NULL, result);
	fail_allocation = TRUE;
	result = (void *)(UINTN)1;
	failures += expect(cdk2_device_path_duplicate(first, &allocator, &result) ==
		EFI_OUT_OF_RESOURCES && result == NULL,
		"allocation failure was not contained");
	failures += expect(allocations == frees, "utility allocation leaked");
	return failures == 0 ? 0 : 1;
}
