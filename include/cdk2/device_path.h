/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_DEVICE_PATH_H_
#define CDK2_DEVICE_PATH_H_

#include <uefi.h>

#define CDK2_DEVICE_PATH_END_TYPE 0x7fU
#define CDK2_DEVICE_PATH_END_INSTANCE 0x01U
#define CDK2_DEVICE_PATH_END_ENTIRE 0xffU
#define CDK2_DEVICE_PATH_HEADER_SIZE 4U
#define CDK2_DEVICE_PATH_MAX_SIZE (1024U * 1024U)

struct cdk2_device_path {
	UINT8 type;
	UINT8 subtype;
	UINT8 length[2];
} __packed;

typedef EFI_STATUS cdk2_device_path_allocate_fn(void *context, UINTN size,
	void **buffer);
typedef void cdk2_device_path_free_fn(void *context, void *buffer);

struct cdk2_device_path_allocator {
	void *context;
	cdk2_device_path_allocate_fn *allocate;
	cdk2_device_path_free_fn *free;
};

UINT16 cdk2_device_path_node_length(const struct cdk2_device_path *node);
EFI_STATUS cdk2_device_path_size(const struct cdk2_device_path *path,
	UINTN limit, UINTN *size);
EFI_STATUS cdk2_device_path_duplicate(const struct cdk2_device_path *path,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **copy);
EFI_STATUS cdk2_device_path_append(const struct cdk2_device_path *first,
	const struct cdk2_device_path *second,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **result);
EFI_STATUS cdk2_device_path_append_node(const struct cdk2_device_path *path,
	const struct cdk2_device_path *node,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **result);
EFI_STATUS cdk2_device_path_append_instance(const struct cdk2_device_path *path,
	const struct cdk2_device_path *instance,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **result);
EFI_STATUS cdk2_device_path_next_instance(const struct cdk2_device_path **path,
	UINTN *size, const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **instance);
BOOLEAN cdk2_device_path_is_multi_instance(const struct cdk2_device_path *path);
EFI_STATUS cdk2_device_path_create_node(UINT8 type, UINT8 subtype, UINT16 length,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **node);

#endif
