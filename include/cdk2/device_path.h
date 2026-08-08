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

typedef UINTN CDK2_MS_ABI cdk2_device_path_get_size_fn(
	const struct cdk2_device_path *path);
typedef struct cdk2_device_path *CDK2_MS_ABI cdk2_device_path_duplicate_fn(
	const struct cdk2_device_path *path);
typedef struct cdk2_device_path *CDK2_MS_ABI cdk2_device_path_append_fn(
	const struct cdk2_device_path *first, const struct cdk2_device_path *second);
typedef struct cdk2_device_path *CDK2_MS_ABI cdk2_device_path_next_fn(
	struct cdk2_device_path **path, UINTN * size);
typedef BOOLEAN CDK2_MS_ABI cdk2_device_path_is_multi_fn(
	const struct cdk2_device_path *path);
typedef struct cdk2_device_path *CDK2_MS_ABI cdk2_device_path_create_fn(
	UINT8 type, UINT8 subtype, UINT16 length);
typedef CHAR16 * CDK2_MS_ABI cdk2_device_path_to_text_fn(
	const struct cdk2_device_path *path, BOOLEAN display_only, BOOLEAN shortcuts);
typedef struct cdk2_device_path *CDK2_MS_ABI cdk2_device_path_from_text_fn(
	const CHAR16 * text);

struct cdk2_device_path_utilities_protocol {
	cdk2_device_path_get_size_fn *get_size;
	cdk2_device_path_duplicate_fn *duplicate;
	cdk2_device_path_append_fn *append_path;
	cdk2_device_path_append_fn *append_node;
	cdk2_device_path_append_fn *append_instance;
	cdk2_device_path_next_fn *next_instance;
	cdk2_device_path_is_multi_fn *is_multi_instance;
	cdk2_device_path_create_fn *create_node;
};

struct cdk2_device_path_to_text_protocol {
	cdk2_device_path_to_text_fn *node_to_text;
	cdk2_device_path_to_text_fn *path_to_text;
};

struct cdk2_device_path_from_text_protocol {
	cdk2_device_path_from_text_fn *node_from_text;
	cdk2_device_path_from_text_fn *path_from_text;
};

typedef EFI_STATUS cdk2_device_path_install_fn(void *context, void **handle,
	const EFI_GUID * guid, void *interface);
typedef EFI_STATUS cdk2_device_path_uninstall_fn(void *context, void *handle,
	const EFI_GUID * guid, void *interface);

struct cdk2_device_path_publication_ops {
	void *context;
	cdk2_device_path_install_fn *install;
	cdk2_device_path_uninstall_fn *uninstall;
};

extern const EFI_GUID cdk2_device_path_utilities_protocol_guid;
extern const EFI_GUID cdk2_device_path_to_text_protocol_guid;
extern const EFI_GUID cdk2_device_path_from_text_protocol_guid;

EFI_STATUS cdk2_device_path_publish(const struct cdk2_device_path_publication_ops *ops,
	void **handle);
const struct cdk2_device_path_utilities_protocol *cdk2_device_path_utilities(void);
const struct cdk2_device_path_to_text_protocol *cdk2_device_path_text_converter(void);
const struct cdk2_device_path_from_text_protocol *cdk2_device_path_text_parser(void);

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

/* required_chars includes the terminating NUL. */
EFI_STATUS cdk2_device_path_node_to_text(const struct cdk2_device_path *node,
	UINTN node_size, BOOLEAN display_only, BOOLEAN allow_shortcuts,
	CHAR16 *text, UINTN text_chars, UINTN *required_chars);
EFI_STATUS cdk2_device_path_to_text(const struct cdk2_device_path *path,
	UINTN path_size, BOOLEAN display_only, BOOLEAN allow_shortcuts,
	CHAR16 *text, UINTN text_chars, UINTN *required_chars);
EFI_STATUS cdk2_device_path_node_from_text(const CHAR16 *text,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **node);
EFI_STATUS cdk2_device_path_from_text(const CHAR16 *text,
	const struct cdk2_device_path_allocator *allocator,
	struct cdk2_device_path **path);

#endif
