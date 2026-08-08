/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/device_path.h>

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);

struct boot_services_view {
	UINT8 header[24];
	void *slots_before_allocate[5];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	void *slots_before_install_multiple[34];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};

struct system_table_view {
	UINT8 before_boot_services[96];
	struct boot_services_view *boot;
};

typedef char allocate_offset_check[
	OFFSET_OF(struct boot_services_view, allocate_pool) == 64 ? 1 : -1];
typedef char install_offset_check[
	OFFSET_OF(struct boot_services_view, install_multiple) == 352 ? 1 : -1];
typedef char boot_offset_check[
	OFFSET_OF(struct system_table_view, boot) == 96 ? 1 : -1];
typedef char utilities_abi_size_check[
	sizeof(struct cdk2_device_path_utilities_protocol) == 64 ? 1 : -1];
typedef char to_text_abi_size_check[
	sizeof(struct cdk2_device_path_to_text_protocol) == 16 ? 1 : -1];
typedef char from_text_abi_size_check[
	sizeof(struct cdk2_device_path_from_text_protocol) == 16 ? 1 : -1];

const EFI_GUID cdk2_device_path_utilities_protocol_guid = {
	0x0379be4e, 0xd706, 0x437d,
	{0xb0, 0x37, 0xed, 0xb8, 0x2f, 0xb7, 0x72, 0xa4}
};
const EFI_GUID cdk2_device_path_to_text_protocol_guid = {
	0x8b843e20, 0x8132, 0x4852,
	{0x90, 0xcc, 0x55, 0x1a, 0x4e, 0x4a, 0x7f, 0x1c}
};
const EFI_GUID cdk2_device_path_from_text_protocol_guid = {
	0x05c99a21, 0xc70f, 0x4ad2,
	{0x8a, 0x5f, 0x35, 0xdf, 0x33, 0x43, 0xf5, 0x1e}
};

static struct boot_services_view *boot;

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	(void)context;
	return boot->allocate_pool(4U, size, buffer);
}

static void release(void *context, void *buffer)
{
	(void)context;
	(void)boot->free_pool(buffer);
}

static const struct cdk2_device_path_allocator allocator = {
	.allocate = allocate,
	.free = release,
};

static UINTN CDK2_MS_ABI get_size(const struct cdk2_device_path *path)
{
	UINTN size;
	return cdk2_device_path_size(path, CDK2_DEVICE_PATH_MAX_SIZE, &size) == EFI_SUCCESS ?
		size : 0;
}

static struct cdk2_device_path *CDK2_MS_ABI duplicate(
	const struct cdk2_device_path *path)
{
	struct cdk2_device_path *result = NULL;
	(void)cdk2_device_path_duplicate(path, &allocator, &result);
	return result;
}

static struct cdk2_device_path *end_path(void)
{
	struct cdk2_device_path *result = NULL;
	if (cdk2_device_path_create_node(CDK2_DEVICE_PATH_END_TYPE,
	    CDK2_DEVICE_PATH_END_ENTIRE, 4, &allocator, &result) != EFI_SUCCESS)
		return NULL;
	return result;
}

static struct cdk2_device_path *CDK2_MS_ABI append_path(
	const struct cdk2_device_path *first, const struct cdk2_device_path *second)
{
	struct cdk2_device_path *result = NULL;
	if (first == NULL && second == NULL)
		return end_path();
	(void)cdk2_device_path_append(first, second, &allocator, &result);
	return result;
}

static struct cdk2_device_path *CDK2_MS_ABI append_node(
	const struct cdk2_device_path *path, const struct cdk2_device_path *node)
{
	struct cdk2_device_path *result = NULL;
	if (node == NULL)
		return path == NULL ? end_path() : duplicate(path);
	(void)cdk2_device_path_append_node(path, node, &allocator, &result);
	return result;
}

static struct cdk2_device_path *CDK2_MS_ABI append_instance(
	const struct cdk2_device_path *path, const struct cdk2_device_path *instance)
{
	struct cdk2_device_path *result = NULL;
	(void)cdk2_device_path_append_instance(path, instance, &allocator, &result);
	return result;
}

static struct cdk2_device_path *CDK2_MS_ABI next_instance(
	struct cdk2_device_path **path, UINTN *size)
{
	const struct cdk2_device_path *cursor;
	struct cdk2_device_path *result = NULL;
	UINTN local_size;
	if (path == NULL || *path == NULL)
		return NULL;
	cursor = *path;
	if (cdk2_device_path_next_instance(&cursor, &local_size, &allocator,
	    &result) != EFI_SUCCESS)
		return NULL;
	*path = (struct cdk2_device_path *)cursor;
	if (size != NULL)
		*size = local_size;
	return result;
}

static BOOLEAN CDK2_MS_ABI is_multi(const struct cdk2_device_path *path)
{
	return cdk2_device_path_is_multi_instance(path);
}

static struct cdk2_device_path *CDK2_MS_ABI create_node(UINT8 type,
	UINT8 subtype, UINT16 length)
{
	struct cdk2_device_path *result = NULL;
	(void)cdk2_device_path_create_node(type, subtype, length, &allocator, &result);
	return result;
}

static CHAR16 *node_text(const struct cdk2_device_path *path, BOOLEAN display,
	BOOLEAN shortcuts, BOOLEAN whole_path)
{
	CHAR16 *text = NULL;
	UINTN required;
	UINTN size;
	EFI_STATUS status;
	if (path == NULL)
		return NULL;
	if (whole_path) {
		if (cdk2_device_path_size(path, CDK2_DEVICE_PATH_MAX_SIZE, &size) != EFI_SUCCESS)
			return NULL;
		status = cdk2_device_path_to_text(path, size, display, shortcuts,
			NULL, 0, &required);
	} else {
		size = cdk2_device_path_node_length(path);
		status = cdk2_device_path_node_to_text(path, size, display, shortcuts,
			NULL, 0, &required);
	}
	if (status != EFI_BUFFER_TOO_SMALL || required > MAX_UINTN / sizeof(*text) ||
	    boot->allocate_pool(4U, required * sizeof(*text), (void **)&text) != EFI_SUCCESS)
		return NULL;
	status = whole_path ? cdk2_device_path_to_text(path, size, display, shortcuts,
		text, required, &required) :
		cdk2_device_path_node_to_text(path, size, display, shortcuts,
		text, required, &required);
	if (EFI_ERROR(status)) {
		(void)boot->free_pool(text);
		return NULL;
	}
	return text;
}

static CHAR16 *CDK2_MS_ABI node_to_text(const struct cdk2_device_path *path,
	BOOLEAN display, BOOLEAN shortcuts)
{
	return node_text(path, display, shortcuts, FALSE);
}

static CHAR16 *CDK2_MS_ABI path_to_text(const struct cdk2_device_path *path,
	BOOLEAN display, BOOLEAN shortcuts)
{
	return node_text(path, display, shortcuts, TRUE);
}

static struct cdk2_device_path *CDK2_MS_ABI node_from_text(const CHAR16 *text)
{
	struct cdk2_device_path *result = NULL;
	(void)cdk2_device_path_node_from_text(text, &allocator, &result);
	return result;
}

static struct cdk2_device_path *CDK2_MS_ABI path_from_text(const CHAR16 *text)
{
	struct cdk2_device_path *result = NULL;
	(void)cdk2_device_path_from_text(text, &allocator, &result);
	return result;
}

static const struct cdk2_device_path_utilities_protocol utilities = {
	get_size, duplicate, append_path, append_node, append_instance,
	next_instance, is_multi, create_node,
};
static const struct cdk2_device_path_to_text_protocol to_text = {
	node_to_text, path_to_text,
};
static const struct cdk2_device_path_from_text_protocol from_text = {
	node_from_text, path_from_text,
};

const struct cdk2_device_path_utilities_protocol *cdk2_device_path_utilities(void)
{
	return &utilities;
}

const struct cdk2_device_path_to_text_protocol *cdk2_device_path_text_converter(void)
{
	return &to_text;
}

const struct cdk2_device_path_from_text_protocol *cdk2_device_path_text_parser(void)
{
	return &from_text;
}

EFI_STATUS cdk2_device_path_publish(const struct cdk2_device_path_publication_ops *ops,
	void **handle)
{
	const EFI_GUID *guids[] = {&cdk2_device_path_utilities_protocol_guid,
		&cdk2_device_path_to_text_protocol_guid,
		&cdk2_device_path_from_text_protocol_guid};
	void *interfaces[] = {(void *)&utilities, (void *)&to_text, (void *)&from_text};
	UINTN installed = 0;
	EFI_STATUS status;
	if (ops == NULL || ops->install == NULL || ops->uninstall == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	while (installed < ARRAY_SIZE(guids)) {
		status = ops->install(ops->context, handle, guids[installed],
			interfaces[installed]);
		if (EFI_ERROR(status)) {
			while (installed != 0) {
				installed--;
				(void)ops->uninstall(ops->context, *handle, guids[installed],
					interfaces[installed]);
			}
			return status;
		}
		installed++;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS install(void *context, void **handle, const EFI_GUID *guid,
	void *interface)
{
	struct boot_services_view *services = context;
	return services->install_multiple(handle, guid, interface, NULL);
}

static EFI_STATUS uninstall(void *context, void *handle, const EFI_GUID *guid,
	void *interface)
{
	struct boot_services_view *services = context;
	return services->uninstall_multiple(handle, guid, interface, NULL);
}

EFI_STATUS CDK2_MS_ABI cdk2_device_path_entry(void *image,
	struct system_table_view *system)
{
	struct cdk2_device_path_publication_ops ops;
	void *handle = image;
	if (system == NULL || system->boot == NULL ||
	    system->boot->allocate_pool == NULL || system->boot->free_pool == NULL ||
	    system->boot->install_multiple == NULL ||
	    system->boot->uninstall_multiple == NULL)
		return EFI_INVALID_PARAMETER;
	boot = system->boot;
	ops.context = boot;
	ops.install = install;
	ops.uninstall = uninstall;
	return cdk2_device_path_publish(&ops, &handle);
}
