/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pcd.h>

#include <string.h>

static const EFI_GUID pcd_guid = {
	0x11b34006, 0xd85b, 0x4d0a, { 0xa2, 0x90, 0xd5, 0xa5, 0x71, 0x31, 0x0e, 0xf7 }
};
static const EFI_GUID efi_pcd_guid = {
	0x13a3f0f6, 0x264a, 0x3ef0, { 0xf2, 0xe0, 0xde, 0xc5, 0x12, 0x34, 0x2f, 0x34 }
};
static const EFI_GUID info_guid = {
	0x5be40f57, 0xfa68, 0x4610, { 0xbb, 0xbf, 0xe9, 0xc5, 0xfc, 0xda, 0xd3, 0x65 }
};
static const EFI_GUID efi_info_guid = {
	0xfd0f4478, 0x0efd, 0x461d, { 0xba, 0x2d, 0xe5, 0x8c, 0x45, 0xfd, 0x5f, 0x5e }
};
static struct cdk2_pcd_context *active;
static struct cdk2_pcd_context driver_context;
static void *pcd_handle;

typedef uint64_t CDK2_MS_ABI read_section_fn(void *, const EFI_GUID *, uint8_t,
	size_t, void **, size_t *, uint32_t *);

struct firmware_volume2_view {
	void *get_attributes, *set_attributes, *read_file;
	read_section_fn *read_section;
};

struct table_header { uint64_t signature; uint32_t revision, header_size,
	crc32, reserved; };
struct system_table_view {
	struct table_header header;
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6];
	void *runtime_services;
	struct cdk2_pcd_boot_services *boot_services;
};

static const EFI_GUID fv2_guid = {
	0x220e73b6, 0x6bdb, 0x4413, { 0x84, 0x05, 0xb9, 0x74, 0xb1, 0x08, 0x61, 0x9a }
};
static const EFI_GUID loaded_image_guid = {
	0x5b1b31a1, 0x9562, 0x11d2, { 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b }
};
static const EFI_GUID pcd_file_guid = {
	0x80cf7257, 0x87ab, 0x47f9, { 0xa3, 0xfe, 0xd5, 0x0b, 0x76, 0xd8, 0x95, 0x41 }
};

static void *get_value(const EFI_GUID *space, size_t token, size_t *size)
{
	void *value = NULL;
	size_t found = 0;

	if (active != NULL && cdk2_pcd_get(active, space, (uint32_t)token,
		&value, &found) == EFI_SUCCESS && (size == NULL || *size == found)) {
		if (size != NULL)
			*size = found;
		return value;
	}
	return NULL;
}

static void CDK2_MS_ABI abi_set_sku(size_t sku)
{
	if (active != NULL)
		(void)cdk2_pcd_set_sku(active, sku);
}

#define GET_NATIVE(bits, type) \
	static type CDK2_MS_ABI abi_get##bits(size_t token) \
	{ size_t size = sizeof(type); void *p = get_value(NULL, token, &size); \
	  type value = 0; if (p != NULL) memcpy(&value, p, sizeof(value)); return value; }
#define GET_EX(bits, type) \
	static type CDK2_MS_ABI abi_get##bits##_ex(const EFI_GUID *space, size_t token) \
	{ size_t size = sizeof(type); void *p = get_value(space, token, &size); \
	  type value = 0; if (p != NULL) memcpy(&value, p, sizeof(value)); return value; }
GET_NATIVE(8, uint8_t)
GET_NATIVE(16, uint16_t)
GET_NATIVE(32, uint32_t)
GET_NATIVE(64, uint64_t)
GET_EX(8, uint8_t)
GET_EX(16, uint16_t)
GET_EX(32, uint32_t)
GET_EX(64, uint64_t)

static void *CDK2_MS_ABI abi_get_ptr(size_t token)
{
	return get_value(NULL, token, NULL);
}

static void *CDK2_MS_ABI abi_get_ptr_ex(const EFI_GUID *space, size_t token)
{
	return get_value(space, token, NULL);
}

static size_t CDK2_MS_ABI abi_get_size(size_t token)
{
	void *value;
	size_t size = 0;

	return active != NULL && cdk2_pcd_get(active, NULL, token, &value, &size) ==
		EFI_SUCCESS ? size : 0;
}

static size_t CDK2_MS_ABI abi_get_size_ex(const EFI_GUID *space, size_t token)
{
	void *value;
	size_t size = 0;

	return active != NULL && cdk2_pcd_get(active, space, token, &value, &size) ==
		EFI_SUCCESS ? size : 0;
}

static uint64_t set_value(const EFI_GUID *space, size_t token, uint64_t value,
	size_t size)
{
	return active == NULL ? EFI_NOT_READY : cdk2_pcd_set(active, space,
		(uint32_t)token, &value, &size);
}

#define SET_NATIVE(bits, type) \
	static uint64_t CDK2_MS_ABI abi_set##bits(size_t token, type value) \
	{ return set_value(NULL, token, value, sizeof(value)); }
#define SET_EX(bits, type) \
	static uint64_t CDK2_MS_ABI abi_set##bits##_ex(const EFI_GUID *space, \
		size_t token, type value) \
	{ return set_value(space, token, value, sizeof(value)); }
SET_NATIVE(8, uint8_t)
SET_NATIVE(16, uint16_t)
SET_NATIVE(32, uint32_t)
SET_NATIVE(64, uint64_t)
SET_EX(8, uint8_t)
SET_EX(16, uint16_t)
SET_EX(32, uint32_t)
SET_EX(64, uint64_t)

static uint64_t CDK2_MS_ABI abi_set_ptr(size_t token, size_t *size, void *value)
{
	return active == NULL ? EFI_NOT_READY : cdk2_pcd_set(active, NULL, token,
		value, size);
}

static uint64_t CDK2_MS_ABI abi_set_ptr_ex(const EFI_GUID *space, size_t token,
	size_t *size, void *value)
{
	return active == NULL ? EFI_NOT_READY : cdk2_pcd_set(active, space, token,
		value, size);
}

static uint64_t CDK2_MS_ABI abi_callback(const EFI_GUID *space, size_t token,
	cdk2_pcd_callback callback)
{
	return active == NULL ? EFI_NOT_READY : cdk2_pcd_register(active, space,
		token, callback);
}

static uint64_t CDK2_MS_ABI abi_cancel(const EFI_GUID *space, size_t token,
	cdk2_pcd_callback callback)
{
	return active == NULL ? EFI_NOT_READY : cdk2_pcd_unregister(active, space,
		token, callback);
}

static uint64_t CDK2_MS_ABI abi_next(const EFI_GUID *space, size_t *token)
{
	uint32_t current;
	uint64_t status;

	if (active == NULL || token == NULL || *token > UINT32_MAX)
		return EFI_INVALID_PARAMETER;
	current = (uint32_t)*token;
	status = cdk2_pcd_next_token(active, space, &current);
	*token = current;
	return status;
}

static uint64_t CDK2_MS_ABI abi_next_space(const EFI_GUID **space)
{
	size_t index;
	EFI_GUID *table;

	if (active == NULL || space == NULL)
		return EFI_INVALID_PARAMETER;
	table = (EFI_GUID *)(active->database + active->header->guid_offset);
	if (*space == NULL) {
		if (active->header->guid_count == 0)
			return EFI_NOT_FOUND;
		*space = table;
		return EFI_SUCCESS;
	}
	for (index = 0; index + 1 < active->header->guid_count; index++)
		if (memcmp(*space, &table[index], sizeof(**space)) == 0) {
			*space = &table[index + 1];
			return EFI_SUCCESS;
		}
	return EFI_NOT_FOUND;
}

static uint64_t info_common(const EFI_GUID *space, size_t token,
	struct cdk2_pcd_info *info)
{
	void *value;
	size_t size;
	uint64_t status;

	if (info == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_pcd_get(active, space, token, &value, &size);
	if (status != EFI_SUCCESS)
		return status;
	info->pcd_type = 0;
	info->pcd_size = size;
	info->pcd_name = NULL;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI abi_info(size_t token, struct cdk2_pcd_info *info)
{
	return info_common(NULL, token, info);
}

static uint64_t CDK2_MS_ABI abi_info_ex(const EFI_GUID *space, size_t token,
	struct cdk2_pcd_info *info)
{
	return info_common(space, token, info);
}

static size_t CDK2_MS_ABI abi_sku(void)
{
	return active == NULL ? 0 : active->header->system_sku_id;
}

static struct cdk2_pcd_protocol native_protocol = {
	abi_set_sku, abi_get8, abi_get16, abi_get32, abi_get64, abi_get_ptr,
	abi_get8, abi_get_size,
	{ abi_get8_ex, abi_get16_ex, abi_get32_ex, abi_get64_ex, abi_get_ptr_ex,
	  abi_get8_ex, abi_get_size_ex },
	abi_set8, abi_set16, abi_set32, abi_set64, abi_set_ptr, abi_set8,
	{ abi_set8_ex, abi_set16_ex, abi_set32_ex, abi_set64_ex, abi_set_ptr_ex,
	  abi_set8_ex }, abi_callback, abi_cancel, abi_next, abi_next_space
};
static struct cdk2_efi_pcd_protocol pi_protocol = {
	abi_set_sku,
	{ abi_get8_ex, abi_get16_ex, abi_get32_ex, abi_get64_ex, abi_get_ptr_ex,
	  abi_get8_ex, abi_get_size_ex },
	{ abi_set8_ex, abi_set16_ex, abi_set32_ex, abi_set64_ex, abi_set_ptr_ex,
	  abi_set8_ex }, abi_callback, abi_cancel, abi_next, abi_next_space
};
static struct cdk2_get_pcd_info_protocol info_protocol = {
	abi_info, abi_info_ex, abi_sku
};
static struct cdk2_efi_get_pcd_info_protocol pi_info_protocol = {
	abi_info_ex, abi_sku
};

uint64_t cdk2_pcd_publish(struct cdk2_pcd_context *context,
	struct cdk2_pcd_boot_services *boot_services)
{
	uint64_t status;

	if (context == NULL || context->header == NULL || boot_services == NULL ||
	    boot_services->install_multiple_protocols == NULL)
		return EFI_INVALID_PARAMETER;
	active = context;
	status = boot_services->install_multiple_protocols(&pcd_handle, &pcd_guid,
		&native_protocol, &efi_pcd_guid, &pi_protocol, NULL);
	if (status != EFI_SUCCESS)
		goto fail;
	status = boot_services->install_multiple_protocols(&pcd_handle, &info_guid,
		&info_protocol, &efi_info_guid, &pi_info_protocol, NULL);
	if (status == EFI_SUCCESS)
		return status;
	if (boot_services->uninstall_multiple_protocols != NULL)
		(void)boot_services->uninstall_multiple_protocols(pcd_handle, &pcd_guid,
			&native_protocol, &efi_pcd_guid, &pi_protocol, NULL);
fail:
	active = NULL;
	pcd_handle = NULL;
	return status;
}

uint64_t CDK2_MS_ABI cdk2_pcd_driver_entry(void *image_handle,
	void *system_table)
{
	struct system_table_view *table = system_table;
	struct firmware_volume2_view *volume = NULL;
	struct { uint32_t revision, pad; void *parent, *system, *device; } *loaded = NULL;
	void *database = NULL;
	size_t size = 0;
	uint32_t authentication = 0;
	uint64_t status;

	(void)image_handle;
	if (table == NULL || table->boot_services == NULL ||
	    table->boot_services->handle_protocol == NULL)
		return EFI_INVALID_PARAMETER;
	status = table->boot_services->handle_protocol(image_handle,
		&loaded_image_guid, (void **)&loaded);
	if (status != EFI_SUCCESS)
		return status;
	if (loaded == NULL || loaded->device == NULL)
		return EFI_NOT_FOUND;
	status = table->boot_services->handle_protocol(loaded->device, &fv2_guid,
		(void **)&volume);
	if (status != EFI_SUCCESS)
		return status;
	if (volume == NULL || volume->read_section == NULL)
		return EFI_NOT_FOUND;
	status = volume->read_section(volume, &pcd_file_guid, 0x19, 0, &database,
		&size, &authentication);
	if (status != EFI_SUCCESS)
		return status;
	if (authentication != 0)
		return EFI_SECURITY_VIOLATION;
	status = cdk2_pcd_init(&driver_context, database, size);
	if (status != EFI_SUCCESS)
		return status;
	return cdk2_pcd_publish(&driver_context, table->boot_services);
}
