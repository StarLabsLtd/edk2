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
static struct variable_policy_view *active_variable_policy;
static struct cdk2_pcd_context *locking_context;

typedef uint64_t CDK2_MS_ABI read_section_fn(void *, const EFI_GUID *, uint8_t,
	size_t, void **, size_t *, uint32_t *);

struct firmware_volume2_view {
	void *get_attributes, *set_attributes, *read_file;
	read_section_fn *read_section;
};

struct table_header {
	uint64_t signature;
	uint32_t revision;
	uint32_t header_size;
	uint32_t crc32;
	uint32_t reserved;
};
struct system_table_view {
	struct table_header header;
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6];
	void *runtime_services;
	struct cdk2_pcd_boot_services *boot_services;
	size_t table_count;
	struct configuration_table_view *tables;
};

struct configuration_table_view {
	EFI_GUID guid;
	void *table;
};

struct hob_header {
	uint16_t type, length;
	uint32_t reserved;
};

struct guid_hob {
	struct hob_header header;
	EFI_GUID guid;
};

struct runtime_services_view {
	struct table_header header;
	void *time_services[6];
	cdk2_pcd_get_variable_fn *get_variable;
	void *get_next_variable_name;
	cdk2_pcd_set_variable_fn *set_variable;
};

typedef uint64_t CDK2_MS_ABI register_policy_fn(const void *);
struct variable_policy_view {
	uint64_t revision;
	void *disable, *enabled;
	register_policy_fn *register_policy;
};

#pragma pack(push, 1)
struct variable_policy_entry {
	uint32_t version;
	uint16_t size, name_offset;
	EFI_GUID namespace;
	uint32_t minimum_size, maximum_size;
	uint32_t attributes_must_have, attributes_cant_have;
	uint8_t lock_type, padding[3];
};
#pragma pack(pop)

static const EFI_GUID module_token_space = {
	0xa1aff049, 0xfdeb, 0x442a, { 0xb3, 0x20, 0x13, 0xab, 0x4c, 0xb7, 0x2b, 0xbc }
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
static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID pcd_hob_guid = {
	0xea296d92, 0x0b69, 0x423c, { 0x8c, 0x28, 0x33, 0xb4, 0xe0, 0xa9, 0x12, 0x68 }
};
static const EFI_GUID variable_policy_guid = {
	0x81d1675c, 0x86f6, 0x48df, { 0xbd, 0x95, 0x9a, 0x6e, 0x4f, 0x09, 0x25, 0xc3 }
};

#define EFI_AUTH_STATUS_TEST_FAILED 0x00000008U

static int same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

static uint64_t merge_pei_pcd_hob(struct cdk2_pcd_context *context,
	struct system_table_view *table)
{
	struct hob_header *hob = NULL;
	size_t index;

	if (table->table_count != 0 && table->tables == NULL)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < table->table_count; index++)
		if (same_guid(&table->tables[index].guid, &hob_list_guid)) {
			hob = table->tables[index].table;
			break;
		}
	while (hob != NULL && hob->type != 0xffffU) {
		struct guid_hob *guid;

		if (hob->length < sizeof(*hob) || (hob->length & 7U) != 0)
			return EFI_COMPROMISED_DATA;
		if (hob->type == 4U) {
			if (hob->length < sizeof(*guid))
				return EFI_COMPROMISED_DATA;
			guid = (struct guid_hob *)hob;
			if (same_guid(&guid->guid, &pcd_hob_guid))
				return cdk2_pcd_merge_hob(context, guid + 1,
					hob->length - sizeof(*guid));
		}
		hob = (struct hob_header *)((uint8_t *)hob + hob->length);
	}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI register_read_only_variable(const uint16_t *name,
	const EFI_GUID *guid)
{
	struct variable_policy_entry *entry;
	size_t length = 0, bytes, available;
	void *allocation;
	uint64_t status;

	if (locking_context == NULL || active_variable_policy == NULL ||
	    active_variable_policy->register_policy == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if ((const uint8_t *)name < locking_context->database ||
	    (const uint8_t *)name >= locking_context->database +
		locking_context->header->length)
		return EFI_COMPROMISED_DATA;
	available = (size_t)(locking_context->database + locking_context->header->length -
		(const uint8_t *)name) / sizeof(*name);
	while (length < available && name[length] != 0)
		length++;
	if (length == available || length > (UINT16_MAX - sizeof(*entry)) /
		sizeof(*name))
		return EFI_COMPROMISED_DATA;
	bytes = sizeof(*entry) + (length + 1) * sizeof(*name);
	status = locking_context->allocate_pool(4U, bytes, &allocation);
	if (status != EFI_SUCCESS)
		return status;
	entry = allocation;
	memset(entry, 0, sizeof(*entry));
	entry->version = 0x00010000U;
	entry->size = (uint16_t)bytes;
	entry->name_offset = sizeof(*entry);
	entry->namespace = *guid;
	entry->maximum_size = UINT32_MAX;
	entry->lock_type = 1U;
	memcpy((uint8_t *)entry + sizeof(*entry), name,
		(length + 1) * sizeof(*name));
	status = active_variable_policy->register_policy(entry);
	(void)locking_context->free_pool(entry);
	return status;
}

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
	if (active != NULL) {
		uint64_t status = sku == 0 ? EFI_NOT_FOUND :
			cdk2_pcd_apply_sku_delta(active, sku);

		if (status == EFI_NOT_FOUND)
			(void)cdk2_pcd_set_sku(active, sku);
	}
}

static uint64_t get_scalar(const EFI_GUID *space, size_t token, size_t size)
{
	uint64_t value = 0;
	void *source = get_value(space, token, &size);
	uint8_t *destination = (uint8_t *)&value;
	const uint8_t *bytes = source;
	size_t index;

	if (source != NULL)
		for (index = 0; index < size; index++)
			destination[index] = bytes[index];
	return value;
}

static uint8_t CDK2_MS_ABI abi_get8(size_t token)
{
	return (uint8_t)get_scalar(NULL, token, sizeof(uint8_t));
}

static uint16_t CDK2_MS_ABI abi_get16(size_t token)
{
	return (uint16_t)get_scalar(NULL, token, sizeof(uint16_t));
}

static uint32_t CDK2_MS_ABI abi_get32(size_t token)
{
	return (uint32_t)get_scalar(NULL, token, sizeof(uint32_t));
}

static uint64_t CDK2_MS_ABI abi_get64(size_t token)
{
	return get_scalar(NULL, token, sizeof(uint64_t));
}

static uint8_t CDK2_MS_ABI abi_get8_ex(const EFI_GUID *space, size_t token)
{
	return (uint8_t)get_scalar(space, token, sizeof(uint8_t));
}

static uint16_t CDK2_MS_ABI abi_get16_ex(const EFI_GUID *space, size_t token)
{
	return (uint16_t)get_scalar(space, token, sizeof(uint16_t));
}

static uint32_t CDK2_MS_ABI abi_get32_ex(const EFI_GUID *space, size_t token)
{
	return (uint32_t)get_scalar(space, token, sizeof(uint32_t));
}

static uint64_t CDK2_MS_ABI abi_get64_ex(const EFI_GUID *space, size_t token)
{
	return get_scalar(space, token, sizeof(uint64_t));
}

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

static uint64_t CDK2_MS_ABI abi_set8(size_t token, uint8_t value)
{
	return set_value(NULL, token, value, sizeof(value));
}

static uint64_t CDK2_MS_ABI abi_set16(size_t token, uint16_t value)
{
	return set_value(NULL, token, value, sizeof(value));
}

static uint64_t CDK2_MS_ABI abi_set32(size_t token, uint32_t value)
{
	return set_value(NULL, token, value, sizeof(value));
}

static uint64_t CDK2_MS_ABI abi_set64(size_t token, uint64_t value)
{
	return set_value(NULL, token, value, sizeof(value));
}

static uint64_t CDK2_MS_ABI abi_set8_ex(const EFI_GUID *space, size_t token,
	uint8_t value)
{
	return set_value(space, token, value, sizeof(value));
}

static uint64_t CDK2_MS_ABI abi_set16_ex(const EFI_GUID *space, size_t token,
	uint16_t value)
{
	return set_value(space, token, value, sizeof(value));
}

static uint64_t CDK2_MS_ABI abi_set32_ex(const EFI_GUID *space, size_t token,
	uint32_t value)
{
	return set_value(space, token, value, sizeof(value));
}

static uint64_t CDK2_MS_ABI abi_set64_ex(const EFI_GUID *space, size_t token,
	uint64_t value)
{
	return set_value(space, token, value, sizeof(value));
}

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
	size_t index, prior;
	EFI_GUID *table;
	struct cdk2_pcd_ex_map *maps;
	int after;

	if (active == NULL || space == NULL)
		return EFI_INVALID_PARAMETER;
	table = (EFI_GUID *)(active->database + active->header->guid_offset);
	maps = (struct cdk2_pcd_ex_map *)(active->database + active->header->ex_map_offset);
	after = *space == NULL;
	for (index = 0; index < active->header->ex_token_count; index++) {
		if (maps[index].guid_index >= active->header->guid_count)
			return EFI_COMPROMISED_DATA;
		if (!after) {
			if (memcmp(*space, &table[maps[index].guid_index], sizeof(**space)) == 0)
				after = 1;
			continue;
		}
		if (after) {
			for (prior = 0; prior < index; prior++)
				if (maps[prior].guid_index < active->header->guid_count &&
				    memcmp(&table[maps[prior].guid_index],
					&table[maps[index].guid_index], sizeof(*table)) == 0)
					break;
			if (prior == index) {
				*space = &table[maps[index].guid_index];
				return EFI_SUCCESS;
			}
		}
	}
	return EFI_NOT_FOUND;
}

static uint64_t info_common(const EFI_GUID *space, size_t token,
	struct cdk2_pcd_info *info)
{
	size_t size;
	size_t type;
	uint64_t status;

	if (info == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_pcd_get_info(active, space, token, &type, &size);
	if (status != EFI_SUCCESS)
		return status;
	info->pcd_type = type;
	info->pcd_size = size;
	status = cdk2_pcd_get_name(active, space, (uint32_t)token, &info->pcd_name);
	if (status != EFI_SUCCESS && status != EFI_NOT_FOUND)
		return status;
	if (status == EFI_NOT_FOUND)
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
	void *expanded = NULL;
	size_t size = 0;
	size_t expanded_size;
	size_t index;
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
	if ((authentication & EFI_AUTH_STATUS_TEST_FAILED) != 0) {
		status = EFI_SECURITY_VIOLATION;
		goto free_database;
	}
	if (database == NULL || size < sizeof(struct cdk2_pcd_database_header))
		status = EFI_COMPROMISED_DATA;
	else {
		struct cdk2_pcd_database_header *header = database;

		if (header->length > size || header->uninitialized_size > SIZE_MAX - size)
			status = EFI_COMPROMISED_DATA;
		else if (table->boot_services->allocate_pool == NULL)
			status = EFI_UNSUPPORTED;
		else {
			expanded_size = size + header->uninitialized_size;
			status = table->boot_services->allocate_pool(4U, expanded_size, &expanded);
			if (status == EFI_SUCCESS) {
				for (index = 0; index < size; index++)
					((uint8_t *)expanded)[index] = ((uint8_t *)database)[index];
				for (; index < expanded_size; index++)
					((uint8_t *)expanded)[index] = 0;
			}
		}
	}
free_database:
	if (table->boot_services->free_pool != NULL)
		(void)table->boot_services->free_pool(database);
	if (status != EFI_SUCCESS)
		return status;
	status = cdk2_pcd_init(&driver_context, expanded, expanded_size);
	if (status != EFI_SUCCESS)
		goto free_expanded;
	driver_context.allocate_pool = table->boot_services->allocate_pool;
	driver_context.free_pool = table->boot_services->free_pool;
	status = merge_pei_pcd_hob(&driver_context, table);
	if (status != EFI_SUCCESS)
		goto free_expanded;
	if (table->runtime_services != NULL) {
		struct runtime_services_view *runtime = table->runtime_services;
		void *vpd_value;
		size_t vpd_width;
		uint8_t *vpd = NULL;
		size_t vpd_size = 0;

		if (cdk2_pcd_get(&driver_context, &module_token_space, 0x00030006U,
		    &vpd_value, &vpd_width) == EFI_SUCCESS && vpd_width == 8) {
			uint64_t address;
			memcpy(&address, vpd_value, sizeof(address));
			if (address != 0 && address <= UINTPTR_MAX) {
				vpd = (uint8_t *)(uintptr_t)address;
				vpd_size = UINTPTR_MAX - (uintptr_t)vpd + 1U;
			}
		}
		status = cdk2_pcd_configure_storage(&driver_context,
			runtime->get_variable, runtime->set_variable, vpd, vpd_size);
		if (status != EFI_SUCCESS)
			goto free_expanded;
	}
	if (table->boot_services->locate_protocol != NULL &&
	    table->boot_services->locate_protocol(&variable_policy_guid, NULL,
		(void **)&active_variable_policy) == EFI_SUCCESS) {
		locking_context = &driver_context;
		status = cdk2_pcd_lock_read_only(&driver_context,
			register_read_only_variable);
		locking_context = NULL;
		active_variable_policy = NULL;
		if (status != EFI_SUCCESS)
			goto free_expanded;
	}
	status = cdk2_pcd_publish(&driver_context, table->boot_services);
	if (status == EFI_SUCCESS)
		return status;
free_expanded:
	if (table->boot_services->free_pool != NULL)
		(void)table->boot_services->free_pool(expanded);
	return status;
}
