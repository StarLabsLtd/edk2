/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Native SMM Access 2 protocol over the coreboot-provided SMRAM descriptor. */

#include <cdk2/smm_access.h>
#include <stddef.h>
#include <stdint.h>

#define HOB_TYPE_GUID_EXTENSION 0x0004U
#define HOB_TYPE_END_OF_LIST 0xffffU
#define MAX_HOB_LIST_SIZE SIZE_1MB
#define MAX_SMRAM_REGIONS 8U

struct table_header {
	UINT64 signature;
	UINT32 revision;
	UINT32 header_size;
	UINT32 crc32;
	UINT32 reserved;
};

struct config_table {
	EFI_GUID guid;
	void *table;
};

struct system_table_view {
	struct table_header header;
	CHAR16 *firmware_vendor;
	UINT32 firmware_revision;
	UINT32 padding;
	void *console_fields[6];
	void *runtime_services;
	void *boot_services;
	UINTN table_count;
	struct config_table *tables;
};

typedef EFI_STATUS install_multiple_function(void **handle, ...) CDK2_MS_ABI;

struct boot_services_view {
	UINT8 unused[328];
	install_multiple_function *install_multiple;
};

struct hob_header {
	UINT16 type;
	UINT16 length;
	UINT32 reserved;
};

struct guid_hob {
	struct hob_header header;
	EFI_GUID name;
};

static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4,
	{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID smram_memory_guid = {
	0x6dadf1d1, 0xd4cc, 0x4910,
	{ 0xbb, 0x6e, 0x82, 0xb1, 0xfd, 0x80, 0xff, 0x3d }
};
static const EFI_GUID smm_access2_guid = {
	0xc2702b74, 0x800c, 0x4131,
	{ 0x87, 0x46, 0x8f, 0xb5, 0xb8, 0x9c, 0xe4, 0xac }
};

static EFI_SMRAM_DESCRIPTOR descriptors[MAX_SMRAM_REGIONS];
static UINTN descriptor_count;
static UINT64 region_state;
static void *driver_handle;

static int guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left;
	const UINT8 *b = (const UINT8 *)right;
	UINTN index;

	for (index = 0; index < sizeof(*left); index++) {
		if (a[index] != b[index])
			return 0;
	}
	return 1;
}

static void update_descriptor_state(UINT64 clear, UINT64 set)
{
	UINTN index;

	region_state &= ~clear;
	region_state |= set;
	for (index = 0; index < descriptor_count; index++) {
		descriptors[index].region_state &= ~clear;
		descriptors[index].region_state |= set;
	}
}

static EFI_STATUS CDK2_MS_ABI open_smram(struct cdk2_smm_access2_protocol *protocol)
{
	if ((region_state & EFI_SMRAM_LOCKED) != 0U)
		return EFI_DEVICE_ERROR;
	update_descriptor_state(EFI_SMRAM_CLOSED | EFI_ALLOCATED, EFI_SMRAM_OPEN);
	protocol->open_state = TRUE;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI close_smram(struct cdk2_smm_access2_protocol *protocol)
{
	if ((region_state & EFI_SMRAM_LOCKED) != 0U ||
	    (region_state & EFI_SMRAM_CLOSED) != 0U)
		return EFI_DEVICE_ERROR;
	update_descriptor_state(EFI_SMRAM_OPEN, EFI_SMRAM_CLOSED | EFI_ALLOCATED);
	protocol->open_state = FALSE;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI lock_smram(struct cdk2_smm_access2_protocol *protocol)
{
	if (protocol->open_state)
		return EFI_DEVICE_ERROR;
	update_descriptor_state(0, EFI_SMRAM_LOCKED);
	protocol->lock_state = TRUE;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_capabilities(
	const struct cdk2_smm_access2_protocol *protocol, UINTN *map_size,
	EFI_SMRAM_DESCRIPTOR *map)
{
	UINTN required;
	UINTN index;

	(void)protocol;
	if (map_size == NULL)
		return EFI_INVALID_PARAMETER;
	required = descriptor_count * sizeof(*map);
	if (*map_size < required) {
		*map_size = required;
		return EFI_BUFFER_TOO_SMALL;
	}
	if (required != 0U && map == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < descriptor_count; index++)
		map[index] = descriptors[index];
	*map_size = required;
	return EFI_SUCCESS;
}

static struct cdk2_smm_access2_protocol smm_access = {
	open_smram, close_smram, lock_smram, get_capabilities, FALSE, FALSE
};

static const EFI_SMRAM_HOB_DESCRIPTOR_BLOCK *find_smram_block(
	const struct system_table_view *system, UINTN *payload_size)
{
	const UINT8 *hob_list = NULL;
	const struct hob_header *hob;
	UINTN index;
	UINTN walked = 0;

	if (system->table_count != 0U && system->tables == NULL)
		return NULL;
	for (index = 0; index < system->table_count; index++) {
		if (guid_equal(&system->tables[index].guid, &hob_list_guid)) {
			hob_list = system->tables[index].table;
			break;
		}
	}
	if (hob_list == NULL)
		return NULL;

	hob = (const struct hob_header *)(const void *)hob_list;
	while (walked + sizeof(*hob) <= MAX_HOB_LIST_SIZE) {
		const struct guid_hob *guid_hob;

		if (hob->type == HOB_TYPE_END_OF_LIST)
			return NULL;
		if (hob->length < sizeof(*hob) || hob->length > MAX_HOB_LIST_SIZE - walked)
			return NULL;
		if (hob->type == HOB_TYPE_GUID_EXTENSION && hob->length >= sizeof(*guid_hob)) {
			guid_hob = (const struct guid_hob *)(const void *)hob;
			if (guid_equal(&guid_hob->name, &smram_memory_guid)) {
				*payload_size = hob->length - sizeof(*guid_hob);
				return (const EFI_SMRAM_HOB_DESCRIPTOR_BLOCK *)(const void *)(guid_hob + 1);
			}
		}
		walked += hob->length;
		hob = (const struct hob_header *)(const void *)(hob_list + walked);
	}
	return NULL;
}

EFI_STATUS CDK2_MS_ABI cdk2_smm_access_entry(void *image,
	struct system_table_view *system)
{
	const EFI_SMRAM_HOB_DESCRIPTOR_BLOCK *block;
	struct boot_services_view *boot;
	UINTN payload_size;
	UINTN required_size;
	UINTN index;

	(void)image;
	if (system == NULL || system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	block = find_smram_block(system, &payload_size);
	if (block == NULL)
		return EFI_NOT_FOUND;
	if (block->number_of_smm_reserved_regions == 0U ||
	    block->number_of_smm_reserved_regions > MAX_SMRAM_REGIONS)
		return EFI_COMPROMISED_DATA;
	required_size = OFFSET_OF(EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, descriptor) +
		(UINTN)block->number_of_smm_reserved_regions * sizeof(block->descriptor[0]);
	if (required_size > payload_size)
		return EFI_COMPROMISED_DATA;

	descriptor_count = block->number_of_smm_reserved_regions;
	region_state = EFI_SMRAM_CLOSED;
	for (index = 0; index < descriptor_count; index++) {
		if (block->descriptor[index].physical_size == 0U ||
		    block->descriptor[index].physical_start >
			MAX_UINT64 - block->descriptor[index].physical_size)
			return EFI_COMPROMISED_DATA;
		descriptors[index] = block->descriptor[index];
		descriptors[index].region_state &= EFI_ALLOCATED;
		descriptors[index].region_state |= EFI_SMRAM_CLOSED | EFI_CACHEABLE;
		region_state |= descriptors[index].region_state;
	}
	smm_access.lock_state = FALSE;
	smm_access.open_state = FALSE;
	boot = system->boot_services;
	return boot->install_multiple(&driver_handle, &smm_access2_guid, &smm_access, NULL);
}
