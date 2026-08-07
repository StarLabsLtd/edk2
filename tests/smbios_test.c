/* SPDX-License-Identifier: GPL-2.0-only */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "../src/modules/smbios/smbios.c"

struct allocation { size_t size; };
static void *installed2, *installed3;
static unsigned int installations;

static uint64_t CDK2_MS_ABI test_allocate(uint32_t type, size_t size, void **buffer)
{
	struct allocation *allocation; size_t total = (sizeof(*allocation) + size + 4095U) & ~4095U;
	(void)type;
	allocation = mmap(NULL, total, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if (allocation == MAP_FAILED)
		return EFI_OUT_OF_RESOURCES;
	allocation->size = total; *buffer = allocation + 1; return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI test_free(void *buffer)
{
	struct allocation *allocation = (struct allocation *)buffer - 1;
	return munmap(allocation, allocation->size) == 0 ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}
static uint64_t CDK2_MS_ABI test_install_config(const EFI_GUID *guid, void *table)
{
	if (guid_equal(guid, &smbios_table_guid))
		installed2 = table;
	else if (guid_equal(guid, &smbios3_table_guid))
		installed3 = table;
	else
		return EFI_INVALID_PARAMETER;
	installations++; return EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{ if (!condition) { fprintf(stderr, "smbios: %s\n", message); return 1; } return 0; }
static void reset_state(void)
{
	struct node *node;
	while ((node = records) != NULL) {
		records = node->next;
		test_free(node);
	}
	if (published != NULL)
		test_free(published);
	published = installed2 = installed3 = NULL; installations = 0;
}
int main(void)
{
	struct boot_services services = { .allocate_pool = test_allocate, .free_pool = test_free,
		.install_configuration_table = test_install_config };
	uint8_t record1[] = { 1, 4, 0, 0, 'o', 'n', 'e', 0, 't', 'w', 'o', 0, 0 };
	uint8_t record2[] = { 2, 4, 0, 0, 0, 0 };
	uint8_t malformed[] = { 3, 3, 0, 0, 0, 0 };
	uint16_t h1 = CDK2_SMBIOS_HANDLE_PI_RESERVED, h2 = 42, cursor;
	struct cdk2_smbios_header *out = NULL; void *producer = NULL;
	size_t string_number; uint8_t type; int failures = 0;
	struct {
		EFI_HOB_GUID_TYPE guid;
		CDK2_SMBIOS_TABLE_HOB payload;
		EFI_HOB_GENERIC_HEADER end;
	} hob_storage;
	struct config_table configuration;
	struct system_table system = { 0 };
	struct smbios3_entry *source_entry;
	uint8_t *source_table;

	bs = &services; reset_state();
	failures += expect(add(&protocol, NULL, &h1, (void *)malformed) == EFI_INVALID_PARAMETER,
		"short formatted area rejected");
	failures += expect(add(&protocol, (void *)1, &h1, (void *)record1) == EFI_SUCCESS && h1 == 0,
		"automatic handle assigned");
	failures += expect(add(&protocol, (void *)2, &h2, (void *)record2) == EFI_SUCCESS,
		"explicit handle accepted");
	failures += expect(add(&protocol, NULL, &h2, (void *)record2) == EFI_ALREADY_STARTED,
		"duplicate handle rejected");
	failures += expect(installed2 != NULL && installed3 != NULL && installations == 4,
		"both entry points republished after mutations");
	failures += expect(checksum(installed2, sizeof(struct smbios2_entry)) == 0 &&
		checksum(installed3, sizeof(struct smbios3_entry)) == 0,
		"entry-point checksums valid");
	failures += expect(((struct smbios2_entry *)installed2)->structures == 2 &&
		((struct smbios2_entry *)installed2)->table_length == sizeof(record1) + sizeof(record2),
		"SMBIOS2 sizes and count rebuilt");
	cursor = CDK2_SMBIOS_HANDLE_PI_RESERVED;
	failures += expect(get_next(&protocol, &cursor, NULL, &out, &producer) == EFI_SUCCESS &&
		cursor == h1 && producer == (void *)1, "enumeration returns first record and producer");
	type = 2; cursor = CDK2_SMBIOS_HANDLE_PI_RESERVED;
	failures += expect(get_next(&protocol, &cursor, &type, &out, NULL) == EFI_SUCCESS && cursor == h2,
		"type-filtered enumeration");
	failures += expect(get_next(&protocol, &cursor, &type, &out, NULL) == EFI_NOT_FOUND &&
		cursor == CDK2_SMBIOS_HANDLE_PI_RESERVED, "enumeration terminates canonically");
	string_number = 2;
	failures += expect(update_string(&protocol, &h1, &string_number, "second-longer") == EFI_SUCCESS,
		"string can grow");
	cursor = CDK2_SMBIOS_HANDLE_PI_RESERVED;
	get_next(&protocol, &cursor, NULL, &out, NULL);
	failures += expect(memcmp((uint8_t *)out + out->length, "one\0second-longer\0\0", 19) == 0,
		"updated strings remain correctly terminated");
	string_number = 3;
	failures += expect(update_string(&protocol, &h1, &string_number, "missing") == EFI_NOT_FOUND,
		"nonexistent string rejected");
	string_number = 0;
	failures += expect(update_string(&protocol, &h1, &string_number, "bad") == EFI_INVALID_PARAMETER,
		"zero string number rejected");
	failures += expect(remove_record(&protocol, 0x9999) == EFI_INVALID_PARAMETER,
		"unknown removal rejected");
	failures += expect(remove_record(&protocol, h1) == EFI_SUCCESS && find(h1, NULL) == NULL,
		"record removed and table rebuilt");
	reset_state();
	failures += expect(test_allocate(4, sizeof(*source_entry) + sizeof(record2),
		(void **)&source_entry) == EFI_SUCCESS, "source SMBIOS allocation");
	source_table = (uint8_t *)(source_entry + 1);
	memset(source_entry, 0, sizeof(*source_entry)); memcpy(source_entry->anchor, "_SM3_", 5);
	source_entry->length = sizeof(*source_entry); source_entry->major = 3;
	source_entry->max_size = sizeof(record2); source_entry->table_address = (uintptr_t)source_table;
	memcpy(source_table, record2, sizeof(record2));
	((struct cdk2_smbios_header *)source_table)->type = CDK2_SMBIOS_TYPE_END_OF_TABLE;
	source_entry->checksum = checksum(source_entry, sizeof(*source_entry));
	memset(&hob_storage, 0, sizeof(hob_storage));
	hob_storage.guid.header.hob_type = EFI_HOB_TYPE_GUID_EXTENSION;
	hob_storage.guid.header.hob_length = sizeof(hob_storage.guid) + sizeof(hob_storage.payload);
	hob_storage.guid.name = smbios3_hob_guid;
	hob_storage.payload.header.revision = CDK2_SMBIOS_TABLE_HOB_REVISION;
	hob_storage.payload.header.length = sizeof(hob_storage.payload);
	hob_storage.payload.smbios_entry_point = (uintptr_t)source_entry;
	hob_storage.end.hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	hob_storage.end.hob_length = sizeof(hob_storage.end);
	configuration.guid = hob_list_guid; configuration.table = &hob_storage;
	system.table_count = 1; system.tables = &configuration;
	failures += expect(import_hob(&system) == EFI_SUCCESS && records != NULL &&
		((struct cdk2_smbios_header *)records->data)->type == CDK2_SMBIOS_TYPE_END_OF_TABLE,
		"SMBIOS3 GUID HOB imported");
	reset_state();
	source_entry->checksum++;
	failures += expect(import_hob(&system) == EFI_COMPROMISED_DATA,
		"bad imported entry-point checksum rejected");
	test_free(source_entry);
	reset_state();
	return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
