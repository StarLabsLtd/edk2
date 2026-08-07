/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hob_payload.h>
#include <cdk2/smbios.h>
#include <pi/hob.h>

#include <cdk2/config.h>

#define EFI_ALREADY_STARTED EFIERR(20)
#define EFI_BAD_BUFFER_SIZE EFIERR(4)
#define HOB_LIST_GUID { 0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }
#define SMBIOS_HOB_GUID { 0x590a0d26, 0x06e5, 0x4d20, { 0x8a, 0x82, 0x59, 0xea, 0x1b, 0x34, 0x98, 0x2d } }
#define SMBIOS3_HOB_GUID { 0x92b7896c, 0x3362, 0x46ce, { 0x99, 0xb3, 0x4f, 0x5e, 0x3c, 0x34, 0xeb, 0x42 } }
#define SMBIOS_TABLE_GUID { 0xeb9d2d31, 0x2d88, 0x11d3, { 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }
#define SMBIOS3_TABLE_GUID { 0xf2fd1544, 0x9794, 0x4a2c, { 0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94 } }
#define SMBIOS_PROTOCOL_GUID { 0x03583ff6, 0xcb36, 0x4940, { 0x94, 0x7e, 0xb9, 0xb3, 0x9f, 0x4a, 0xfa, 0xf7 } }

struct table_header { uint64_t signature; uint32_t revision, header_size, crc32, reserved; };
struct config_table { EFI_GUID guid; void *table; };
struct system_table {
	struct table_header header; uint16_t *vendor; uint32_t revision, pad;
	void *cin_handle, *cin, *cout_handle, *cout, *err_handle, *err, *runtime, *boot;
	size_t table_count; struct config_table *tables;
};
typedef uint64_t CDK2_MS_ABI alloc_fn(uint32_t, size_t, void **);
typedef uint64_t CDK2_MS_ABI free_fn(void *);
typedef uint64_t CDK2_MS_ABI install_config_fn(const EFI_GUID *, void *);
typedef uint64_t CDK2_MS_ABI install_multiple_fn(void **, const EFI_GUID *, void *, ...);
struct boot_services {
	uint8_t to_alloc[64];
	alloc_fn *allocate_pool;
	free_fn *free_pool;
	uint8_t to_install_config[112];
	install_config_fn *install_configuration_table;
	uint8_t to_install_multiple[128];
	install_multiple_fn *install_multiple;
};
struct node { struct node *next; void *producer; size_t size; uint8_t data[]; };
struct smbios2_entry {
	char anchor[4]; uint8_t checksum, length, major, minor; uint16_t max_size;
	uint8_t revision; uint8_t formatted[5]; char intermediate[5]; uint8_t intermediate_checksum;
	uint16_t table_length; uint32_t table_address; uint16_t structures; uint8_t bcd_revision;
} __packed;
struct smbios3_entry {
	char anchor[5]; uint8_t checksum, length, major, minor, docrev, revision, reserved;
	uint32_t max_size; uint64_t table_address;
} __packed;

static const EFI_GUID hob_list_guid = HOB_LIST_GUID;
static const EFI_GUID smbios_hob_guid = SMBIOS_HOB_GUID;
static const EFI_GUID smbios3_hob_guid = SMBIOS3_HOB_GUID;
static const EFI_GUID smbios_table_guid = SMBIOS_TABLE_GUID;
static const EFI_GUID smbios3_table_guid = SMBIOS3_TABLE_GUID;
static const EFI_GUID protocol_guid = SMBIOS_PROTOCOL_GUID;
static struct boot_services *bs;
static struct node *records;
static void *published;
static void *protocol_handle;

static int bytes_equal(const void *left, const void *right, size_t size)
{
	const uint8_t *a = left, *b = right;
	while (size-- != 0)
		if (*a++ != *b++)
			return 0;
	return 1;
}
static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{ return bytes_equal(a, b, sizeof(*a)); }
static uint8_t checksum(const void *data, size_t size)
{
	const uint8_t *p = data; uint8_t sum = 0;
	while (size-- != 0)
		sum = (uint8_t)(sum + *p++);
	return (uint8_t)(0U - sum);
}
static size_t string_length(const char *s)
{ size_t n = 0; while (s[n] != 0) n++; return n; }
static int record_size(const struct cdk2_smbios_header *record, size_t limit, size_t *size)
{
	const uint8_t *p = (const uint8_t *)record; size_t i;
	if (record == NULL || record->length < sizeof(*record) || record->length > limit)
		return 0;
	for (i = record->length; i + 1U < limit; i++) {
		if (p[i] == 0 && p[i + 1U] == 0) {
			*size = i + 2U;
			return 1;
		}
	}
	return 0;
}
static struct node *find(uint16_t handle, struct node **previous)
{
	struct node *node = records, *prev = NULL;
	while (node != NULL) {
		if (((struct cdk2_smbios_header *)node->data)->handle == handle)
			break;
		prev = node; node = node->next;
	}
	if (previous != NULL)
		*previous = prev;
	return node;
}
static uint64_t rebuild(void)
{
	struct node *node; struct smbios2_entry *e2; struct smbios3_entry *e3;
	uint8_t *blob, *table; size_t bytes = 0, maximum = 0, count = 0, prefix;
	uint64_t status;
	for (node = records; node != NULL; node = node->next) {
		if (bytes > SIZE_MAX - node->size)
			return EFI_OUT_OF_RESOURCES;
		bytes += node->size; if (node->size > maximum) maximum = node->size; count++;
	}
	prefix = ((CONFIG_CDK2_SMBIOS_ENTRY_POINTS & 1) ? sizeof(*e2) : 0) +
		((CONFIG_CDK2_SMBIOS_ENTRY_POINTS & 2) ? sizeof(*e3) : 0);
	if (bytes > UINT32_MAX || prefix > SIZE_MAX - bytes || count > UINT16_MAX)
		return EFI_BAD_BUFFER_SIZE;
	status = bs->allocate_pool(4, prefix + bytes, (void **)&blob);
	if (status != EFI_SUCCESS)
		return status;
	__builtin_memset(blob, 0, prefix + bytes); table = blob + prefix;
	for (node = records; node != NULL; node = node->next) {
		__builtin_memcpy(table, node->data, node->size); table += node->size;
	}
	table = blob + prefix;
	if ((CONFIG_CDK2_SMBIOS_ENTRY_POINTS & 1) != 0) {
		if (bytes > UINT16_MAX || maximum > UINT16_MAX || (uintptr_t)table > UINT32_MAX) {
			bs->free_pool(blob); return EFI_UNSUPPORTED;
		}
		e2 = (struct smbios2_entry *)blob;
		__builtin_memcpy(e2->anchor, "_SM_", 4); e2->length = sizeof(*e2);
		e2->major = CONFIG_CDK2_SMBIOS_MAJOR; e2->minor = CONFIG_CDK2_SMBIOS_MINOR;
		e2->max_size = (uint16_t)maximum; e2->revision = 0;
		__builtin_memcpy(e2->intermediate, "_DMI_", 5);
		e2->table_length = (uint16_t)bytes; e2->table_address = (uint32_t)(uintptr_t)table;
		e2->structures = (uint16_t)count; e2->bcd_revision = (uint8_t)((e2->major << 4) | e2->minor);
		e2->intermediate_checksum = checksum(e2->intermediate,
			sizeof(*e2) - offsetof(struct smbios2_entry, intermediate));
		e2->checksum = checksum(e2, sizeof(*e2));
		status = bs->install_configuration_table(&smbios_table_guid, e2);
		if (status != EFI_SUCCESS) {
			bs->free_pool(blob);
			return status;
		}
	}
	if ((CONFIG_CDK2_SMBIOS_ENTRY_POINTS & 2) != 0) {
		e3 = (struct smbios3_entry *)(blob + ((CONFIG_CDK2_SMBIOS_ENTRY_POINTS & 1) ? sizeof(*e2) : 0));
		__builtin_memcpy(e3->anchor, "_SM3_", 5); e3->length = sizeof(*e3);
		e3->major = CONFIG_CDK2_SMBIOS_MAJOR; e3->minor = CONFIG_CDK2_SMBIOS_MINOR;
		e3->docrev = CONFIG_CDK2_SMBIOS_DOCREV; e3->revision = 1;
		e3->max_size = (uint32_t)bytes; e3->table_address = (uint64_t)(uintptr_t)table;
		e3->checksum = checksum(e3, sizeof(*e3));
		status = bs->install_configuration_table(&smbios3_table_guid, e3);
		if (status != EFI_SUCCESS)
			return status; /* Keep the SMBIOS2 publication live. */
	}
	if (published != NULL)
		bs->free_pool(published);
	published = blob; return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI add(const struct cdk2_smbios *self, void *producer,
	uint16_t *handle, struct cdk2_smbios_header *record)
{
	struct node *node, **tail; size_t size; uint16_t candidate; uint64_t status; (void)self;
	if (handle == NULL || !record_size(record, UINT16_MAX, &size))
		return EFI_INVALID_PARAMETER;
	candidate = *handle;
	if (candidate == CDK2_SMBIOS_HANDLE_PI_RESERVED) {
		for (candidate = 0; candidate < CDK2_SMBIOS_HANDLE_PI_RESERVED; candidate++) {
			if (find(candidate, NULL) == NULL)
				break;
		}
		if (candidate == CDK2_SMBIOS_HANDLE_PI_RESERVED)
			return EFI_OUT_OF_RESOURCES;
	} else if (find(candidate, NULL) != NULL) {
		return EFI_ALREADY_STARTED;
	}
	status = bs->allocate_pool(4, sizeof(*node) + size, (void **)&node);
	if (status != EFI_SUCCESS)
		return status;
	node->next = NULL; node->producer = producer; node->size = size;
	__builtin_memcpy(node->data, record, size);
	((struct cdk2_smbios_header *)node->data)->handle = candidate;
	for (tail = &records; *tail != NULL; tail = &(*tail)->next)
		;
	*tail = node; status = rebuild();
	if (status != EFI_SUCCESS) {
		*tail = NULL;
		bs->free_pool(node);
		return status;
	}
	*handle = candidate; return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI update_string(const struct cdk2_smbios *self,
	uint16_t *handle, size_t *number, char *string)
{
	struct node *node, *replacement;
	size_t old_start, old_end, index, new_len, new_size;
	uint64_t status;

	(void)self;
	if (handle == NULL || number == NULL || *number == 0 || string == NULL)
		return EFI_INVALID_PARAMETER;
	node = find(*handle, NULL);
	if (node == NULL)
		return EFI_INVALID_PARAMETER;
	old_start = ((struct cdk2_smbios_header *)node->data)->length; index = 1;
	while (old_start + 1U < node->size && node->data[old_start] != 0) {
		old_end = old_start; while (old_end < node->size && node->data[old_end] != 0) old_end++;
		if (index++ == *number)
			goto found_string;
		old_start = old_end + 1U;
	}
	return EFI_NOT_FOUND;
found_string:
	new_len = string_length(string);
	if (new_len > UINT8_MAX)
		return EFI_UNSUPPORTED;
	if (node->size - (old_end - old_start) > SIZE_MAX - new_len)
		return EFI_OUT_OF_RESOURCES;
	new_size = node->size - (old_end - old_start) + new_len;
	status = bs->allocate_pool(4, sizeof(*replacement) + new_size, (void **)&replacement);
	if (status != EFI_SUCCESS)
		return status;
	*replacement = *node; replacement->size = new_size;
	__builtin_memcpy(replacement->data, node->data, old_start);
	__builtin_memcpy(replacement->data + old_start, string, new_len);
	__builtin_memcpy(replacement->data + old_start + new_len, node->data + old_end,
		node->size - old_end);
	{
		struct node *prev;
		find(*handle, &prev);
		if (prev != NULL)
			prev->next = replacement;
		else
			records = replacement;
	}
	status = rebuild();
	if (status == EFI_SUCCESS) {
		bs->free_pool(node);
		return status;
	}
	{
		struct node *prev;
		find(*handle, &prev);
		if (prev != NULL)
			prev->next = node;
		else
			records = node;
		node->next = replacement->next;
	}
	bs->free_pool(replacement); return status;
}
static uint64_t CDK2_MS_ABI remove_record(const struct cdk2_smbios *self, uint16_t handle)
{
	struct node *node, *prev; uint64_t status; (void)self;
	node = find(handle, &prev);
	if (node == NULL)
		return EFI_INVALID_PARAMETER;
	if (prev != NULL)
		prev->next = node->next;
	else
		records = node->next;
	status = rebuild();
	if (status != EFI_SUCCESS) {
		if (prev != NULL)
			prev->next = node;
		else
			records = node;
		return status;
	}
	bs->free_pool(node); return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI get_next(const struct cdk2_smbios *self, uint16_t *handle,
	uint8_t *type, struct cdk2_smbios_header **record, void **producer)
{
	struct node *node; (void)self;
	if (handle == NULL || record == NULL)
		return EFI_INVALID_PARAMETER;
	node = *handle == CDK2_SMBIOS_HANDLE_PI_RESERVED ? records : find(*handle, NULL);
	if (*handle != CDK2_SMBIOS_HANDLE_PI_RESERVED && node != NULL)
		node = node->next;
	while (node != NULL && type != NULL &&
	       ((struct cdk2_smbios_header *)node->data)->type != *type)
		node = node->next;
	if (node == NULL) {
		*handle = CDK2_SMBIOS_HANDLE_PI_RESERVED;
		return EFI_NOT_FOUND;
	}
	*record = (struct cdk2_smbios_header *)node->data; *handle = (*record)->handle;
	if (producer != NULL)
		*producer = node->producer;
	return EFI_SUCCESS;
}
static struct cdk2_smbios protocol = { add, update_string, remove_record, get_next,
	CONFIG_CDK2_SMBIOS_MAJOR, CONFIG_CDK2_SMBIOS_MINOR };

static void *find_hob_list(struct system_table *st)
{
	size_t index;

	for (index = 0; index < st->table_count; index++) {
		if (guid_equal(&st->tables[index].guid, &hob_list_guid))
			return st->tables[index].table;
	}
	return NULL;
}
static uint64_t import_table(uint8_t *table, size_t size)
{
	size_t offset = 0, record_bytes; uint16_t handle; uint64_t status;
	while (offset < size) {
		struct cdk2_smbios_header *header = (void *)(table + offset);
		if (!record_size(header, size - offset, &record_bytes))
			return EFI_COMPROMISED_DATA;
		handle = header->handle;
		status = add(&protocol, NULL, &handle, header);
		if (status != EFI_SUCCESS)
			return status;
		offset += record_bytes; if (header->type == CDK2_SMBIOS_TYPE_END_OF_TABLE) return EFI_SUCCESS;
	}
	return EFI_COMPROMISED_DATA;
}
static uint64_t import_hob(struct system_table *st)
{
	EFI_HOB_GENERIC_HEADER *hob = find_hob_list(st);
	while (hob != NULL && hob->hob_type != EFI_HOB_TYPE_END_OF_HOB_LIST) {
		if (hob->hob_length < sizeof(*hob))
			return EFI_COMPROMISED_DATA;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION &&
		    hob->hob_length >= sizeof(EFI_HOB_GUID_TYPE) +
					  sizeof(CDK2_SMBIOS_TABLE_HOB)) {
			EFI_HOB_GUID_TYPE *gh = (void *)hob;
			CDK2_SMBIOS_TABLE_HOB *payload = (void *)(gh + 1);
			uint8_t *ep;

			if (!guid_equal(&gh->name, &smbios_hob_guid) &&
			    !guid_equal(&gh->name, &smbios3_hob_guid))
				goto next;
			if (payload->header.revision != CDK2_SMBIOS_TABLE_HOB_REVISION ||
			    payload->header.length < sizeof(*payload) ||
			    payload->smbios_entry_point == 0)
				return EFI_COMPROMISED_DATA;
			ep = (void *)(uintptr_t)payload->smbios_entry_point;
			if (guid_equal(&gh->name, &smbios_hob_guid)) {
				struct smbios2_entry *e = (void *)ep;

				if (!bytes_equal(e->anchor, "_SM_", 4) ||
				    e->length != sizeof(*e) || checksum(e, e->length) != 0 ||
				    checksum(e->intermediate, sizeof(*e) -
					     offsetof(struct smbios2_entry, intermediate)) != 0)
					return EFI_COMPROMISED_DATA;
				return import_table((void *)(uintptr_t)e->table_address, e->table_length);
			} else {
				struct smbios3_entry *e = (void *)ep;

				if (!bytes_equal(e->anchor, "_SM3_", 5) ||
				    e->length != sizeof(*e) || checksum(e, e->length) != 0)
					return EFI_COMPROMISED_DATA;
				return import_table((void *)(uintptr_t)e->table_address, e->max_size);
			}
		}
next:		hob = (void *)((uint8_t *)hob + hob->hob_length);
	}
	return EFI_NOT_FOUND;
}
uint64_t CDK2_MS_ABI cdk2_smbios_entry(void *image, struct system_table *st)
{
	uint64_t status; (void)image; if (st == NULL || st->boot == NULL) return EFI_INVALID_PARAMETER;
	bs = st->boot; status = import_hob(st); if (status == EFI_NOT_FOUND) status = rebuild();
	if (status != EFI_SUCCESS)
		return status;
	return bs->install_multiple(&protocol_handle, &protocol_guid, &protocol, NULL);
}
