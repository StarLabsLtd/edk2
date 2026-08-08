/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

static UINTN notifications;
static void notify(void *context, const EFI_GUID *layout)
{ (void)context; (void)layout; notifications++; }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII keyboard test: %s\n", message); return !condition; }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }
int main(void)
{
	static const struct cdk2_hii_database_ops ops = { allocate, release };
	struct cdk2_hii_database database = { 0 };
	struct cdk2_hii_database raw_database;
	UINT8 record[37] = { 37U, 0U };
	UINT8 copied[37];
	UINT16 copied_size = 0U;
	EFI_GUID first = { .data1 = 1U }, second = { .data1 = 2U }, current;
	EFI_GUID layouts[2]; UINT16 count = 2U; int failures = 0;
	(void)cdk2_hii_add_keyboard_layout(&database, &first);
	(void)cdk2_hii_add_keyboard_layout(&database, &second);
	cdk2_hii_set_keyboard_notify(&database, notify, NULL);
	failures += expect(cdk2_hii_set_keyboard_layout(&database, &second) ==
		EFI_SUCCESS && notifications == 1U &&
		cdk2_hii_get_keyboard_layout(&database, &current) == EFI_SUCCESS &&
		current.data1 == 2U, "layout selection or notification failed");
	failures += expect(cdk2_hii_find_keyboard_layouts(&database, &count, layouts) ==
		EFI_SUCCESS && count == 2U && layouts[0].data1 == 1U,
		"layout enumeration failed");
	(void)cdk2_hii_database_init(&raw_database, &ops, NULL);
	__builtin_memcpy(record + 2U, &first, sizeof(first));
	record[22] = 1U;
	failures += expect(cdk2_hii_add_keyboard_layout_record(&raw_database,
		(void *)9, record, sizeof(record)) == EFI_SUCCESS &&
		cdk2_hii_copy_keyboard_layout(&raw_database, &first, &copied_size,
		NULL) == EFI_BUFFER_TOO_SMALL && copied_size == sizeof(record) &&
		cdk2_hii_copy_keyboard_layout(&raw_database, &first, &copied_size,
		copied) == EFI_SUCCESS && copied[22] == 1U,
		"variable-length layout record was not retained exactly");
	record[0]--;
	failures += expect(cdk2_hii_add_keyboard_layout_record(&raw_database,
		(void *)9, record, sizeof(record)) == EFI_INVALID_PARAMETER,
		"malformed layout length was admitted");
	cdk2_hii_remove_keyboard_layouts(&raw_database, (void *)9);
	failures += expect(raw_database.keyboard_layout_count == 0U,
		"package layout ownership was not released");
	return failures == 0 ? 0 : 1;
}
