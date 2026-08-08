/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }
static void write32(UINT8 *value, UINT32 data)
{
	value[0] = data; value[1] = data >> 8; value[2] = data >> 16;
	value[3] = data >> 24;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII package parser test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_hii_database_ops ops = { allocate, release };
	struct cdk2_hii_database database;
	UINT8 list[81] = { 0 };
	CHAR16 text[3];
	UINTN size = sizeof(text);
	void *handle = NULL;
	int failures = 0;

	write32(list + 20U, (0x04U << 24) | 57U);
	write32(list + 24U, 49U);
	write32(list + 28U, 49U);
	list[64] = 1U;
	list[66] = 'e'; list[67] = 'n';
	list[69] = 0x14U;
	list[70] = 'H'; list[72] = 'i';
	write32(list + 77U, (CDK2_HII_PACKAGE_END << 24) | 4U);
	write32(list + 16U, sizeof(list));
	(void)cdk2_hii_database_init(&database, &ops, NULL);
	failures += expect(cdk2_hii_new_package_list(&database, list, NULL, &handle) ==
		EFI_SUCCESS && cdk2_hii_get_string(&database, "en", handle, 1U,
		text, &size, NULL) == EFI_SUCCESS && text[0] == L'H' && text[1] == L'i',
		"raw UCS-2 string package was not decoded");
	(void)cdk2_hii_remove_package_list(&database, handle);
	list[75] = 1U;
	failures += expect(cdk2_hii_new_package_list(&database, list, NULL, &handle) ==
		EFI_INVALID_PARAMETER && handle == NULL,
		"unterminated raw string was admitted");
	return failures == 0 ? 0 : 1;
}
