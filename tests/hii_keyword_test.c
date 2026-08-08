/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer) { (void)context; free(buffer); }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII keyword test: %s\n", message); return !condition; }
int main(void)
{
	static const struct cdk2_hii_database_ops ops = { allocate, release };
	struct cdk2_hii_database database;
	CHAR16 *value;
	int failures = 0;

	(void)cdk2_hii_database_init(&database, &ops, NULL);
	failures += expect(cdk2_hii_register_keyword(&database, L"x-uefi", L"Mode",
		L"Safe", FALSE) == EFI_SUCCESS && cdk2_hii_get_keyword_data(&database,
			L"x-uefi", L"Mode", &value) == EFI_SUCCESS && value[0] == L'S',
		"keyword registration or lookup failed");
	failures += expect(cdk2_hii_set_keyword_data(&database, L"x-uefi", L"Mode",
		L"Fast") == EFI_SUCCESS && cdk2_hii_get_keyword_data(&database,
			L"x-uefi", L"Mode", &value) == EFI_SUCCESS && value[0] == L'F',
		"keyword update failed");
	(void)cdk2_hii_register_keyword(&database, L"x-uefi", L"Fixed", L"1", TRUE);
	failures += expect(cdk2_hii_set_keyword_data(&database, L"x-uefi", L"Fixed",
		L"2") == EFIERR(8), "read-only keyword was modified");
	return failures == 0 ? 0 : 1;
}
