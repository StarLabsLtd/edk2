/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

struct fixture_list {
	struct cdk2_hii_package_list_header list;
	struct cdk2_hii_package_header end;
};
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII string test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_hii_database_ops ops = { allocate, release };
	struct cdk2_hii_database database;
	struct fixture_list package = {
		.list = { .guid = { 1U }, .length = sizeof(package) },
		.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
	};
	void *handle;
	UINT16 id = 0U;
	CHAR16 text[16];
	CHAR8 languages[16];
	UINTN size;
	int failures = 0;

	(void)cdk2_hii_database_init(&database, &ops, NULL);
	(void)cdk2_hii_new_package_list(&database, &package, NULL, &handle);
	failures += expect(cdk2_hii_new_string(&database, handle, &id, "en-US",
		L"Hello", NULL) == EFI_SUCCESS && id != 0U &&
		cdk2_hii_set_string(&database, handle, id, "fr-FR", L"Salut", NULL) ==
			EFI_SUCCESS, "multilingual string creation failed");
	size = 0U;
	failures += expect(cdk2_hii_get_string(&database, "en-US", handle, id, NULL,
		&size, NULL) == EFI_BUFFER_TOO_SMALL && size == 12U,
		"GetString sizing is wrong");
	failures += expect(cdk2_hii_get_string(&database, "fr-FR", handle, id, text,
		&size, NULL) == EFI_SUCCESS && text[0] == L'S' && text[4] == L't',
		"localized GetString failed");
	size = sizeof(languages);
	failures += expect(cdk2_hii_get_languages(&database, handle, languages, &size) ==
		EFI_SUCCESS && languages[0] == 'e' && languages[5] == ';',
		"language enumeration failed");
	failures += expect(cdk2_hii_set_string(&database, handle, id, "en-US",
		L"Updated", NULL) == EFI_SUCCESS, "transactional SetString failed");
	return failures == 0 ? 0 : 1;
}
