/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

struct fixture_list {
	struct cdk2_hii_package_list_header list;
	struct cdk2_hii_package_header strings;
	UINT32 payload;
	struct cdk2_hii_package_header end;
};
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }
static UINTN notifications;
static EFI_STATUS notify(void *context, UINT8 type, const EFI_GUID *guid,
	const void *list, void *handle, UINTN operation)
{ (void)context; (void)guid; (void)list; (void)handle; if (type == 1U && operation != 0U) notifications++; return EFI_SUCCESS; }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII database test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_hii_database_ops ops = { allocate, release };
	struct cdk2_hii_database database;
	struct fixture_list package = {
		.list = { .guid = { 1U, 2U, 3U, { 4U } }, .length = sizeof(package) },
		.strings = { (1U << 24) | 8U }, .payload = 0x12345678U,
		.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
	};
	struct fixture_list update = package, exported;
	void *handle, *notify_handle, *handles[1];
	UINTN size = 0U, count = 1U;
	int failures = 0;
	void *driver_handle = NULL;

	failures += expect(cdk2_hii_database_init(&database, &ops, NULL) == EFI_SUCCESS &&
		cdk2_hii_register_package_notify(&database, 1U, NULL, notify, NULL,
			1U | 2U | 4U | 8U, &notify_handle) == EFI_SUCCESS &&
		cdk2_hii_new_package_list(&database, &package, (void *)7, &handle) ==
			EFI_SUCCESS && notifications == 1U,
		"package admission or NEW notification failed");
	failures += expect(cdk2_hii_get_package_list_handle(&database, handle,
		&driver_handle) == EFI_SUCCESS && driver_handle == (void *)7,
		"package-list driver handle was not retained");
	failures += expect(cdk2_hii_list_package_lists(&database, 1U, NULL, &count,
		handles) == EFI_SUCCESS && count == 1U && handles[0] == handle,
		"package type filtering failed");
	failures += expect(cdk2_hii_export_package_lists(&database, handle, &size, NULL) ==
		EFI_BUFFER_TOO_SMALL && size == sizeof(package), "export sizing failed");
	failures += expect(cdk2_hii_export_package_lists(&database, handle, &size,
		&exported) == EFI_SUCCESS && exported.payload == package.payload &&
		notifications == 2U, "package export failed");
	update.payload++;
	failures += expect(cdk2_hii_update_package_list(&database, handle, &update) ==
		EFI_SUCCESS && notifications == 4U,
		"transactional package update notifications failed");
	failures += expect(cdk2_hii_remove_package_list(&database, handle) == EFI_SUCCESS &&
		notifications == 5U && cdk2_hii_unregister_package_notify(&database,
			notify_handle) == EFI_SUCCESS, "package removal or notify cleanup failed");
	package.end.length_and_type = (CDK2_HII_PACKAGE_END << 24) | 5U;
	failures += expect(cdk2_hii_new_package_list(&database, &package, NULL, &handle) ==
		EFI_INVALID_PARAMETER, "malformed END package was admitted");
	return failures == 0 ? 0 : 1;
}
