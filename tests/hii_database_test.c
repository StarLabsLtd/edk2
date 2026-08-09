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
static BOOLEAN fail_allocation;
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	(void)context;
	if (fail_allocation) { fail_allocation = FALSE; return EFI_OUT_OF_RESOURCES; }
	*buffer = malloc(size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }
static UINTN notifications;
static EFI_STATUS notify(void *context, UINT8 type, const EFI_GUID *guid,
	const void *list, void *handle, UINTN operation)
{ (void)context; (void)guid; (void)list; (void)handle; if (type == 1U && operation != 0U) notifications++; return EFI_SUCCESS; }
struct update_context { struct cdk2_hii_database *database; const void *replacement; UINTN calls; };
static EFI_STATUS export_update(void *opaque, UINT8 type, const EFI_GUID *guid,
	const void *package, void *handle, UINTN operation)
{
	struct update_context *update = opaque;
	(void)type; (void)guid; (void)package; (void)operation;
	update->calls++;
	return cdk2_hii_update_package_list(update->database, handle, update->replacement);
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII database test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_hii_database_ops ops = { .allocate = allocate, .release = release };
	struct cdk2_hii_database database;
	struct fixture_list package = {
		.list = { .guid = { 1U, 2U, 3U, { 4U } }, .length = sizeof(package) },
		.strings = { (1U << 24) | 8U }, .payload = 0x12345678U,
		.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
	};
	struct fixture_list update = package, exported;
	void *handle, *notify_handle, *handles[1];
	UINTN size = 0U, count = 1U;
	EFI_STATUS status;
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
	failures += expect(cdk2_hii_list_package_lists(&database, 0U, NULL, &count,
		handles) == EFI_SUCCESS && count == 1U && handles[0] == handle,
		"package type filtering failed");
	count = 0U;
	failures += expect(cdk2_hii_list_package_lists(&database, 1U, NULL, &count,
		NULL) == EFI_INVALID_PARAMETER &&
		cdk2_hii_list_package_lists(&database, 0U, &(EFI_GUID){ 0 }, &count,
		NULL) == EFI_INVALID_PARAMETER,
		"GUID/type parameter pairing was accepted");
	failures += expect(cdk2_hii_export_package_lists(&database, handle, &size, NULL) ==
		EFI_BUFFER_TOO_SMALL && size == sizeof(package), "export sizing failed");
	failures += expect(cdk2_hii_export_package_lists(&database, handle, &size,
		&exported) == EFI_SUCCESS && exported.payload == package.payload &&
		notifications == 3U, "package export failed");
	update.payload++;
	failures += expect(cdk2_hii_update_package_list(&database, handle, &update) ==
		EFI_SUCCESS && notifications == 5U,
		"transactional package update notifications failed");
	failures += expect(cdk2_hii_remove_package_list(&database, handle) == EFI_SUCCESS &&
		notifications == 6U && cdk2_hii_unregister_package_notify(&database,
			notify_handle) == EFI_SUCCESS, "package removal or notify cleanup failed");
	package.end.length_and_type = (CDK2_HII_PACKAGE_END << 24) | 5U;
	failures += expect(cdk2_hii_new_package_list(&database, &package, NULL, &handle) ==
		EFI_INVALID_PARAMETER, "malformed END package was admitted");
	{
		struct two_packages { struct cdk2_hii_package_list_header list;
			struct cdk2_hii_package_header a; UINT32 av;
			struct cdk2_hii_package_header b; UINT32 bv;
			struct cdk2_hii_package_header end; } old = {
			.list = { .length = sizeof(old) }, .a = { (0xe0U << 24) | 8U },
			.av = 1U, .b = { (0xe1U << 24) | 8U }, .bv = 2U,
			.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
		}, out;
		struct fixture_list replacement = {
			.list = { .length = sizeof(replacement) },
			.strings = { (0xe0U << 24) | 8U }, .payload = 3U,
			.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
		};
		struct update_context reentrant = { .database = &database,
			.replacement = &replacement };
		void *export_notify;
		size = sizeof(out);
		failures += expect(cdk2_hii_new_package_list(&database, &old, NULL, &handle) ==
			EFI_SUCCESS && cdk2_hii_update_package_list(&database, handle, &replacement) ==
			EFI_SUCCESS && cdk2_hii_export_package_lists(&database, handle, &size, &out) ==
			EFI_SUCCESS && out.av == 2U && out.bv == 3U,
			"update did not preserve unmatched package type");
		old.av = 9U; fail_allocation = TRUE;
		failures += expect(cdk2_hii_update_package_list(&database, handle, &old) ==
			EFI_OUT_OF_RESOURCES, "allocation-fault update was not rolled back");
		size = sizeof(out);
		failures += expect(cdk2_hii_export_package_lists(&database, handle, &size, &out) ==
			EFI_SUCCESS && out.av == 2U && out.bv == 3U,
			"allocation-fault update changed the prior package list");
		failures += expect(cdk2_hii_register_package_notify(&database, 0xe0U, NULL,
			export_update, &reentrant, 4U, &export_notify) == EFI_SUCCESS,
			"export update notify registration failed");
		size = sizeof(out);
		status = cdk2_hii_export_package_lists(&database, handle, &size, &out);
		if (status != EFI_SUCCESS || reentrant.calls != 1U)
			fprintf(stderr, "reentrant status=%llu calls=%llu size=%llu\n",
				(unsigned long long)status, (unsigned long long)reentrant.calls,
				(unsigned long long)size);
		failures += expect(status == EFI_SUCCESS && reentrant.calls == 1U,
			"reentrant EXPORT update was unsafe");
		(void)cdk2_hii_unregister_package_notify(&database, export_notify);
		(void)cdk2_hii_remove_package_list(&database, handle);
	}
	cdk2_hii_database_destroy(&database);
	return failures == 0 ? 0 : 1;
}
