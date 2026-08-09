/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>

#include "../src/modules/hii_database/entry.c"

static void *published[6];
static EFI_STATUS install_status;
static UINTN config_calls;
static EFI_STATUS CDK2_MS_ABI access_extract(const void *self, const CHAR16 *request,
	CHAR16 **progress, CHAR16 **results)
{ (void)self; config_calls++; *progress = (CHAR16 *)(request + 24U); *results = NULL; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI access_route(const void *self,
	const CHAR16 *configuration, CHAR16 **progress)
{ (void)self; config_calls++; *progress = (CHAR16 *)(configuration + 24U); return EFI_SUCCESS; }
static struct config_access_protocol config_access = {
	.extract = access_extract, .route = access_route
};
static EFI_STATUS CDK2_MS_ABI locate_path(const EFI_GUID *guid, void **path,
	void **handle)
{
	const UINT8 *bytes = *path;
	(void)guid;
	if (bytes[0] != 1U || bytes[1] != 2U)
		return EFI_NOT_FOUND;
	*handle = (void *)9;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle, const EFI_GUID *guid,
	void **protocol)
{ (void)guid; if (handle != (void *)9) return EFI_NOT_FOUND; *protocol = &config_access; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI pool_allocate(UINT32 type, UINTN size, void **buffer)
{ (void)type; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI pool_free(void *buffer)
{ free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{
	(void)handle;
	published[0] = &context.database_protocol;
	published[1] = &context.string_protocol;
	published[2] = &context.image_protocol;
	published[3] = &context.font_protocol;
	published[4] = &context.config_protocol;
	published[5] = &context.keyword_protocol;
	return install_status;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII entry test: %s\n", message); return !condition; }

int main(void)
{
	struct boot_services_view boot = { 0 };
	struct system_table_view system = { 0 };
	struct cdk2_efi_hii_database_protocol *database;
	struct cdk2_efi_hii_font_protocol *font;
	struct cdk2_efi_hii_config_routing_protocol *config;
	struct cdk2_efi_config_keyword_protocol *keyword;
	CHAR16 *progress, *results;
	UINT32 progress_error;
	int failures = 0;

	boot.allocate_pool = pool_allocate;
	boot.free_pool = pool_free;
	boot.install_multiple = install;
	boot.locate_device_path = locate_path;
	boot.handle_protocol = handle_protocol;
	system.boot = &boot;
	failures += expect(cdk2_hii_database_entry((void *)1, &system) == EFI_SUCCESS,
		"entry failed to publish protocols");
	database = published[0];
	font = published[3];
	config = published[4];
	keyword = published[5];
	failures += expect(database != NULL && database->new_package_list != NULL &&
		database->register_package_notify != NULL && keyword != NULL &&
		keyword->get_data != NULL && keyword->set_data != NULL &&
		font->string_to_image != NULL && font->string_id_to_image != NULL &&
		font->get_glyph != NULL && font->get_font_info != NULL &&
		config->extract_config != NULL && config->export_config != NULL &&
		config->route_config != NULL && config->block_to_config != NULL &&
		config->config_to_block != NULL && config->get_alt_config != NULL,
		"a mandatory protocol method was not published");
	(void)cdk2_hii_register_keyword(&context.database, L"x-UEFI-test", L"Mode",
		L"1", FALSE);
	(void)cdk2_hii_register_keyword(&context.database, L"private", L"Hidden",
		L"0", FALSE);
	failures += expect(keyword->get_data(keyword, L"X-uefi-TEST", L"KEYWORD=mode",
		&progress, &progress_error, &results) == EFI_SUCCESS &&
		progress_error == 0U && results[0] == L'N',
		"case-insensitive keyword request adapter failed");
	free(results);
	failures += expect(keyword->get_data(keyword, NULL, NULL, &progress,
		&progress_error, &results) == EFI_SUCCESS && results[0] == L'N' &&
		results[10] == L'x',
		"NULL namespace did not restrict discovery to x-UEFI languages");
	free(results);
	failures += expect(config->extract_config(config,
		L"GUID=A&PATH=0102&OFFSET=0", &progress, &results) == EFI_SUCCESS &&
		config->route_config(config, L"GUID=A&PATH=0102&VALUE=00", &progress) ==
		EFI_SUCCESS && config_calls == 2U,
		"ConfigAccess device-path routing failed");
	failures += expect(keyword->set_data(keyword,
		L"NAMESPACE=x-UEFI-test&KEYWORD=Mode&VALUE=2", &progress,
		&progress_error) == EFI_SUCCESS && progress_error == 0U,
		"keyword response adapter failed");
	failures += expect(keyword->set_data(keyword,
		L"NAMESPACE=x-UEFI-test&KEYWORD=Mode&VALUE=3&NAMESPACE=x-UEFI-test&"
		L"KEYWORD=Missing&VALUE=4", &progress, &progress_error) == EFI_NOT_FOUND &&
		cdk2_hii_get_keyword_data(&context.database, L"x-UEFI-test", L"Mode",
			&results) == EFI_SUCCESS && results[0] == L'2',
		"multi-keyword validation modified storage before a later failure");
	free(results);
	install_status = EFI_DEVICE_ERROR;
	failures += expect(cdk2_hii_database_entry((void *)1, &system) == EFI_DEVICE_ERROR,
		"protocol publication failure was not propagated");
	return failures == 0 ? 0 : 1;
}
