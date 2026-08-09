/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>

#include "../src/modules/hii_database/entry.c"

static void *published[6];
static EFI_STATUS install_status;
static EFI_STATUS uninstall_status;
static UINTN uninstall_calls;
static EFI_STATUS create_status, signal_status, close_status;
static UINTN config_calls;
static UINT8 test_path[] = { 1U, 2U, 4U, 0U, 0x7fU, 0xffU, 4U, 0U };
static UINTN u16_length(const CHAR16 *text)
{ UINTN length = 0U; while (text[length] != 0U) length++; return length; }
static int u16_contains(const CHAR16 *text, const CHAR16 *needle)
{
	UINTN index, candidate;
	for (index = 0U; text[index] != 0U; index++) {
		for (candidate = 0U; needle[candidate] != 0U &&
		     text[index + candidate] == needle[candidate]; candidate++)
			;
		if (needle[candidate] == 0U)
			return 1;
	}
	return 0;
}
static EFI_STATUS CDK2_MS_ABI access_extract(const void *self, const CHAR16 *request,
	CHAR16 **progress, CHAR16 **results)
{
	static const CHAR16 suffix[] = L"&VALUE=A5";
	UINTN request_length = u16_length(request), suffix_length = u16_length(suffix);
	(void)self; config_calls++; *progress = (CHAR16 *)(request + request_length);
	*results = malloc((request_length + suffix_length + 1U) * sizeof(CHAR16));
	if (*results == NULL)
		return EFI_OUT_OF_RESOURCES;
	__builtin_memcpy(*results, request, request_length * sizeof(CHAR16));
	__builtin_memcpy(*results + request_length, suffix,
		(suffix_length + 1U) * sizeof(CHAR16));
	return EFI_SUCCESS;
}
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
	*path = (UINT8 *)*path + 4U;
	*handle = (void *)9;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle, const EFI_GUID *guid,
	void **protocol)
{
	if (handle != (void *)9)
		return EFI_NOT_FOUND;
	*protocol = same_guid(guid, &device_path_guid) ? (void *)test_path :
		(void *)&config_access;
	return EFI_SUCCESS;
}
static void write16(UINT8 *data, UINT16 value)
{ data[0] = value; data[1] = value >> 8; }
static void write32(UINT8 *data, UINT32 value)
{ write16(data, value); write16(data + 2U, value >> 16); }
static EFI_STATUS CDK2_MS_ABI pool_allocate(UINT32 type, UINTN size, void **buffer)
{ (void)type; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI pool_free(void *buffer)
{ free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{
	*handle = (void *)0x44;
	published[0] = &context.database_protocol;
	published[1] = &context.string_protocol;
	published[2] = &context.image_protocol;
	published[3] = &context.font_protocol;
	published[4] = &context.config_protocol;
	published[5] = &context.keyword_protocol;
	return install_status;
}
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{ uninstall_calls++; return handle == (void *)0x44 ? uninstall_status : EFI_INVALID_PARAMETER; }
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *opaque,
	const EFI_GUID *group, void **event)
{
	(void)type; (void)tpl; (void)notify; (void)opaque; (void)group;
	*event = (void *)0x1234;
	return create_status;
}
static EFI_STATUS CDK2_MS_ABI signal_event(void *event)
{ return event == (void *)0x1234 ? signal_status : EFI_INVALID_PARAMETER; }
static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{ return event == (void *)0x1234 ? close_status : EFI_INVALID_PARAMETER; }
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
	UINT8 routed_list[84] = { 0 };
	void *routed_handle;
	UINT32 progress_error;
	int failures = 0;

	boot.allocate_pool = pool_allocate;
	boot.free_pool = pool_free;
	boot.install_multiple = install;
	boot.uninstall_multiple = uninstall;
	boot.create_event_ex = create_event;
	boot.signal_event = signal_event;
	boot.close_event = close_event;
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
	{
		struct path_list { struct cdk2_hii_package_list_header list;
			struct cdk2_hii_package_header opaque; UINT32 value;
			struct cdk2_hii_package_header end; } input = {
			.list = { .length = sizeof(input) },
			.opaque = { (0xe0U << 24) | 8U }, .value = 1U,
			.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
		};
		UINT8 output[64]; UINTN output_size = sizeof(output), offset;
		void *path_handle = NULL; BOOLEAN found_path = FALSE;
		failures += expect(database->new_package_list(database, &input, (void *)9,
			&path_handle) == EFI_SUCCESS && database->export_package_lists(database,
			path_handle, &output_size, output) == EFI_SUCCESS,
			"DriverHandle DevicePath package was not synthesized");
		for (offset = sizeof(input.list); offset + 4U <= output_size;) {
			UINT32 header = (UINT32)output[offset] | ((UINT32)output[offset + 1U] << 8) |
				((UINT32)output[offset + 2U] << 16) | ((UINT32)output[offset + 3U] << 24);
			if ((header >> 24) == 0x08U) found_path = TRUE;
			if ((header & 0x00ffffffU) < 4U) break;
			offset += header & 0x00ffffffU;
		}
		failures += expect(found_path, "export omitted synthesized DevicePath package");
		(void)database->remove_package_list(database, path_handle);
	}
	failures += expect(database->list_package_lists(database, 1U, NULL,
		&(UINTN){ 0U }, NULL) == EFI_INVALID_PARAMETER &&
		config->extract_config(config, L"GUID=A", NULL, &results) == EFI_INVALID_PARAMETER,
		"database/config ABI NULL validation failed");
	(void)cdk2_hii_register_keyword(&context.database, L"x-UEFI-test", L"Mode",
		L"1", FALSE);
	(void)cdk2_hii_register_keyword(&context.database, L"x-UEFI-other", L"Mode",
		L"9", FALSE);
	(void)cdk2_hii_register_keyword(&context.database, L"private", L"Hidden",
		L"0", FALSE);
	(void)cdk2_hii_register_keyword(&context.database, L"x-UEFI-test", L"Fixed",
		L"1", TRUE);
	failures += expect(keyword->get_data(keyword, L"X-uefi-TEST", L"KEYWORD=mode",
		&progress, &progress_error, &results) == EFI_SUCCESS &&
		progress_error == 0U && results[0] == L'N',
		"case-insensitive keyword request adapter failed");
	free(results);
	failures += expect(keyword->get_data(keyword, L"x-UEFI-test",
		L"KEYWORD=Mode&ReadWrite&Buffer", &progress, &progress_error,
		&results) == EFI_SUCCESS && keyword->get_data(keyword, L"x-UEFI-test",
		L"KEYWORD=Mode&Numeric", &progress, &progress_error, &results) ==
		EFI_INVALID_PARAMETER && progress_error == 0x00000008U,
		"keyword access/data filters were not enforced");
	free(results);
	failures += expect(keyword->get_data(keyword, L"x-UEFI-test",
		L"KEYWORD=Fixed&ReadOnly", &progress, &progress_error, &results) ==
		EFI_SUCCESS && results[0] == L'N',
		"read-only keyword filter or response failed");
	free(results);
	failures += expect(keyword->get_data(keyword, NULL, NULL, &progress,
		&progress_error, &results) == EFI_SUCCESS && results[0] == L'N' &&
		results[10] == L'x',
		"NULL namespace did not restrict discovery to x-UEFI languages");
	free(results);
	failures += expect(keyword->get_data(keyword, NULL, L"KEYWORD=Mode", &progress,
		&progress_error, &results) == EFI_SUCCESS &&
		u16_contains(results, L"NAMESPACE=x-UEFI-test&KEYWORD=Mode") &&
		!u16_contains(results, L"NAMESPACE=x-UEFI-other"),
		"NULL namespace keyword lookup did not use database order");
	free(results);
	{
		static const EFI_GUID selected_guid = { 1U, 2U, 3U, { 4U } };
		static const UINT8 selected_path[] = { 0x7fU, 0xffU, 4U, 0U };
		failures += expect(config->get_alt_config(config,
			L"GUID=00000000000000000000000000000000&NAME=0058&PATH=7FFF0400&"
			L"ALTCFG=0001&OFFSET=0&WIDTH=1&VALUE=00&"
			L"GUID=01000000020003000400000000000000&NAME=0059&PATH=7FFF0400&"
			L"ALTCFG=0001&OFFSET=0&WIDTH=1&VALUE=11",
			&selected_guid, L"Y", selected_path, &(UINT16){ 1U }, &results) ==
			EFI_SUCCESS && u16_contains(results, L"VALUE=11") &&
			!u16_contains(results, L"VALUE=00"),
			"GetAltCfg ignored GUID/NAME/PATH selectors");
		free(results);
	}
	failures += expect(config->extract_config(config,
		L"GUID=A&PATH=010204007FFF0400&OFFSET=0", &progress, &results) == EFI_SUCCESS &&
		config->route_config(config, L"GUID=A&PATH=010204007FFF0400&VALUE=00", &progress) ==
		EFI_SUCCESS && config_calls == 2U,
		"ConfigAccess device-path routing failed");
	free(results);
	{
		EFI_GUID first = { .data1 = 0x11U }, second = { .data1 = 0x22U }, current;
		(void)cdk2_hii_add_keyboard_layout(&context.database, &first);
		(void)cdk2_hii_add_keyboard_layout(&context.database, &second);
		create_status = EFI_DEVICE_ERROR;
		failures += expect(database->set_keyboard_layout(database, &second) ==
			EFI_DEVICE_ERROR && cdk2_hii_get_keyboard_layout(&context.database,
				&current) == EFI_SUCCESS && same_guid(&current, &first),
			"CreateEventEx failure changed the keyboard layout");
		create_status = EFI_SUCCESS; signal_status = EFI_DEVICE_ERROR;
		failures += expect(database->set_keyboard_layout(database, &second) ==
			EFI_DEVICE_ERROR && cdk2_hii_get_keyboard_layout(&context.database,
				&current) == EFI_SUCCESS && same_guid(&current, &first),
			"SignalEvent failure did not roll back the keyboard layout");
		signal_status = EFI_SUCCESS; close_status = EFI_DEVICE_ERROR;
		failures += expect(database->set_keyboard_layout(database, &second) ==
			EFI_DEVICE_ERROR && pending_keyboard_event != NULL &&
			cdk2_hii_get_keyboard_layout(&context.database, &current) == EFI_SUCCESS &&
			same_guid(&current, &second),
			"CloseEvent failure lost event ownership or committed state");
		close_status = EFI_SUCCESS;
		failures += expect(database->set_keyboard_layout(database, &first) ==
			EFI_SUCCESS && pending_keyboard_event == NULL,
			"retained keyboard event was not closed on retry");
	}
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
	write32(routed_list + 16U, sizeof(routed_list));
	write32(routed_list + 20U, (0x02U << 24) | 60U);
	routed_list[24] = 0x24U; routed_list[25] = 24U;
	write16(routed_list + 42U, 1U); write16(routed_list + 44U, 8U);
	routed_list[46] = 'V';
	routed_list[48] = 0x05U; routed_list[49] = 0x80U | 17U;
	write16(routed_list + 50U, 1U); write16(routed_list + 54U, 3U);
	write16(routed_list + 56U, 1U); write16(routed_list + 58U, 2U);
	routed_list[62] = 1U; routed_list[63] = 10U; routed_list[64] = 1U;
	routed_list[65] = 0x09U; routed_list[66] = 7U;
	write16(routed_list + 67U, 2U); routed_list[70] = 0U; routed_list[71] = 1U;
	routed_list[72] = 0x5bU; routed_list[73] = 6U;
	routed_list[77] = 5U;
	routed_list[78] = 0x29U; routed_list[79] = 2U;
	write32(routed_list + 80U, (CDK2_HII_PACKAGE_END << 24) | 4U);
	failures += expect(cdk2_hii_new_package_list(&context.database, routed_list,
		(void *)9, &routed_handle) == EFI_SUCCESS &&
		cdk2_hii_register_package_keyword(&context.database, routed_handle,
			L"x-UEFI-test", L"Routed", 1U, 1U, 2U, 1U, 0x05U, 0U,
			FALSE) == EFI_SUCCESS &&
		cdk2_hii_set_string(&context.database, routed_handle, 1U, "en-US",
			L"Routing mode", NULL) == EFI_SUCCESS &&
		cdk2_hii_set_string(&context.database, routed_handle, 2U, "en-US",
			L"Enabled", NULL) == EFI_SUCCESS &&
		keyword->get_data(keyword, L"x-UEFI-test", L"KEYWORD=Routed&Numeric:1",
			&progress, &progress_error, &results) == EFI_SUCCESS &&
		u16_contains(results, L"&PATH=010204007FFF0400&KEYWORD=Routed") &&
		keyword->set_data(keyword,
			L"NAMESPACE=x-UEFI-test&"
			L"GUID=00000000000000000000000000000000&NAME=0056&"
			L"PATH=010204007FFF0400&KEYWORD=Routed&VALUE=5A", &progress,
			&progress_error) == EFI_SUCCESS && config_calls >= 4U,
		"IFR keyword value was not forwarded through ConfigAccess");
	free(results);
	failures += expect(keyword->get_data(keyword, L"x-UEFI-test",
		L"GUID=00000000000000000000000000000000&NAME=0056&"
		L"PATH=010204007FFF0400&KEYWORD=Routed&KEYWORDINFO=All", &progress,
		&progress_error, &results) == EFI_SUCCESS &&
		u16_contains(results, L"&DATATYPE=Numeric:1") &&
		u16_contains(results, L"&MAX=0A&MIN=01&STEP=01") &&
		u16_contains(results, L"&OPTIONVALUE=01&OPTIONSTRING=Enabled") &&
		u16_contains(results, L"&STANDARDDEFAULT=05") &&
		u16_contains(results, L"&DISPLAYNAME=Routing mode"),
		"PATH-qualified keyword owner or KeywordInfo was not returned");
	free(results);
	failures += expect(cdk2_hii_database_unload((void *)1) == EFI_SUCCESS &&
		uninstall_calls == 1U && context.database.ops == NULL,
		"unload did not uninstall protocols before releasing ownership");
	install_status = EFI_DEVICE_ERROR;
	failures += expect(cdk2_hii_database_entry((void *)1, &system) ==
		EFI_DEVICE_ERROR && context.database.ops == NULL,
		"failed protocol publication did not destroy initialized ownership");
	install_status = EFI_SUCCESS;
	failures += expect(cdk2_hii_database_entry((void *)1, &system) == EFI_SUCCESS,
		"entry retry after publication rollback failed");
	cdk2_hii_database_destroy(&context.database);
	return failures == 0 ? 0 : 1;
}
