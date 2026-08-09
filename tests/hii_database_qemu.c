/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database_abi.h>
#include <cdk2/hii_database.h>

typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
struct boot_services_view {
	UINT8 before_locate[320];
	locate_protocol_fn *locate_protocol;
};
struct system_table_view {
	UINT8 header[24];
	CHAR16 *vendor;
	UINT32 revision, pad;
	void *console[6], *runtime; struct boot_services_view *boot;
};

static const EFI_GUID database_guid = { 0xef9fc172, 0xa1b2, 0x4693,
	{ 0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42 } };
static const EFI_GUID string_guid = { 0x0fd96974, 0x23aa, 0x4cdc,
	{ 0xb9, 0xcb, 0x98, 0xd1, 0x77, 0x50, 0x32, 0x2a } };
static const EFI_GUID image_guid = { 0x31a6406a, 0x6bdf, 0x4e46,
	{ 0xb2, 0xa2, 0xeb, 0xaa, 0x89, 0xc4, 0x09, 0x20 } };
static const EFI_GUID font_guid = { 0xe9ca4775, 0x8657, 0x47fc,
	{ 0x97, 0xe7, 0x7e, 0xd6, 0x5a, 0x08, 0x43, 0x24 } };
static const EFI_GUID config_guid = { 0x587e72d7, 0xcc50, 0x4f79,
	{ 0x82, 0x09, 0xca, 0x29, 0x1f, 0xc1, 0xa1, 0x0f } };
static const EFI_GUID keyword_guid = { 0x0a8badd5, 0x03b8, 0x4d19,
	{ 0xb1, 0x28, 0x7b, 0x8f, 0x0e, 0xda, 0xa5, 0x96 } };
static UINTN notify_count;
static EFI_STATUS CDK2_MS_ABI package_notify(UINT8 type, const EFI_GUID *guid,
	const void *package, void *handle, UINTN operation)
{
	(void)guid; (void)package; (void)handle;
	if (type == 0xe0U && operation != 0U) notify_count++;
	return EFI_SUCCESS;
}

static UINT8 port_read(UINT16 port)
{
	UINT8 value;
	__asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}
static void serial_write(const char *text)
{
	while (*text != '\0') {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++), "Nd"((UINT16)0x3f8));
	}
}
static int locate(struct system_table_view *system, const EFI_GUID *guid, void **protocol)
{
	return !EFI_ERROR(system->boot->locate_protocol(guid, NULL, protocol)) &&
		*protocol != NULL;
}

EFI_STATUS CDK2_MS_ABI hii_database_qemu_entry(void *image, void *table)
{
	struct system_table_view *system = table;
	struct cdk2_efi_hii_database_protocol *database;
	struct cdk2_efi_hii_string_protocol *string;
	struct cdk2_efi_hii_image_protocol *image_protocol;
	struct cdk2_efi_hii_font_protocol *font;
	struct cdk2_efi_hii_config_routing_protocol *config;
	struct cdk2_efi_config_keyword_protocol *keyword;
	struct oracle_list { struct cdk2_hii_package_list_header list;
		struct cdk2_hii_package_header package; UINT32 value;
		struct cdk2_hii_package_header end; } synthetic = {
		.list = { .guid = { 0x48494932U, 0x1111U, 0x2222U, { 3U } },
			.length = sizeof(synthetic) },
		.package = { (0xe0U << 24) | 8U }, .value = 0x12345678U,
		.end = { (CDK2_HII_PACKAGE_END << 24) | 4U }
	}, exported;
	void *hii_handle = NULL, *notify_handle = NULL;
	UINTN size = 0;

	(void)image;
	serial_write("CDK2_HII_DATABASE_ORACLE_ENTRY\r\n");
	if (system == NULL || system->boot == NULL || system->boot->locate_protocol == NULL)
		goto bad;
	if (!locate(system, &database_guid, (void **)&database) ||
	    database->list_package_lists == NULL || database->export_package_lists == NULL ||
	    database->list_package_lists(database, 0U, NULL, &size, NULL) !=
		EFI_BUFFER_TOO_SMALL || size == 0U)
		goto bad;
	serial_write("CDK2_HII_DATABASE_PROTOCOL_OK\r\n");
	if (database->register_package_notify(database, 0xe0U, NULL, package_notify,
		1U | 2U | 4U | 8U, &notify_handle) != EFI_SUCCESS ||
	    database->new_package_list(database, &synthetic, NULL, &hii_handle) != EFI_SUCCESS)
		goto bad;
	synthetic.value++;
	if (database->update_package_list(database, hii_handle, &synthetic) != EFI_SUCCESS)
		goto bad;
	size = sizeof(exported);
	if (database->export_package_lists(database, hii_handle, &size, &exported) !=
		EFI_SUCCESS || size != sizeof(exported) || exported.value != synthetic.value ||
	    notify_count != 4U || database->remove_package_list(database, hii_handle) !=
		EFI_SUCCESS || database->unregister_package_notify(database, notify_handle) !=
		EFI_SUCCESS || notify_count != 5U)
		goto bad;
	serial_write("CDK2_HII_DATABASE_BEHAVIOR_OK\r\n");
	if (!locate(system, &string_guid, (void **)&string) || string->get_string == NULL ||
	    string->get_languages == NULL || !EFI_ERROR(string->get_languages(string, NULL, NULL, &size)))
		goto bad;
	serial_write("CDK2_HII_STRING_PROTOCOL_OK\r\n");
	if (!locate(system, &image_guid, (void **)&image_protocol) ||
	    image_protocol->get_image == NULL || image_protocol->draw_image == NULL)
		goto bad;
	serial_write("CDK2_HII_IMAGE_PROTOCOL_OK\r\n");
	if (!locate(system, &font_guid, (void **)&font) || font->get_glyph == NULL ||
	    font->get_font_info == NULL)
		goto bad;
	serial_write("CDK2_HII_FONT_PROTOCOL_OK\r\n");
	if (!locate(system, &config_guid, (void **)&config) ||
	    config->block_to_config == NULL || config->get_alt_config == NULL)
		goto bad;
	serial_write("CDK2_HII_CONFIG_PROTOCOL_OK\r\n");
	if (!locate(system, &keyword_guid, (void **)&keyword) ||
	    keyword->get_data == NULL || keyword->set_data == NULL)
		goto bad;
	serial_write("CDK2_HII_KEYWORD_PROTOCOL_OK\r\n");
	serial_write("CDK2_HII_DATABASE_ORACLE_OK\r\n");
	return EFI_SUCCESS;
bad:
	serial_write("CDK2_HII_DATABASE_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
