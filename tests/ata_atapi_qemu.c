/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

struct guid { UINT32 a; UINT16 b, c; UINT8 d[8]; };
typedef EFI_STATUS CDK2_MS_ABI locate_fn(const struct guid *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
struct boot_view {
	UINT8 before_free[72];
	free_fn *free_pool;
	UINT8 before_locate[240];
	locate_fn *locate_protocol;
};
struct system_view { UINT8 before_boot[96]; struct boot_view *boot; };
static const struct guid ata_guid = { 0x1d3de7f0U, 0x0807U, 0x424fU,
	{ 0xaa, 0x69, 0x11, 0xa5, 0x4e, 0x19, 0xa4, 0x6f } };
static const struct guid ext_guid = { 0x143b7632U, 0xb81bU, 0x4cb7U,
	{ 0xab, 0xd3, 0xb6, 0x25, 0xa5, 0xb9, 0xbf, 0xfe } };

static UINT8 port_read(UINT16 port)
{ UINT8 value; __asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value; }
static void serial(const char *text)
{
	while (*text != 0) {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++),
			"Nd"((UINT16)0x3f8));
	}
}
static int same(const UINT8 *left, const UINT8 *right, UINTN size)
{
	for (UINTN index = 0; index < size; index++)
		if (left[index] != right[index])
			return 0;
	return 1;
}

EFI_STATUS CDK2_MS_ABI ata_atapi_qemu_entry(void *image, void *table)
{
	struct system_view *system = table;
	struct cdk2_ata_pass_thru_protocol *ata = NULL;
	struct cdk2_ext_scsi_protocol *ext = NULL;
	struct cdk2_ata_command_block acb = { 0 };
	struct cdk2_ata_status_block asb;
	struct cdk2_ata_command_packet packet = { .asb = &asb, .acb = &acb,
		.timeout = 50000000U, .protocol = 0x0aU, .length = 0x20U };
	UINT8 identify[512] __aligned(16) = { 0 };
	UINT8 first[512] __aligned(16) = { 0 };
	UINT8 second[512] __aligned(16) = { 0 };
	UINT8 target_data[CDK2_EXT_SCSI_TARGET_BYTES]; UINT8 *target = target_data;
	UINT16 port = 0xffffU, device = 0xffffU, parsed_port, parsed_device;
	UINT64 lun = 0; void *path = NULL; EFI_STATUS status;
	(void)image;

	serial("CDK2_ATA_ATAPI_ORACLE_ENTRY\r\n");
	if (system == NULL || system->boot == NULL ||
	    system->boot->locate_protocol == NULL || system->boot->free_pool == NULL ||
	    EFI_ERROR(system->boot->locate_protocol(&ata_guid, NULL, (void **)&ata)) ||
	    ata == NULL || ata->mode == NULL || ata->pass_thru == NULL ||
	    ata->get_next_port == NULL || ata->get_next_device == NULL ||
	    ata->build_device_path == NULL || ata->get_device == NULL)
		goto bad;
	serial("ATA_STAGE_LOCATE_OK\r\n");
	if (EFI_ERROR(ata->get_next_port(ata, &port)) ||
	    EFI_ERROR(ata->get_next_device(ata, port, &device)))
		goto bad;
	serial("ATA_STAGE_ENUM_OK\r\n");
	if (EFI_ERROR(ata->build_device_path(ata, port, device, &path)) ||
	    path == NULL || EFI_ERROR(ata->get_device(ata, path, &parsed_port,
		&parsed_device)) || parsed_port != port || parsed_device != device ||
	    EFI_ERROR(system->boot->free_pool(path)))
		goto bad;
	path = NULL;
	serial("ATA_STAGE_PATH_OK\r\n");
	acb.command = 0xecU; packet.in_data = identify;
	packet.in_length = sizeof(identify);
	if (EFI_ERROR(ata->pass_thru(ata, port, device, &packet, NULL)) ||
	    (identify[0] == 0U && identify[1] == 0U))
		goto bad;
	serial("ATA_STAGE_IDENTIFY_OK\r\n");
	acb = (struct cdk2_ata_command_block) { .command = 0x25U,
		.sector_count = 1U };
	packet.in_data = first; packet.in_length = sizeof(first);
	if (EFI_ERROR(ata->pass_thru(ata, port, device, &packet, NULL)))
		goto bad;
	packet.in_data = second; packet.in_length = sizeof(second);
	if (EFI_ERROR(ata->pass_thru(ata, port, device, &packet, NULL)) ||
	    !same(first, second, sizeof(first)))
		goto bad;
	serial("ATA_STAGE_READ_OK\r\n");
	if (ata->reset_port == NULL || ata->reset_device == NULL ||
	    EFI_ERROR(ata->reset_device(ata, port, device)) ||
	    ata->reset_device(ata, port, (UINT16)(device + 7U)) != EFI_NOT_FOUND)
		goto bad;
	serial("ATA_STAGE_RESET_OK\r\n");
	status = system->boot->locate_protocol(&ext_guid, NULL, (void **)&ext);
	if (EFI_ERROR(status) || ext == NULL || ext->get_next_target_lun == NULL)
		goto bad;
	for (UINTN index = 0; index < sizeof(target_data); index++)
		target_data[index] = 0xffU;
	status = ext->get_next_target_lun(ext, &target, &lun);
	if (status != EFI_NOT_FOUND && EFI_ERROR(status))
		goto bad;
	serial(status == EFI_NOT_FOUND ? "EXT_STAGE_NO_TARGET_OK\r\n" :
		"EXT_STAGE_TARGET_OK\r\n");
	serial("CDK2_ATA_ATAPI_ORACLE_OK\r\n");
	return EFI_SUCCESS;
bad:
	if (path != NULL)
		(void)system->boot->free_pool(path);
	serial("CDK2_ATA_ATAPI_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
