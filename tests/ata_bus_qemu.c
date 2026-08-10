/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_bus.h>

#include <string.h>

typedef EFI_STATUS CDK2_MS_ABI locate_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI locate_handles_fn(UINT32, const EFI_GUID *,
	void *, UINTN *, void ***);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI wait_fn(UINTN, void **, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI check_fn(void *);
struct boot_view {
	UINT8 header[72];
	free_fn *free_pool;
	create_fn *create_event;
	void *set_timer;
	wait_fn *wait_for_event;
	void *signal_event;
	close_fn *close_event;
	check_fn *check_event;
	UINT8 before_handle[24];
	handle_fn *handle_protocol;
	UINT8 before_locate_handles[152];
	locate_handles_fn *locate_handle_buffer;
	locate_fn *locate_protocol;
};
struct system_view { UINT8 prefix[96]; struct boot_view *boot; };
static const EFI_GUID block_guid = { 0x964e5b21U, 0x6459U, 0x11d2U,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID block2_guid = { 0xa77b2472U, 0xe282U, 0x4e9fU,
	{ 0xa2, 0x45, 0xc2, 0xc0, 0xe2, 0x7b, 0xbc, 0xc1 } };
static const EFI_GUID disk_guid = { 0xd432a67fU, 0x14dcU, 0x484bU,
	{ 0xb3, 0xbb, 0x3f, 0x02, 0x91, 0x84, 0x93, 0x27 } };
static const EFI_GUID ahci_interface = { 0x9e498932U, 0x4abcU, 0x45afU,
	{ 0xa3, 0x4d, 0x02, 0x47, 0x78, 0x7b, 0xe7, 0xc6 } };

static UINT8 port_read(UINT16 port)
{
	UINT8 value;
	__asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}
static void serial(const char *text)
{
	while (*text != 0) {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++),
			"Nd"((UINT16)0x3f8));
	}
}
static void serial_status(EFI_STATUS status)
{
	static const char hex[] = "0123456789abcdef";
	char value[19] = "0x0000000000000000";

	for (UINTN index = 0; index < 16U; index++)
		value[17U - index] = hex[(status >> (index * 4U)) & 0xfU];
	serial(value);
	serial("\r\n");
}
static BOOLEAN same(const UINT8 *left, const UINT8 *right, UINTN size)
{
	for (UINTN index = 0; index < size; index++)
		if (left[index] != right[index])
			return 0;
	return 1;
}

EFI_STATUS CDK2_MS_ABI ata_bus_qemu_entry(void *image, void *table)
{
	struct system_view *system = table;
	struct cdk2_block_io *block = NULL;
	struct cdk2_block_io2 *block2 = NULL;
	struct cdk2_ata_bus_disk_info *disk = NULL;
	struct cdk2_block_io2_token token = { 0 };
	UINT8 saved[512], pattern[512], readback[512], identify[512];
	UINT32 identify_size = sizeof(identify);
	UINTN index = 0;
	UINT64 scratch;
	void *event = NULL;
	EFI_STATUS status;
	void **handles = NULL;
	UINTN handle_count = 0;
	(void)image;

	serial("CDK2_ATA_BUS_ORACLE_ENTRY\r\n");
	if (system == NULL || system->boot == NULL ||
	    EFI_ERROR(system->boot->locate_handle_buffer(2U, &disk_guid, NULL,
	    &handle_count, &handles)))
		goto bad;
	serial("CDK2_ATA_BUS_HANDLES_OK\r\n");
	for (index = 0; index < handle_count; index++) {
		if (!EFI_ERROR(system->boot->handle_protocol(handles[index], &block_guid,
		    (void **)&block)) && !EFI_ERROR(system->boot->handle_protocol(handles[index],
		    &block2_guid, (void **)&block2)) && !EFI_ERROR(system->boot->handle_protocol(
		    handles[index], &disk_guid, (void **)&disk)) &&
		    same((const UINT8 *)&disk->interface, (const UINT8 *)&ahci_interface,
		    sizeof(ahci_interface)))
			break;
		block = NULL;
		block2 = NULL;
		disk = NULL;
	}
	(void)system->boot->free_pool(handles);
	serial("CDK2_ATA_BUS_HANDLE_SCAN_OK\r\n");
	if (block == NULL || block2 == NULL || disk == NULL || block->media == NULL ||
	    block->media != block2->media || block->media->block_size != 512U)
		goto bad;
	serial("CDK2_ATA_BUS_PROTOCOLS_OK\r\n");
	status = disk->identify(disk, identify, &identify_size);
	if (EFI_ERROR(status) || identify_size != sizeof(identify)) {
		serial("CDK2_ATA_BUS_DISK_INFO_STATUS=");
		serial_status(status);
		serial("CDK2_ATA_BUS_DISK_INFO_SIZE=");
		serial_status(identify_size);
		goto bad;
	}
	serial("CDK2_ATA_BUS_DISK_INFO_OK\r\n");
	scratch = block->media->last_block;
	for (index = 0; index < sizeof(pattern); index++)
		pattern[index] = (UINT8)(index ^ 0xa5U);
	if (EFI_ERROR(block->read_blocks(block, block->media->media_id, scratch,
	    sizeof(saved), saved)) || EFI_ERROR(system->boot->create_event(0U, 0U,
	    NULL, NULL, &event)))
		goto bad;
	serial("CDK2_ATA_BUS_SYNC_READ_OK\r\n");
	if (EFI_ERROR(block->write_blocks(block, block->media->media_id, scratch,
	    sizeof(pattern), pattern)) || EFI_ERROR(block->read_blocks(block,
	    block->media->media_id, scratch, sizeof(readback), readback)) ||
	    !same(pattern, readback, sizeof(pattern)) || EFI_ERROR(block->write_blocks(
	    block, block->media->media_id, scratch, sizeof(saved), saved)))
		goto bad;
	serial("CDK2_ATA_BUS_SYNC_WRITE_OK\r\n");
	token.event = event;
	status = block2->write_blocks(block2, block->media->media_id, scratch, &token,
		sizeof(pattern), pattern);
	if (EFI_ERROR(status))
		goto restore;
	serial("CDK2_ATA_BUS_SUBMIT_OK\r\n");
	if (system->boot->check_event(event) != EFI_NOT_READY)
		goto restore;
	serial("CDK2_ATA_BUS_RETURN_BEFORE_OK\r\n");
	if (EFI_ERROR(system->boot->wait_for_event(1U, &event, &index)))
		goto restore;
	serial("CDK2_ATA_BUS_WAIT_OK\r\n");
	if (token.transaction_status != EFI_SUCCESS) {
		serial("CDK2_ATA_BUS_TOKEN_STATUS=");
		serial_status(token.transaction_status);
		goto restore;
	}
	serial("CDK2_ATA_BUS_ASYNC_OK\r\n");
	if (EFI_ERROR(block->read_blocks(block, block->media->media_id, scratch,
	    sizeof(readback), readback)) || !same(pattern, readback, sizeof(pattern)) ||
	    EFI_ERROR(block->write_blocks(block, block->media->media_id, scratch,
	    sizeof(saved), saved)) || EFI_ERROR(block->flush_blocks(block)))
		goto restore;
	serial("CDK2_ATA_BUS_RESTORE_FLUSH_OK\r\n");
	(void)system->boot->close_event(event);
	serial("CDK2_ATA_BUS_ORACLE_OK\r\n");
	return EFI_SUCCESS;
restore:
	(void)block->write_blocks(block, block->media->media_id, scratch,
		sizeof(saved), saved);
	if (event != NULL)
		(void)system->boot->close_event(event);
bad:
	serial("CDK2_ATA_BUS_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
