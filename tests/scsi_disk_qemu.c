/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_disk.h>

typedef EFI_STATUS CDK2_MS_ABI locate_handles_fn(UINT32, const EFI_GUID *,
	void *, UINTN *, void ***);
typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_fn(UINT32, UINTN,
	void(CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI wait_fn(UINTN, void **, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI check_fn(void *);
struct boot_view {
	UINT8 header[64];
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	create_fn *create_event;
	void *set_timer;
	wait_fn *wait_for_event;
	void *signal_event;
	close_fn *close_event;
	check_fn *check_event;
	UINT8 before_handle[24];
	handle_fn *handle_protocol;
	UINT8 before_locate[152];
	locate_handles_fn *locate_handle_buffer;
};
struct system_view { UINT8 prefix[96]; struct boot_view *boot; };
static const EFI_GUID block_guid = { 0x964e5b21U, 0x6459U, 0x11d2U,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID block2_guid = { 0xa77b2472U, 0xe282U, 0x4e9fU,
	{ 0xa2, 0x45, 0xc2, 0xc0, 0xe2, 0x7b, 0xbc, 0xc1 } };
static const EFI_GUID disk_guid = { 0xd432a67fU, 0x14dcU, 0x484bU,
	{ 0xb3, 0xbb, 0x3f, 0x02, 0x91, 0x84, 0x93, 0x27 } };

static UINT8 port_read(UINT16 port)
{
	UINT8 value;

	__asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}

static void serial(const char *text)
{
	while (*text != '\0') {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++),
			"Nd"((UINT16)0x3f8));
	}
}

EFI_STATUS CDK2_MS_ABI scsi_disk_qemu_entry(void *image, void *table)
{
	struct system_view *system = table;
	struct cdk2_block_io *block = NULL;
	struct cdk2_block_io2 *block2 = NULL;
	struct cdk2_scsi_disk_info *disk = NULL;
	struct cdk2_block_io2_token token = { 0 };
	UINT8 inquiry[36];
	UINT32 inquiry_size = sizeof(inquiry);
	void **handles = NULL;
	UINTN handle_count = 0;
	UINTN index = 0;
	void *allocation = NULL;
	void *event = NULL;
	UINT8 *buffer;
	UINTN alignment;
	(void)image;

	serial("CDK2_SCSI_DISK_ORACLE_ENTRY\r\n");
	if (system == NULL || system->boot == NULL ||
	    EFI_ERROR(system->boot->locate_handle_buffer(2U, &disk_guid, NULL,
	    &handle_count, &handles)))
		goto bad;
	serial("SCSI_DISK_STAGE_HANDLES_OK\r\n");
	for (index = 0; index < handle_count; index++)
		if (!EFI_ERROR(system->boot->handle_protocol(handles[index], &block_guid,
		    (void **)&block)) && !EFI_ERROR(system->boot->handle_protocol(handles[index],
		    &block2_guid, (void **)&block2)) && !EFI_ERROR(system->boot->handle_protocol(
		    handles[index], &disk_guid, (void **)&disk)) && block->media != NULL &&
		    block->media == block2->media && block->media->read_only)
			break;
	(void)system->boot->free_pool(handles);
	if (block == NULL || block2 == NULL || disk == NULL ||
	    EFI_ERROR(disk->inquiry(disk, inquiry, &inquiry_size)) ||
	    inquiry_size != sizeof(inquiry) || (inquiry[0] & 0x1fU) != 5U)
		goto bad;
	serial("SCSI_DISK_STAGE_DISK_INFO_OK\r\n");
	alignment = block->media->io_align == 0U ? 1U : block->media->io_align;
	if ((alignment & (alignment - 1U)) != 0U || alignment > 0x10000U ||
	    EFI_ERROR(system->boot->allocate_pool(4U,
	    block->media->block_size + alignment - 1U, &allocation)))
		goto bad;
	buffer = (void *)(((UINTN)allocation + alignment - 1U) & ~(alignment - 1U));
	if (EFI_ERROR(block->read_blocks(block, block->media->media_id, 0,
	    block->media->block_size, buffer)))
		goto bad;
	serial("SCSI_DISK_STAGE_SYNC_READ_OK\r\n");
	if (EFI_ERROR(system->boot->create_event(0U, 0U, NULL, NULL, &event)))
		goto bad;
	token.event = event;
	if (EFI_ERROR(block2->read_blocks(block2, block->media->media_id, 0, &token,
	    block->media->block_size, buffer)))
		goto bad;
	serial("SCSI_DISK_STAGE_SUBMIT_OK\r\n");
	if (system->boot->check_event(event) != EFI_NOT_READY)
		goto bad;
	serial("SCSI_DISK_STAGE_RETURN_BEFORE_OK\r\n");
	if (EFI_ERROR(system->boot->wait_for_event(1U, &event, &index)) || index != 0U ||
	    token.transaction_status != EFI_SUCCESS)
		goto bad;
	serial("SCSI_DISK_STAGE_ASYNC_READ_OK\r\n");
	if (EFI_ERROR(block2->reset(block2, FALSE)))
		goto bad;
	serial("SCSI_DISK_STAGE_RESET_OK\r\n");
	(void)system->boot->close_event(event);
	(void)system->boot->free_pool(allocation);
	serial("CDK2_SCSI_DISK_ORACLE_OK\r\n");
	return EFI_SUCCESS;
bad:
	if (event != NULL)
		(void)system->boot->close_event(event);
	if (allocation != NULL)
		(void)system->boot->free_pool(allocation);
	serial("CDK2_SCSI_DISK_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
