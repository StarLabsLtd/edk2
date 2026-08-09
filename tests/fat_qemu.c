/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/fat_binding.h>

typedef EFI_STATUS CDK2_MS_ABI locate_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
					       void(CDK2_MS_ABI *)(void *, void *), void *,
					       void **);
typedef EFI_STATUS CDK2_MS_ABI wait_event_fn(UINTN, void **, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
struct boot_view {
	UINT8 header[56];
	create_event_fn *create_event;
	void *set_timer;
	wait_event_fn *wait_event;
	void *signal_event;
	close_event_fn *close_event;
	UINT8 before_locate[224];
	locate_fn *locate_protocol;
};
typedef char create_event_offset_must_be_56[
	offsetof(struct boot_view, create_event) == 56U ? 1 : -1];
typedef char locate_protocol_offset_must_be_320[
	offsetof(struct boot_view, locate_protocol) == 320U ? 1 : -1];
struct system_view {
	UINT8 before_boot[96];
	struct boot_view *boot;
};
struct file_info {
	UINT64 size, file_size, physical_size;
	UINT8 times[48];
	UINT64 attribute;
	CHAR16 name[32];
};
static const EFI_GUID simple_fs_guid = {
	0x964e5b22U, 0x6459U, 0x11d2U, {0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU}};
static const EFI_GUID file_info_guid = {
	0x09576e92U, 0x6d3fU, 0x11d2U, {0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU}};
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
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++), "Nd"((UINT16)0x3f8));
	}
}
static void CDK2_MS_ABI notify(void *event, void *context)
{
	(void)event;
	*(BOOLEAN *)context = TRUE;
}

EFI_STATUS CDK2_MS_ABI fat_qemu_entry(void *image, void *table)
{
	struct system_view *system = table;
	struct cdk2_fat_simple_fs_protocol *fs;
	struct cdk2_fat_file_protocol *root = NULL, *file = NULL;
	EFI_STATUS status;
	struct cdk2_fat_file_io_token token;
	struct file_info info = {0};
	UINT8 written[16] = "native-fat-data", readback[16] = {0};
	UINTN size, index;
	UINTN compare;
	void *event = NULL;
	BOOLEAN done = FALSE;
	(void)image;
	serial("CDK2_FAT_ORACLE_ENTRY\r\n");
	if (system == NULL || system->boot == NULL || system->boot->locate_protocol == NULL ||
	    EFI_ERROR(system->boot->locate_protocol(&simple_fs_guid, NULL, (void **)&fs)) ||
	    fs == NULL)
		goto bad;
	if (EFI_ERROR(fs->open_volume(fs, &root)))
		goto bad;
	status = root->open(root, &file, L"\x00e4-sync.tmp", 0x8000000000000003ULL, 0U);
	if (EFI_ERROR(status) || file == NULL) {
		goto bad;
	}
	size = sizeof(written);
	if (EFI_ERROR(file->write(file, &size, written)) || size != sizeof(written))
		goto bad;
	if (EFI_ERROR(file->set_position(file, 0U)))
		goto bad;
	size = sizeof(readback);
	if (EFI_ERROR(file->read(file, &size, readback)))
		goto bad;
	for (compare = 0U; compare < sizeof(written); compare++)
		if (written[compare] != readback[compare]) {
			goto bad;
		}
	info.size = sizeof(info);
	info.file_size = sizeof(written);
	info.attribute = 0U;
	info.name[0] = 0x00c4U;
	info.name[1] = '-';
	info.name[2] = 'r';
	info.name[3] = 0U;
	if (EFI_ERROR(file->set_info(file, (EFI_GUID *)&file_info_guid, sizeof(info), &info)))
		goto bad;
	if (file->revision >= 0x20000ULL) {
		if (system->boot->create_event == NULL || system->boot->wait_event == NULL ||
		    EFI_ERROR(system->boot->create_event(0x200U, 8U, notify, &done, &event)))
			goto bad;
		token = (struct cdk2_fat_file_io_token){event, EFI_NOT_READY, 0U, NULL};
		if (EFI_ERROR(file->flush_ex(file, &token)) ||
		    EFI_ERROR(system->boot->wait_event(1U, &event, &index)) || !done ||
		    EFI_ERROR(token.status))
			goto bad;
		(void)system->boot->close_event(event);
	}
	if (EFI_ERROR(file->delete(file)))
		goto bad;
	(void)root->close(root);
	serial("CDK2_FAT_SYNC_ASYNC_UNICODE_OK\r\n");
	serial("CDK2_FAT_ORACLE_OK\r\n");
	return EFI_SUCCESS;
bad:
	serial("CDK2_FAT_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
