/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/config.h>
#include <cdk2/pcd.h>
#include <guid/acpi_board_info.h>
#include <guid/graphics_info_hob.h>
#include <pi/hob.h>

#define TOKEN_SETUP_HORIZONTAL 23U
#define TOKEN_SETUP_VERTICAL 24U
#define TOKEN_VIDEO_HORIZONTAL 29U
#define TOKEN_VIDEO_VERTICAL 30U
#define TOKEN_PCIE_BASE 33U
#define TOKEN_PCIE_SIZE 34U
#define TOKEN_TPM_INSTANCE 47U
#define MAX_HOB_LIST_SIZE (1024U * 1024U)

struct table_header { UINT64 signature; UINT32 revision, size, crc, reserved; };
struct configuration_table { EFI_GUID guid; void *table; };
struct system_table_view {
	struct table_header header;
	UINT16 *vendor;
	UINT32 revision, pad;
	void *console[6], *runtime;
	struct cdk2_pcd_boot_services *boot;
	UINTN table_count;
	struct configuration_table *tables;
};

static const EFI_GUID pcd_protocol_guid = {
	0x11b34006, 0xd85b, 0x4d0a, { 0xa2, 0x90, 0xd5, 0xa5, 0x71, 0x31, 0x0e, 0xf7 }
};
static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID graphics_guid = {
	0x39f62cce, 0x6825, 0x4669, { 0xbb, 0x56, 0x54, 0x1a, 0xba, 0x75, 0x3a, 0x07 }
};
static const EFI_GUID board_guid = {
	0x0ad3d31b, 0xb3d8, 0x4506, { 0xae, 0x71, 0x2e, 0xf1, 0x10, 0x06, 0xd9, 0x0f }
};
static const EFI_GUID tpm12_guid = {
	0x8b01e5b6, 0x4f19, 0x46e8, { 0xab, 0x93, 0x1c, 0x53, 0x67, 0x1b, 0x90, 0xcc }
};
static const EFI_GUID tpm20_guid = {
	0x286bf25a, 0xc2c3, 0x408c, { 0xb3, 0xb4, 0x25, 0xe6, 0x75, 0x8b, 0x73, 0x17 }
};

static int same_guid(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left, *b = (const UINT8 *)right;
	UINTN index;
	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return 0;
	return 1;
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

static int find_hobs(void *list, const EFI_PEI_GRAPHICS_INFO_HOB **graphics,
	const ACPI_BOARD_INFO **board)
{
	UINT8 *bytes = list;
	UINTN walked = 0;

	*graphics = NULL; *board = NULL;
	if (list == NULL || ((UINTN)list & 7U) != 0)
		return 0;
	while (walked + sizeof(EFI_HOB_GENERIC_HEADER) <= MAX_HOB_LIST_SIZE) {
		EFI_HOB_GENERIC_HEADER *header = (void *)(bytes + walked);
		EFI_HOB_GUID_TYPE *guid;
		if (header->reserved != 0 || header->hob_length < sizeof(*header) ||
		    (header->hob_length & 7U) != 0 ||
		    header->hob_length > MAX_HOB_LIST_SIZE - walked)
			return 0;
		if (header->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST)
			return header->hob_length == sizeof(*header) &&
				*graphics != NULL && *board != NULL;
		if (header->hob_type == EFI_HOB_TYPE_GUID_EXTENSION &&
		    header->hob_length >= sizeof(*guid)) {
			guid = (void *)header;
			if (*graphics == NULL && same_guid(&guid->name, &graphics_guid) &&
			    header->hob_length >= sizeof(*guid) + sizeof(**graphics))
				*graphics = (void *)(guid + 1);
			else if (*board == NULL && same_guid(&guid->name, &board_guid) &&
			    header->hob_length >= sizeof(*guid) + sizeof(**board))
				*board = (void *)(guid + 1);
		}
		walked += header->hob_length;
	}
	return 0;
}

EFI_STATUS CDK2_MS_ABI bl_support_qemu_entry(void *image, void *table)
{
	struct system_table_view *system = table;
	struct cdk2_pcd_protocol *pcd = NULL;
	const EFI_PEI_GRAPHICS_INFO_HOB *graphics;
	const ACPI_BOARD_INFO *board;
	const EFI_GUID *expected_tpm, *actual_tpm;
	UINT32 video_h, video_v, setup_h, setup_v, expected_h, expected_v;
	UINT32 threshold_h = CONFIG_CDK2_GOP_HIDPI_H_THRESHOLD != 0 ?
		CONFIG_CDK2_GOP_HIDPI_H_THRESHOLD : 1920U;
	UINT32 threshold_v = CONFIG_CDK2_GOP_HIDPI_V_THRESHOLD != 0 ?
		CONFIG_CDK2_GOP_HIDPI_V_THRESHOLD : 1080U;
	UINT32 aspect_w = CONFIG_CDK2_GOP_HIDPI_ASPECT_W != 0 ?
		CONFIG_CDK2_GOP_HIDPI_ASPECT_W : 16U;
	UINT32 aspect_h = CONFIG_CDK2_GOP_HIDPI_ASPECT_H != 0 ?
		CONFIG_CDK2_GOP_HIDPI_ASPECT_H : 9U;
	UINT64 candidate;
	UINTN index;
	void *hob_list = NULL;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->boot == NULL || system->tables == NULL ||
	    system->boot->locate_protocol == NULL)
		goto bad;
	for (index = 0; index < system->table_count; index++)
		if (same_guid(&system->tables[index].guid, &hob_list_guid)) {
			hob_list = system->tables[index].table;
			break;
		}
	if (!find_hobs(hob_list, &graphics, &board))
		goto bad;
	status = system->boot->locate_protocol(&pcd_protocol_guid, NULL, (void **)&pcd);
	if (EFI_ERROR(status) || pcd == NULL || pcd->get32 == NULL ||
	    pcd->get64 == NULL || pcd->get_ptr == NULL || pcd->get_size == NULL)
		goto bad;
	video_h = pcd->get32(TOKEN_VIDEO_HORIZONTAL);
	video_v = pcd->get32(TOKEN_VIDEO_VERTICAL);
	setup_h = pcd->get32(TOKEN_SETUP_HORIZONTAL);
	setup_v = pcd->get32(TOKEN_SETUP_VERTICAL);
	if (video_h != graphics->graphics_mode.horizontal_resolution ||
	    video_v != graphics->graphics_mode.vertical_resolution ||
	    pcd->get64(TOKEN_PCIE_BASE) != board->pcie_base_address ||
	    pcd->get64(TOKEN_PCIE_SIZE) != board->pcie_base_size)
		goto bad;
	expected_h = video_h; expected_v = video_v;
#if CONFIG_CDK2_GOP_HIDPI_ASPECT_CAP
	if ((UINT64)video_h * aspect_h > (UINT64)video_v * aspect_w) {
		candidate = (UINT64)video_v * aspect_w / aspect_h;
		candidate &= ~1ULL;
		if (candidate != 0 && candidate < expected_h)
			expected_h = (UINT32)candidate;
	}
#else
	(void)candidate; (void)aspect_w; (void)aspect_h;
#endif
#if CONFIG_CDK2_GOP_HIDPI
	if (video_h > threshold_h && video_v > threshold_v &&
	    (expected_h & 1U) == 0 && (expected_v & 1U) == 0) {
		expected_h /= 2U;
		expected_v /= 2U;
	}
#else
	(void)threshold_h; (void)threshold_v;
#endif
	if (setup_h != expected_h || setup_v != expected_v)
		goto bad;
	expected_tpm = board->tpm12_present ? &tpm12_guid :
		(board->tpm20_present ? &tpm20_guid : NULL);
	actual_tpm = pcd->get_ptr(TOKEN_TPM_INSTANCE);
	if (expected_tpm == NULL || actual_tpm == NULL ||
	    pcd->get_size(TOKEN_TPM_INSTANCE) != sizeof(*expected_tpm) ||
	    !same_guid(actual_tpm, expected_tpm))
		goto bad;
	serial_write("CDK2_BL_SUPPORT_PCD_EFFECT_OK\r\n");
	return EFI_SUCCESS;
bad:
	serial_write("CDK2_BL_SUPPORT_PCD_EFFECT_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
