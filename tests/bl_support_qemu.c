/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/config.h>
#include <cdk2/pcd.h>

#define TOKEN_SETUP_HORIZONTAL 23U
#define TOKEN_SETUP_VERTICAL 24U
#define TOKEN_VIDEO_HORIZONTAL 29U
#define TOKEN_VIDEO_VERTICAL 30U

struct table_header { UINT64 signature; UINT32 revision, size, crc, reserved; };
struct system_table_view {
	struct table_header header;
	UINT16 *vendor;
	UINT32 revision, pad;
	void *console[6], *runtime;
	struct cdk2_pcd_boot_services *boot;
};

static const EFI_GUID pcd_protocol_guid = {
	0x11b34006, 0xd85b, 0x4d0a, { 0xa2, 0x90, 0xd5, 0xa5, 0x71, 0x31, 0x0e, 0xf7 }
};

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

EFI_STATUS CDK2_MS_ABI bl_support_qemu_entry(void *image, void *table)
{
	struct system_table_view *system = table;
	struct cdk2_pcd_protocol *pcd = NULL;
	UINT32 video_h, video_v, setup_h, setup_v, expected_h, expected_v;
	UINT64 candidate;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->boot == NULL || system->boot->locate_protocol == NULL)
		goto bad;
	status = system->boot->locate_protocol(&pcd_protocol_guid, NULL, (void **)&pcd);
	if (EFI_ERROR(status) || pcd == NULL || pcd->get32 == NULL)
		goto bad;
	video_h = pcd->get32(TOKEN_VIDEO_HORIZONTAL);
	video_v = pcd->get32(TOKEN_VIDEO_VERTICAL);
	setup_h = pcd->get32(TOKEN_SETUP_HORIZONTAL);
	setup_v = pcd->get32(TOKEN_SETUP_VERTICAL);
	if (video_h == 0 || video_v == 0 || setup_h == 0 || setup_v == 0 ||
	    setup_h > video_h || setup_v > video_v)
		goto bad;
	expected_h = video_h;
	expected_v = video_v;
#if CONFIG_CDK2_GOP_HIDPI
	if (video_h > CONFIG_CDK2_GOP_HIDPI_H_THRESHOLD &&
	    video_v > CONFIG_CDK2_GOP_HIDPI_V_THRESHOLD &&
	    (video_h & 1U) == 0 && (video_v & 1U) == 0) {
#if CONFIG_CDK2_GOP_HIDPI_ASPECT_CAP
		if ((UINT64)video_h * CONFIG_CDK2_GOP_HIDPI_ASPECT_H >
		    (UINT64)video_v * CONFIG_CDK2_GOP_HIDPI_ASPECT_W) {
			candidate = (UINT64)video_v * CONFIG_CDK2_GOP_HIDPI_ASPECT_W /
				CONFIG_CDK2_GOP_HIDPI_ASPECT_H;
			candidate &= ~1ULL;
			if (candidate != 0 && candidate < expected_h)
				expected_h = (UINT32)candidate;
		}
#else
		(void)candidate;
#endif
		expected_h /= 2U;
		expected_v /= 2U;
	}
#else
	(void)candidate;
#endif
	if (setup_h != expected_h || setup_v != expected_v)
		goto bad;
	serial_write("CDK2_BL_SUPPORT_PCD_EFFECT_OK\r\n");
	return EFI_SUCCESS;
bad:
	serial_write("CDK2_BL_SUPPORT_PCD_EFFECT_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
