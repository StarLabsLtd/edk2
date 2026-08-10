/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_USB_MASS_H
#define CDK2_USB_MASS_H

#include <cdk2/usb_bus.h>

#define CDK2_USB_MASS_CBW_SIGNATURE 0x43425355U
#define CDK2_USB_MASS_CSW_SIGNATURE 0x53425355U

struct cdk2_usb_mass_cbw {
	UINT32 signature, tag, transfer_length;
	UINT8 flags, lun, command_length, command[16];
} __packed;
struct cdk2_usb_mass_csw {
	UINT32 signature, tag, residue;
	UINT8 status;
} __packed;
struct cdk2_usb_mass_media {
	UINT64 last_block;
	UINT32 block_size, media_id;
	UINT8 lun;
	BOOLEAN present, removable, readonly;
};
struct cdk2_usb_mass_device {
	struct cdk2_usb_io_protocol *usb;
	struct cdk2_usb_mass_media media[16];
	UINT32 next_tag;
	UINT8 bulk_in, bulk_out, maximum_lun, media_count;
};

EFI_STATUS cdk2_usb_mass_init(struct cdk2_usb_mass_device *device,
	struct cdk2_usb_io_protocol *usb);
EFI_STATUS cdk2_usb_mass_build_cbw(struct cdk2_usb_mass_device *device,
	UINT8 lun, const void *command, UINT8 command_length, UINT32 transfer_length,
	BOOLEAN input, struct cdk2_usb_mass_cbw *cbw);
EFI_STATUS cdk2_usb_mass_validate_csw(const struct cdk2_usb_mass_cbw *cbw,
	const struct cdk2_usb_mass_csw *csw, UINT32 actual, UINT32 *transferred);
EFI_STATUS cdk2_usb_mass_parse_capacity10(const UINT8 bytes[8],
	struct cdk2_usb_mass_media *media);
EFI_STATUS cdk2_usb_mass_parse_capacity16(const UINT8 bytes[32],
	struct cdk2_usb_mass_media *media);

#endif
