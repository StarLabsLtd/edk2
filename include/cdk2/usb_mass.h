/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_USB_MASS_H
#define CDK2_USB_MASS_H

#include <cdk2/usb_bus.h>

#define CDK2_USB_DATA_IN 0U
#define CDK2_USB_DATA_OUT 1U
#define CDK2_USB_NO_DATA 2U
#include <cdk2/partition.h>

#define CDK2_USB_MASS_CBW_SIGNATURE 0x43425355U
#define CDK2_USB_MASS_CSW_SIGNATURE 0x53425355U
#define CDK2_USB_MASS_MAX_CONTROLLERS 16U
#ifndef EFI_WRITE_PROTECTED
#define EFI_WRITE_PROTECTED EFIERR(8)
#endif
#ifndef EFI_NO_MEDIA
#define EFI_NO_MEDIA EFIERR(12)
#endif
#ifndef EFI_MEDIA_CHANGED
#define EFI_MEDIA_CHANGED EFIERR(13)
#endif

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

struct cdk2_usb_mass_block {
	struct cdk2_block_io block;
	struct cdk2_block_io2 block2;
	struct cdk2_block_media media;
	struct cdk2_usb_mass_device *device;
	UINT8 lun;
};
struct cdk2_usb_mass_lun_path {
	UINT8 type, subtype;
	UINT16 length;
	UINT8 lun;
} __packed;
struct cdk2_usb_mass_child {
	struct cdk2_usb_mass_block block;
	struct cdk2_usb_mass_lun_path path;
	void *handle;
	void *device_path;
	BOOLEAN installed, linked;
};
struct cdk2_usb_mass_controller {
	void *handle;
	struct cdk2_usb_mass_device device;
	struct cdk2_usb_mass_child children[16];
	UINT8 child_count;
};
typedef EFI_STATUS cdk2_usb_mass_open_fn(void *context, void *controller,
	struct cdk2_usb_io_protocol **usb);
typedef EFI_STATUS cdk2_usb_mass_close_fn(void *context, void *controller);
typedef EFI_STATUS cdk2_usb_mass_publish_fn(void *context, void *controller,
	struct cdk2_usb_mass_child *child, void **handle);
typedef EFI_STATUS cdk2_usb_mass_remove_fn(void *context, void *controller,
	struct cdk2_usb_mass_child *child, void *handle);
typedef EFI_STATUS cdk2_usb_mass_link_fn(void *context, void *controller,
	void *child);
typedef EFI_STATUS cdk2_usb_mass_allocate_fn(void *context, UINTN size,
	void **buffer);
typedef void cdk2_usb_mass_release_fn(void *context, void *buffer);
struct cdk2_usb_mass_binding_services {
	void *context;
	cdk2_usb_mass_open_fn *open_usb;
	cdk2_usb_mass_close_fn *close_usb;
	cdk2_usb_mass_publish_fn *publish;
	cdk2_usb_mass_remove_fn *remove;
	cdk2_usb_mass_link_fn *link;
	cdk2_usb_mass_link_fn *unlink;
	cdk2_usb_mass_allocate_fn *allocate;
	cdk2_usb_mass_release_fn *release;
};
struct cdk2_usb_mass_binding {
	struct cdk2_usb_mass_binding_services services;
	struct cdk2_usb_mass_controller *controllers[CDK2_USB_MASS_MAX_CONTROLLERS];
	UINTN count;
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
EFI_STATUS cdk2_usb_mass_get_max_lun(struct cdk2_usb_mass_device *device);
EFI_STATUS cdk2_usb_mass_transport(struct cdk2_usb_mass_device *device,
	UINT8 lun, const void *command, UINT8 command_length, void *data,
	UINT32 *length, BOOLEAN input, UINTN timeout);
EFI_STATUS cdk2_usb_mass_reset(struct cdk2_usb_mass_device *device);
EFI_STATUS cdk2_usb_mass_probe_lun(struct cdk2_usb_mass_device *device,
	UINT8 lun);
EFI_STATUS cdk2_usb_mass_read(struct cdk2_usb_mass_device *device, UINT8 lun,
	UINT64 lba, UINTN blocks, void *buffer);
EFI_STATUS cdk2_usb_mass_write(struct cdk2_usb_mass_device *device, UINT8 lun,
	UINT64 lba, UINTN blocks, const void *buffer);
EFI_STATUS cdk2_usb_mass_block_init(struct cdk2_usb_mass_block *block,
	struct cdk2_usb_mass_device *device, UINT8 lun);
EFI_STATUS cdk2_usb_mass_binding_init(struct cdk2_usb_mass_binding *binding,
	const struct cdk2_usb_mass_binding_services *services);
EFI_STATUS cdk2_usb_mass_binding_supported(struct cdk2_usb_mass_binding *binding,
	void *controller);
EFI_STATUS cdk2_usb_mass_binding_start(struct cdk2_usb_mass_binding *binding,
	void *controller);
EFI_STATUS cdk2_usb_mass_binding_stop(struct cdk2_usb_mass_binding *binding,
	void *controller, UINTN child_count, void **children);

#endif
