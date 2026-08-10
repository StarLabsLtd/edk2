/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_USB_BUS_H
#define CDK2_USB_BUS_H

#include <uefi.h>

#define CDK2_USB_MAX_INTERFACES 32U
#define CDK2_USB_MAX_ENDPOINTS 16U

struct cdk2_usb_endpoint {
	UINT8 address, attributes, interval;
	UINT16 maximum_packet;
};

struct cdk2_usb_interface {
	UINT8 number, alternate, class_code, subclass, protocol;
	UINT8 endpoint_count;
	struct cdk2_usb_endpoint endpoints[CDK2_USB_MAX_ENDPOINTS];
};

struct cdk2_usb_configuration {
	UINT8 value, attributes, maximum_power, interface_count;
	struct cdk2_usb_interface interfaces[CDK2_USB_MAX_INTERFACES];
};

struct cdk2_usb_device_path_node {
	UINT8 type, subtype;
	UINT16 length;
	UINT8 parent_port, interface;
} __packed;

struct cdk2_usb_address_pool { UINT64 used[2]; };

EFI_STATUS cdk2_usb_parse_configuration(const void *data, UINTN length,
	struct cdk2_usb_configuration *configuration);
EFI_STATUS cdk2_usb_find_interface(const struct cdk2_usb_configuration *configuration,
	UINT8 number, UINT8 alternate, const struct cdk2_usb_interface **interface);
EFI_STATUS cdk2_usb_build_path(UINT8 parent_port, UINT8 interface,
	struct cdk2_usb_device_path_node *node);
EFI_STATUS cdk2_usb_parse_path(const void *node, UINTN available,
	UINT8 *parent_port, UINT8 *interface);
EFI_STATUS cdk2_usb_allocate_address(struct cdk2_usb_address_pool *pool,
	UINT8 *address);
EFI_STATUS cdk2_usb_release_address(struct cdk2_usb_address_pool *pool,
	UINT8 address);

#endif
