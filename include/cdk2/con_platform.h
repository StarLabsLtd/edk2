/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_PLATFORM_H_
#define CDK2_CON_PLATFORM_H_

#include <uefi.h>

#define CDK2_DP_HARDWARE 0x01U
#define CDK2_DP_ACPI 0x02U
#define CDK2_DP_MESSAGING 0x03U
#define CDK2_DP_END 0x7fU
#define CDK2_DP_CONTROLLER 0x05U
#define CDK2_DP_ACPI_ADR 0x03U
#define CDK2_DP_USB_CLASS 0x0fU
#define CDK2_DP_USB_WWID 0x10U
#define CDK2_DP_END_INSTANCE 0x01U
#define CDK2_DP_END_ENTIRE 0xffU

struct cdk2_dp_node {
	UINT8 type, subtype;
	UINT16 length;
} __packed;

struct cdk2_usb_identity {
	UINT16 vendor, product;
	UINT8 device_class, device_subclass, device_protocol;
	UINT8 interface_number, interface_class, interface_subclass, interface_protocol;
	const CHAR16 *serial;
};

BOOLEAN cdk2_con_path_valid(const void *path, UINTN size);
BOOLEAN cdk2_con_gop_siblings(const void *left, UINTN left_size,
	const void *right, UINTN right_size);
BOOLEAN cdk2_con_usb_short_match(const struct cdk2_usb_identity *usb,
	const void *short_path, UINTN short_size);
BOOLEAN cdk2_con_path_instance_match(const void *single, UINTN single_size,
	const void *instance, UINTN instance_size,
	const struct cdk2_usb_identity *usb);

#endif
