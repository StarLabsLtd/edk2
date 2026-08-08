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

enum cdk2_con_variable_operation {
	CDK2_CON_CHECK,
	CDK2_CON_APPEND,
	CDK2_CON_DELETE,
};

typedef EFI_STATUS cdk2_con_variable_read_fn(void *, const CHAR16 *, void **, UINTN *);
typedef EFI_STATUS cdk2_con_variable_write_fn(void *, const CHAR16 *, const void *, UINTN);
typedef EFI_STATUS cdk2_con_path_edit_fn(void *, const void *, UINTN, const void *, UINTN,
	enum cdk2_con_variable_operation, void **, UINTN *);
typedef void cdk2_con_release_fn(void *, void *);

struct cdk2_con_variable_ops {
	cdk2_con_variable_read_fn *read;
	cdk2_con_variable_write_fn *write;
	cdk2_con_path_edit_fn *edit;
	cdk2_con_release_fn *release;
};

EFI_STATUS cdk2_con_update_variable(const struct cdk2_con_variable_ops *ops,
	void *context, const CHAR16 *name, const void *path, UINTN path_size,
	enum cdk2_con_variable_operation operation);

#define CDK2_CON_OPEN_TEST 0x04U
#define CDK2_CON_OPEN_GET 0x02U
#define CDK2_CON_OPEN_BY_DRIVER 0x10U
#define CDK2_CON_ALREADY_STARTED EFIERR(20)

enum cdk2_con_direction { CDK2_CON_INPUT, CDK2_CON_OUTPUT };
struct cdk2_con_binding;
typedef EFI_STATUS cdk2_con_open_fn(void *, void *, const EFI_GUID *, UINT32, void **);
typedef EFI_STATUS cdk2_con_close_fn(void *, void *, const EFI_GUID *);
typedef EFI_STATUS cdk2_con_marker_fn(void *, void *, const EFI_GUID *);
typedef EFI_STATUS cdk2_con_update_fn(void *, const CHAR16 *, const void *, UINTN,
	enum cdk2_con_variable_operation);
typedef BOOLEAN cdk2_con_gop_candidate_fn(void *, const void *, UINTN);

struct cdk2_con_binding_ops {
	cdk2_con_open_fn *open;
	cdk2_con_close_fn *close;
	cdk2_con_marker_fn *install;
	cdk2_con_marker_fn *uninstall;
	cdk2_con_update_fn *update;
	cdk2_con_gop_candidate_fn *gop_candidate;
};

struct cdk2_con_binding {
	const struct cdk2_con_binding_ops *ops;
	void *context, *controller, *interface;
	const void *path;
	UINTN path_size;
	enum cdk2_con_direction direction;
	BOOLEAN protocol_open, input_marker, output_marker, error_marker;
};

EFI_STATUS cdk2_con_binding_supported(struct cdk2_con_binding *binding,
	void *controller);
EFI_STATUS cdk2_con_binding_start(struct cdk2_con_binding *binding,
	void *controller);
EFI_STATUS cdk2_con_binding_stop(struct cdk2_con_binding *binding);

#endif
