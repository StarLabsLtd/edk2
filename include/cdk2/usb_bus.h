/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_USB_BUS_H
#define CDK2_USB_BUS_H

#include <uefi.h>
#include <cdk2/xhci.h>

#define CDK2_USB_MAX_INTERFACES 32U
#define CDK2_USB_MAX_ENDPOINTS 16U
#define CDK2_USB_MAX_CHILDREN 32U
#define CDK2_USB_MAX_CONFIG_LENGTH 4096U

typedef EFI_STATUS cdk2_usb_pool_allocate_fn(void *, UINTN, void **);

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
	UINT16 total_length;
	UINT8 value, attributes, maximum_power, interface_count, number_interfaces;
	struct cdk2_usb_interface interfaces[CDK2_USB_MAX_INTERFACES];
};

struct cdk2_usb_device_path_node {
	UINT8 type, subtype;
	UINT16 length;
	UINT8 parent_port, interface;
} __packed;

struct cdk2_usb_address_pool { UINT64 used[2]; };

struct cdk2_usb_io_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_control_fn(
	struct cdk2_usb_io_protocol *, struct cdk2_usb_request *, UINTN, UINT32,
	void *, UINTN *, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_bulk_fn(
	struct cdk2_usb_io_protocol *, UINT8, void *, UINTN *, UINTN, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_async_interrupt_fn(
	struct cdk2_usb_io_protocol *, UINT8, BOOLEAN, UINTN, UINTN,
	cdk2_usb2_async_callback_fn *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_sync_interrupt_fn(
	struct cdk2_usb_io_protocol *, UINT8, void *, UINTN *, UINTN, UINT32 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_stub_fn(void);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_descriptor_fn(
	struct cdk2_usb_io_protocol *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_index_descriptor_fn(
	struct cdk2_usb_io_protocol *, UINT8, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_string_fn(
	struct cdk2_usb_io_protocol *, UINT16, UINT8, CHAR16 * *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_languages_fn(
	struct cdk2_usb_io_protocol *, UINT16 **, UINT16 *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_usb_io_reset_fn(
	struct cdk2_usb_io_protocol *);

struct cdk2_usb_io_protocol {
	cdk2_usb_io_control_fn *control_transfer;
	cdk2_usb_io_bulk_fn *bulk_transfer;
	cdk2_usb_io_async_interrupt_fn *async_interrupt_transfer;
	cdk2_usb_io_sync_interrupt_fn *sync_interrupt_transfer;
	cdk2_usb_io_stub_fn *isochronous_transfer;
	cdk2_usb_io_stub_fn *async_isochronous_transfer;
	cdk2_usb_io_descriptor_fn *get_device_descriptor;
	cdk2_usb_io_descriptor_fn *get_config_descriptor;
	cdk2_usb_io_descriptor_fn *get_interface_descriptor;
	cdk2_usb_io_index_descriptor_fn *get_endpoint_descriptor;
	cdk2_usb_io_string_fn *get_string_descriptor;
	cdk2_usb_io_languages_fn *get_supported_languages;
	cdk2_usb_io_reset_fn *port_reset;
};

struct cdk2_usb_io_device {
	struct cdk2_usb_io_protocol protocol;
	struct cdk2_usb2_hc_protocol *host;
	struct cdk2_usb_configuration configuration;
	const struct cdk2_usb_interface *interface;
	UINT8 device_descriptor[18];
	UINT8 address, port, speed;
	UINT16 maximum_packet;
	UINT8 toggle[32];
	UINT16 languages[32];
	UINT16 language_count;
	CHAR16 string[127];
	void *allocate_context;
	cdk2_usb_pool_allocate_fn *allocate;
};

struct cdk2_usb_child {
	struct cdk2_usb_io_device io;
	struct cdk2_usb_device_path_node path;
	UINT8 port, address, interface;
	BOOLEAN active;
	void *handle;
	void *device_path;
};

typedef void cdk2_usb_delay_fn(void *context, UINTN microseconds);
struct cdk2_usb_bus {
	struct cdk2_usb2_hc_protocol *host;
	struct cdk2_usb_address_pool addresses;
	struct cdk2_usb_child children[CDK2_USB_MAX_CHILDREN];
	void *delay_context;
	cdk2_usb_delay_fn *delay;
	void *allocate_context;
	cdk2_usb_pool_allocate_fn *allocate;
	UINT8 child_count;
};

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
EFI_STATUS cdk2_usb_io_init(struct cdk2_usb_io_device *device,
	struct cdk2_usb2_hc_protocol *host, UINT8 address, UINT8 port, UINT8 speed,
	UINT16 maximum_packet, const UINT8 descriptor[18],
	const struct cdk2_usb_configuration *configuration, UINT8 interface_number,
	UINT8 alternate);
EFI_STATUS cdk2_usb_bus_init(struct cdk2_usb_bus *bus,
	struct cdk2_usb2_hc_protocol *host, void *delay_context,
	cdk2_usb_delay_fn *delay);
EFI_STATUS cdk2_usb_bus_enumerate_port(struct cdk2_usb_bus *bus, UINT8 port);
EFI_STATUS cdk2_usb_bus_remove_port(struct cdk2_usb_bus *bus, UINT8 port);

typedef EFI_STATUS cdk2_usb_open_host_fn(void *context, void *controller,
	struct cdk2_usb2_hc_protocol **host);
typedef EFI_STATUS cdk2_usb_close_host_fn(void *context, void *controller);
typedef EFI_STATUS cdk2_usb_install_marker_fn(void *context, void *controller,
	void *marker);
typedef EFI_STATUS cdk2_usb_uninstall_marker_fn(void *context, void *controller,
	void *marker);
typedef EFI_STATUS cdk2_usb_publish_child_fn(void *context, void *controller,
	struct cdk2_usb_child *child, void **handle);
typedef EFI_STATUS cdk2_usb_remove_child_fn(void *context, void *controller,
	struct cdk2_usb_child *child, void *handle);
typedef EFI_STATUS cdk2_usb_link_child_fn(void *context, void *controller,
	void *child);
typedef EFI_STATUS cdk2_usb_unlink_child_fn(void *context, void *controller,
	void *child);
typedef EFI_STATUS cdk2_usb_allocate_fn(void *context, UINTN size, void **buffer);
typedef void cdk2_usb_free_fn(void *context, void *buffer);

struct cdk2_usb_binding_services {
	void *context;
	cdk2_usb_open_host_fn *open_host;
	cdk2_usb_close_host_fn *close_host;
	cdk2_usb_install_marker_fn *install_marker;
	cdk2_usb_uninstall_marker_fn *uninstall_marker;
	cdk2_usb_publish_child_fn *publish_child;
	cdk2_usb_remove_child_fn *remove_child;
	cdk2_usb_link_child_fn *link_child;
	cdk2_usb_unlink_child_fn *unlink_child;
	cdk2_usb_allocate_fn *allocate;
	cdk2_usb_free_fn *free;
	void *delay_context;
	cdk2_usb_delay_fn *delay;
};

struct cdk2_usb_binding_controller {
	struct cdk2_usb_bus *bus;
	void *handle;
	BOOLEAN marker;
};

struct cdk2_usb_binding {
	struct cdk2_usb_binding_services services;
	struct cdk2_usb_binding_controller controllers[8];
	UINT8 count;
};

EFI_STATUS cdk2_usb_binding_init(struct cdk2_usb_binding *binding,
	const struct cdk2_usb_binding_services *services);
EFI_STATUS cdk2_usb_binding_supported(struct cdk2_usb_binding *binding,
	void *controller);
EFI_STATUS cdk2_usb_binding_start(struct cdk2_usb_binding *binding,
	void *controller);
EFI_STATUS cdk2_usb_binding_rescan(struct cdk2_usb_binding *binding,
	void *controller);
EFI_STATUS cdk2_usb_binding_stop(struct cdk2_usb_binding *binding,
	void *controller, UINTN child_count, void **children);

#endif
