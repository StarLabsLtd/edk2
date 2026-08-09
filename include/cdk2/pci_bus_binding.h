/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CDK2_PCI_BUS_BINDING_H
#define CDK2_PCI_BUS_BINDING_H

#include <cdk2/pci_bus_model.h>
#include <cdk2/pci_io_abi.h>

#define CDK2_PCI_CHILD_PCI_IO 1U
#define CDK2_PCI_CHILD_DEVICE_PATH 2U
#define CDK2_PCI_CHILD_LOAD_FILE 4U

struct cdk2_efi_load_file2_protocol;
typedef UINTN * cdk2_uintn_pointer;
typedef CHAR8 * cdk2_char8_pointer;
typedef CHAR16 * cdk2_char16_pointer;
typedef cdk2_char16_pointer * cdk2_char16_pointer_pointer;
typedef EFI_STATUS CDK2_MS_ABI cdk2_load_file2_fn(
	struct cdk2_efi_load_file2_protocol *, const void *, BOOLEAN,
	cdk2_uintn_pointer, void *);
struct cdk2_efi_load_file2_protocol {
	cdk2_load_file2_fn *load_file;
};
struct cdk2_pci_bus_child;
struct cdk2_pci_load_file_instance {
	struct cdk2_efi_load_file2_protocol protocol;
	struct cdk2_pci_bus_child *child;
};

struct cdk2_component_name_protocol;
struct cdk2_pci_bus_binding;
typedef EFI_STATUS CDK2_MS_ABI cdk2_get_driver_name_fn(
	struct cdk2_component_name_protocol *protocol, cdk2_char8_pointer language,
	cdk2_char16_pointer_pointer name);
typedef EFI_STATUS CDK2_MS_ABI cdk2_get_controller_name_fn(
	struct cdk2_component_name_protocol *protocol, void *controller, void *child,
	cdk2_char8_pointer language, cdk2_char16_pointer_pointer name);
struct cdk2_component_name_protocol {
	cdk2_get_driver_name_fn *get_driver_name;
	cdk2_get_controller_name_fn *get_controller_name;
	CHAR8 *supported_languages;
};
struct cdk2_component_name_instance {
	struct cdk2_component_name_protocol protocol;
	struct cdk2_pci_bus_binding *binding;
	uint8_t iso639;
};

struct cdk2_driver_binding_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_driver_supported_fn(
	struct cdk2_driver_binding_protocol *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_driver_start_fn(
	struct cdk2_driver_binding_protocol *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_driver_stop_fn(
	struct cdk2_driver_binding_protocol *, void *, UINTN, void **);
struct cdk2_driver_binding_protocol {
	cdk2_driver_supported_fn *supported;
	cdk2_driver_start_fn *start;
	cdk2_driver_stop_fn *stop;
	UINT32 version;
	void *image_handle;
	void *driver_binding_handle;
};

struct cdk2_pci_bus_child {
	void *handle, *parent;
	void *root_io;
	void *entry_context;
	EFI_STATUS io_status;
	void *device_path;
	size_t device_path_size;
	unsigned int installed;
	uint8_t parent_open;
	struct cdk2_pci_function function;
	struct cdk2_pci_io_model io_model;
	struct cdk2_pci_io_instance io;
	struct cdk2_pci_load_file_instance load_file;
};

struct cdk2_pci_bus_services {
	void *context;
	void *(*allocate)(void *context, size_t size);
	void (*free)(void *context, void *buffer);
	int (*install)(void *context, void **handle,
		struct cdk2_pci_bus_child *child, unsigned int protocols);
	int (*uninstall)(void *context, void *handle,
		struct cdk2_pci_bus_child *child, unsigned int protocols);
	int (*open_parent_by_child)(void *context, void *parent, void *child);
	int (*close_parent_by_child)(void *context, void *parent, void *child);
	int (*initialize_io)(void *context, const struct cdk2_pci_function *function,
		struct cdk2_pci_io_model *io);
};

struct cdk2_pci_bus_binding {
	struct cdk2_pci_bus_services services;
	struct cdk2_pci_bus_child *children[CDK2_PCI_MAX_FUNCTIONS];
	size_t child_count;
	struct cdk2_component_name_instance component_name;
	struct cdk2_component_name_instance component_name2;
};

struct cdk2_pci_bus_driver {
	struct cdk2_driver_binding_protocol protocol;
	struct cdk2_pci_bus_binding binding;
	void *context;
	int (*probe)(void *context, void *controller, void *remaining);
	EFI_STATUS (*start_global)(void *context, void *controller, void *remaining);
	int (*discover)(void *context, void *controller, void *remaining,
		struct cdk2_pci_topology *topology, void **path, size_t *path_size);
	void (*release_discovery)(void *context, void *path);
	void (*finish_discovery)(void *context, void *controller, int success);
	void (*finish_stop)(void *context, void *controller, int success);
	int (*publish)(void *context, struct cdk2_pci_bus_driver *driver);
	int (*unpublish)(void *context, struct cdk2_pci_bus_driver *driver);
	uint8_t published;
};

int cdk2_pci_bus_start(struct cdk2_pci_bus_binding *binding, void *parent,
	const void *parent_path, size_t parent_path_size,
	const struct cdk2_pci_topology *topology);
int cdk2_pci_bus_stop(struct cdk2_pci_bus_binding *binding, void *parent,
	void *const *child_handles, size_t child_count);
int cdk2_pci_bus_remove_bdf(struct cdk2_pci_bus_binding *binding, void *parent,
	uint8_t bus, uint8_t device, uint8_t function);
int cdk2_pci_bus_component_name(const char *language, const char **name);
int cdk2_pci_bus_controller_name(const struct cdk2_pci_bus_binding *binding,
	void *controller, void *child, const char *language, const char **name);
void cdk2_pci_bus_initialize_component_names(struct cdk2_pci_bus_binding *binding);
int cdk2_pci_bus_driver_entry(struct cdk2_pci_bus_driver *driver,
	void *image_handle);
int cdk2_pci_bus_driver_unload(struct cdk2_pci_bus_driver *driver);
EFI_STATUS CDK2_MS_ABI cdk2_pci_bus_entry(void *image, void *system_table);
EFI_STATUS CDK2_MS_ABI cdk2_pci_bus_unload(void *image);

#endif
