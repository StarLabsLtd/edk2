/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CDK2_PCI_BUS_BINDING_H
#define CDK2_PCI_BUS_BINDING_H

#include <cdk2/pci_bus_model.h>
#include <cdk2/pci_io_abi.h>

#define CDK2_PCI_CHILD_PCI_IO 1U
#define CDK2_PCI_CHILD_DEVICE_PATH 2U
#define CDK2_PCI_CHILD_LOAD_FILE 4U

struct cdk2_pci_bus_child {
	void *handle, *parent;
	void *device_path;
	size_t device_path_size;
	unsigned int installed;
	uint8_t parent_open;
	struct cdk2_pci_function function;
	struct cdk2_pci_io_model io_model;
	struct cdk2_pci_io_instance io;
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

#endif
