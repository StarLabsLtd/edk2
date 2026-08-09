/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_model.h>

#include <string.h>

int cdk2_pci_host_begin(struct cdk2_pci_host_model *host,
	const struct cdk2_pci_cfg *cfg, struct cdk2_pci_topology *topology)
{
	if (host == NULL || cfg == NULL || topology == NULL ||
	    host->phase != CDK2_PCI_HOST_IDLE)
		return -1;
	host->cfg = cfg;
	host->topology = topology;
	host->allocation_status = -1;
	host->root_count = 0;
	memset(&host->proposed, 0, sizeof(host->proposed));
	host->phase = CDK2_PCI_HOST_BEGIN;
	return 0;
}

int cdk2_pci_host_submit(struct cdk2_pci_host_model *host,
	const struct cdk2_pci_allocation_policy *proposed)
{
	if (host == NULL || proposed == NULL || host->phase != CDK2_PCI_HOST_BEGIN)
		return -1;
	host->proposed = *proposed;
	return 0;
}

int cdk2_pci_host_allocate(struct cdk2_pci_host_model *host)
{
	if (host == NULL || host->phase != CDK2_PCI_HOST_BEGIN ||
	    host->cfg == NULL || host->topology == NULL)
		return -1;
	host->allocation_status = cdk2_pci_allocate_resources(host->cfg,
		host->topology, &host->proposed);
	for (size_t root = 0; root < host->root_count; root++)
		for (unsigned int resource = 0; resource < CDK2_PCI_RESOURCE_CLASSES;
		     resource++)
			host->roots[root].status[resource] = host->allocation_status;
	if (host->allocation_status != 0)
		return -1;
	host->phase = CDK2_PCI_HOST_ALLOCATED;
	return 0;
}

int cdk2_pci_host_add_root(struct cdk2_pci_host_model *host, uint16_t segment,
	uint8_t first_bus, uint8_t last_bus,
	const struct cdk2_pci_resource_request proposed[CDK2_PCI_RESOURCE_CLASSES])
{
	if (host == NULL || proposed == NULL || host->phase != CDK2_PCI_HOST_BEGIN ||
	    host->root_count == CDK2_PCI_MAX_ROOTS || first_bus > last_bus)
		return -1;
	host->roots[host->root_count].segment = segment;
	host->roots[host->root_count].first_bus = first_bus;
	host->roots[host->root_count].last_bus = last_bus;
	memcpy(host->roots[host->root_count].proposed, proposed,
		sizeof(host->roots[host->root_count].proposed));
	for (unsigned int resource = 0; resource < CDK2_PCI_RESOURCE_CLASSES;
	     resource++)
		host->roots[host->root_count].status[resource] = -1;
	host->root_count++;
	return 0;
}

int cdk2_pci_apply_hotplug(const struct cdk2_pci_hotplug_ops *ops,
	struct cdk2_pci_topology *topology,
	struct cdk2_pci_allocation_policy *policy)
{
	struct cdk2_pci_topology staged;
	struct cdk2_pci_allocation_policy staged_policy;
	size_t initialized[CDK2_PCI_MAX_FUNCTIONS];
	size_t initialized_count = 0;
	if (ops == NULL || ops->initialize_controller == NULL ||
	    ops->deinitialize_controller == NULL || ops->get_padding == NULL ||
	    topology == NULL || policy == NULL)
		return -1;
	staged = *topology;
	staged_policy = *policy;
	for (size_t i = 0; i < staged.count; i++) {
		struct cdk2_pci_function *bridge = &staged.functions[i];
		uint64_t padding[CDK2_PCI_RESOURCE_CLASSES];
		uint8_t type = bridge->header_type & 0x7fU;
		if (type != 1U && type != 2U)
			continue;
		if (ops->get_padding(ops->context, bridge, padding) != 0)
			goto rollback;
		memcpy(bridge->hotplug_padding, padding, sizeof(bridge->hotplug_padding));
		if (ops->initialize_controller(ops->context, bridge) != 0)
			goto rollback;
		initialized[initialized_count++] = i;
		bridge->hotplug_bridge = 1;
	}
	*topology = staged;
	*policy = staged_policy;
	return 0;
rollback:
	while (initialized_count != 0U) {
		size_t i = initialized[--initialized_count];
		ops->deinitialize_controller(ops->context, &staged.functions[i]);
	}
	return -1;
}

int cdk2_pci_host_set(struct cdk2_pci_host_model *host)
{
	if (host == NULL || host->phase != CDK2_PCI_HOST_ALLOCATED)
		return -1;
	host->phase = CDK2_PCI_HOST_SET;
	return 0;
}

int cdk2_pci_host_end(struct cdk2_pci_host_model *host)
{
	if (host == NULL || host->phase != CDK2_PCI_HOST_SET)
		return -1;
	host->phase = CDK2_PCI_HOST_ENDED;
	return 0;
}
