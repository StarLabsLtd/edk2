/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_model.h>

#include <string.h>

int cdk2_pci_host_begin(struct cdk2_pci_bus_host_model *host,
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

int cdk2_pci_host_submit(struct cdk2_pci_bus_host_model *host,
	const struct cdk2_pci_allocation_policy *proposed)
{
	if (host == NULL || proposed == NULL || host->phase != CDK2_PCI_HOST_BEGIN)
		return -1;
	host->proposed = *proposed;
	return 0;
}

int cdk2_pci_host_allocate(struct cdk2_pci_bus_host_model *host)
{
	struct cdk2_pci_root_allocation allocations[CDK2_PCI_MAX_ROOTS];
	if (host == NULL || host->phase != CDK2_PCI_HOST_BEGIN ||
	    host->cfg == NULL || host->topology == NULL)
		return -1;
	if (host->root_count != 0U) {
		uint64_t required[CDK2_PCI_MAX_ROOTS][CDK2_PCI_RESOURCE_CLASSES] = { { 0 } };
		for (size_t i = 0; i < host->topology->count; i++) {
			const struct cdk2_pci_function *fn = &host->topology->functions[i];
			size_t root;
			for (root = 0; root < host->root_count; root++)
				if (fn->bus >= host->roots[root].first_bus &&
				    fn->bus <= host->roots[root].last_bus)
					break;
			if (root == host->root_count)
				goto preflight_failed;
			for (uint8_t bar = 0; bar < fn->bar_count; bar++) {
				const struct cdk2_pci_bar *resource = &fn->bars[bar];
				unsigned int kind = resource->kind == CDK2_PCI_BAR_IO ? 0U :
					(resource->kind == CDK2_PCI_BAR_MEM64 ? 2U :
					(resource->prefetchable ? 3U : 1U));
				if (UINT64_MAX - required[root][kind] < resource->size)
					goto preflight_failed;
				required[root][kind] += resource->size;
			}
		}
		for (size_t root = 0; root < host->root_count; root++)
			for (unsigned int resource = 0;
			     resource < CDK2_PCI_RESOURCE_CLASSES; resource++)
				if (required[root][resource] >
				    host->roots[root].proposed[resource].length)
					goto preflight_failed;
		for (size_t root = 0; root < host->root_count; root++) {
			allocations[root].segment = host->roots[root].segment;
			allocations[root].first_bus = host->roots[root].first_bus;
			allocations[root].last_bus = host->roots[root].last_bus;
			allocations[root].policy = host->roots[root].policy_valid ?
				host->roots[root].policy : host->proposed;
		}
	}
	host->allocation_status = host->root_count == 0U ?
		cdk2_pci_allocate_resources(host->cfg, host->topology, &host->proposed) :
		cdk2_pci_allocate_root_resources(host->cfg, host->topology, allocations,
			host->root_count);
	for (size_t root = 0; root < host->root_count; root++)
		for (unsigned int resource = 0; resource < CDK2_PCI_RESOURCE_CLASSES;
		     resource++)
			host->roots[root].status[resource] = host->allocation_status;
	if (host->allocation_status != 0)
		return -1;
	host->phase = CDK2_PCI_HOST_ALLOCATED;
	return 0;
preflight_failed:
	host->allocation_status = -1;
	for (size_t root = 0; root < host->root_count; root++)
		for (unsigned int resource = 0; resource < CDK2_PCI_RESOURCE_CLASSES;
		     resource++)
			host->roots[root].status[resource] = -1;
	return -1;
}

int cdk2_pci_host_set_root_policy(struct cdk2_pci_bus_host_model *host, size_t root,
	const struct cdk2_pci_allocation_policy *policy)
{
	if (host == NULL || policy == NULL || host->phase != CDK2_PCI_HOST_BEGIN ||
	    root >= host->root_count)
		return -1;
	host->roots[root].policy = *policy;
	host->roots[root].policy_valid = 1;
	return 0;
}

int cdk2_pci_host_add_root(struct cdk2_pci_bus_host_model *host, uint16_t segment,
	uint8_t first_bus, uint8_t last_bus,
	const struct cdk2_pci_bus_resource_request proposed[CDK2_PCI_RESOURCE_CLASSES])
{
	if (host == NULL || proposed == NULL || host->phase != CDK2_PCI_HOST_BEGIN ||
	    host->root_count == CDK2_PCI_MAX_ROOTS || first_bus > last_bus)
		return -1;
	for (size_t root = 0; root < host->root_count; root++)
		if (segment == host->roots[root].segment &&
		    first_bus <= host->roots[root].last_bus &&
		    last_bus >= host->roots[root].first_bus)
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

int cdk2_pci_host_set(struct cdk2_pci_bus_host_model *host)
{
	if (host == NULL || host->phase != CDK2_PCI_HOST_ALLOCATED)
		return -1;
	host->phase = CDK2_PCI_HOST_SET;
	return 0;
}

int cdk2_pci_host_end(struct cdk2_pci_bus_host_model *host)
{
	if (host == NULL || host->phase != CDK2_PCI_HOST_SET)
		return -1;
	host->phase = CDK2_PCI_HOST_ENDED;
	return 0;
}
