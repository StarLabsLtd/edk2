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
	if (host->allocation_status != 0)
		return -1;
	host->phase = CDK2_PCI_HOST_ALLOCATED;
	return 0;
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
