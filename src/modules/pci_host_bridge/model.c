/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pci_host_bridge.h>

#include <string.h>

static uint64_t validate_apertures(const struct cdk2_pci_root_bridge_record *bridge)
{
	if (bridge->dma_above_4g > 1U || bridge->no_extended_config > 1U)
		return EFI_COMPROMISED_DATA;
	if (bridge->aperture[0].base > bridge->aperture[0].limit ||
	    bridge->aperture[0].limit > 0xffU)
		return EFI_COMPROMISED_DATA;
	return EFI_SUCCESS;
}

uint64_t cdk2_pci_root_bridges_validate(const void *hob, size_t hob_size,
	size_t *count, uint8_t *resource_assigned)
{
	const struct cdk2_pci_root_bridges_hob *header = hob;
	size_t required, index;

	if (hob == NULL || count == NULL || resource_assigned == NULL ||
	    hob_size < sizeof(*header))
		return EFI_INVALID_PARAMETER;
	if (header->header.revision != CDK2_PCI_ROOT_BRIDGES_REVISION ||
	    header->header.length < sizeof(*header) ||
	    header->header.length > hob_size || header->resource_assigned > 1U ||
	    header->count == 0)
		return EFI_COMPROMISED_DATA;
	required = sizeof(*header) + header->count * sizeof(header->bridge[0]);
	if (required > header->header.length)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < header->count; index++)
		if (validate_apertures(&header->bridge[index]) != EFI_SUCCESS)
			return EFI_COMPROMISED_DATA;
	*count = header->count;
	*resource_assigned = header->resource_assigned;
	return EFI_SUCCESS;
}

uint64_t cdk2_pci_root_bridge_get(const void *hob, size_t hob_size,
	size_t index, struct cdk2_pci_root_bridge_view *bridge)
{
	const struct cdk2_pci_root_bridges_hob *header = hob;
	size_t count;
	uint8_t assigned;
	uint64_t status;

	if (bridge == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_pci_root_bridges_validate(hob, hob_size, &count, &assigned);
	if (status != EFI_SUCCESS)
		return status;
	if (index >= count)
		return EFI_NOT_FOUND;
	memset(bridge, 0, sizeof(*bridge));
	bridge->segment = header->bridge[index].segment;
	bridge->supports = header->bridge[index].supports;
	bridge->attributes = header->bridge[index].attributes;
	bridge->dma_above_4g = header->bridge[index].dma_above_4g;
	bridge->no_extended_config = header->bridge[index].no_extended_config;
	bridge->allocation_attributes = header->bridge[index].allocation_attributes;
	memcpy(bridge->aperture, header->bridge[index].aperture,
		sizeof(bridge->aperture));
	bridge->hid = header->bridge[index].hid;
	bridge->uid = header->bridge[index].uid;
	return EFI_SUCCESS;
}
