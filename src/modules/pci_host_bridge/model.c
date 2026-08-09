/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pci_host_bridge.h>

#include <string.h>

static const uint8_t aperture_index[CDK2_PCI_RESOURCE_TYPES] = { 1, 2, 4, 3, 5 };

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

uint64_t cdk2_pci_host_init(struct cdk2_pci_host_model *host,
	const void *hob, size_t hob_size)
{
	size_t count, index;
	uint8_t assigned;
	uint64_t status;

	if (host == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_pci_root_bridges_validate(hob, hob_size, &count, &assigned);
	if (status != EFI_SUCCESS)
		return status;
	if (count > CDK2_PCI_HOST_MAX_ROOTS)
		return EFI_OUT_OF_RESOURCES;
	memset(host, 0, sizeof(*host));
	host->count = count;
	host->can_restart = 1;
	host->resource_assigned = assigned;
	for (index = 0; index < count; index++) {
		status = cdk2_pci_root_bridge_get(hob, hob_size, index,
			&host->root[index]);
		if (status != EFI_SUCCESS)
			return status;
	}
	return EFI_SUCCESS;
}

uint64_t cdk2_pci_host_submit(struct cdk2_pci_host_model *host, size_t root,
	size_t type, uint64_t length, uint64_t alignment)
{
	struct cdk2_pci_resource_request *request;

	if (host == NULL || root >= host->count || type >= CDK2_PCI_RESOURCE_TYPES ||
	    alignment == UINT64_MAX || (alignment & (alignment + 1U)) != 0)
		return EFI_INVALID_PARAMETER;
	request = &host->request[root][type];
	request->length = length;
	request->alignment = alignment;
	request->submitted = 1;
	request->allocated = 0;
	return EFI_SUCCESS;
}

uint64_t cdk2_pci_host_set_allocator(struct cdk2_pci_host_model *host,
	void *context, cdk2_pci_reserve_fn *reserve, cdk2_pci_release_fn *release)
{
	if (host == NULL || (reserve == NULL) != (release == NULL))
		return EFI_INVALID_PARAMETER;
	host->allocator_context = context;
	host->reserve = reserve;
	host->release = release;
	return EFI_SUCCESS;
}

static uint64_t allocate_request(struct cdk2_pci_host_model *host, size_t root,
	size_t type)
{
	struct cdk2_pci_resource_request *request = &host->request[root][type];
	const struct cdk2_pci_aperture *aperture =
		&host->root[root].aperture[aperture_index[type]];
	uint64_t base, mask = request->alignment;

	if (!request->submitted || request->length == 0)
		return EFI_SUCCESS;
	if (host->resource_assigned) {
		if (aperture->base > aperture->limit)
			return EFI_OUT_OF_RESOURCES;
		request->base = aperture->base;
		request->length = aperture->limit - aperture->base + 1U;
		request->alignment = 0;
		request->allocated = 1;
		return EFI_SUCCESS;
	}
	if (aperture->base > aperture->limit || request->length - 1U >
		aperture->limit - aperture->base)
		return EFI_OUT_OF_RESOURCES;
	base = (aperture->base + mask) & ~mask;
	if (base < aperture->base || request->length - 1U > aperture->limit - base ||
	    (aperture->translation & mask) != 0)
		return EFI_OUT_OF_RESOURCES;
	request->base = base;
	if (host->reserve != NULL && !host->resource_assigned) {
		uint64_t allocated = base;
		uint64_t status = host->reserve(host->allocator_context, type != 0,
			base - aperture->translation, request->length, mask, &allocated);

		if (status != EFI_SUCCESS)
			return status;
		if (allocated > UINT64_MAX - aperture->translation) {
			(void)host->release(host->allocator_context, type != 0, allocated,
				request->length);
			return EFI_OUT_OF_RESOURCES;
		}
		request->base = allocated + aperture->translation;
	}
	request->allocated = 1;
	return EFI_SUCCESS;
}

static void release_request(struct cdk2_pci_host_model *host, size_t root,
	size_t type)
{
	struct cdk2_pci_resource_request *request = &host->request[root][type];
	const struct cdk2_pci_aperture *aperture =
		&host->root[root].aperture[aperture_index[type]];

	if (request->allocated && host->release != NULL && !host->resource_assigned)
		(void)host->release(host->allocator_context, type != 0,
			request->base - aperture->translation, request->length);
	request->allocated = 0;
}

uint64_t cdk2_pci_host_notify(struct cdk2_pci_host_model *host,
	enum cdk2_pci_host_phase phase)
{
	size_t root, type;
	uint64_t status;

	if (host == NULL || phase > CDK2_PCI_END_ENUMERATION)
		return EFI_INVALID_PARAMETER;
	if (phase == CDK2_PCI_BEGIN_ENUMERATION) {
		if (!host->can_restart)
			return EFI_NOT_READY;
		memset(host->request, 0, sizeof(host->request));
		memset(host->resource_submitted, 0, sizeof(host->resource_submitted));
		return EFI_SUCCESS;
	}
	if (phase == CDK2_PCI_BEGIN_BUS_ALLOCATION) {
		host->can_restart = 0;
		return EFI_SUCCESS;
	}
	if (phase == CDK2_PCI_FREE_RESOURCES) {
		for (root = 0; root < host->count; root++)
			for (type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++)
				release_request(host, root, type);
		memset(host->request, 0, sizeof(host->request));
		memset(host->resource_submitted, 0, sizeof(host->resource_submitted));
		host->can_restart = 1;
		return EFI_SUCCESS;
	}
	if (phase != CDK2_PCI_ALLOCATE_RESOURCES)
		return EFI_SUCCESS;
	for (root = 0; root < host->count; root++) {
		uint8_t handled[CDK2_PCI_RESOURCE_TYPES] = { 0 };
		size_t slot;

		if (!host->resource_submitted[root])
			return EFI_NOT_READY;
		for (slot = 0; slot < CDK2_PCI_RESOURCE_TYPES; slot++) {
			size_t candidate = CDK2_PCI_RESOURCE_TYPES;
			uint64_t maximum = 0;

			for (type = 0; type < CDK2_PCI_RESOURCE_TYPES; type++) {
				if (!host->request[root][type].submitted) {
					handled[type] = 1;
					continue;
				}
				if (!handled[type] && (candidate == CDK2_PCI_RESOURCE_TYPES ||
				    maximum <= host->request[root][type].alignment)) {
					candidate = type;
					maximum = host->request[root][type].alignment;
				}
			}
			if (candidate == CDK2_PCI_RESOURCE_TYPES)
				continue;
			handled[candidate] = 1;
			status = allocate_request(host, root, candidate);
			if (status != EFI_SUCCESS) {
				size_t undo_root, undo_type;

				for (undo_root = 0; undo_root <= root; undo_root++)
					for (undo_type = 0; undo_type < CDK2_PCI_RESOURCE_TYPES;
					     undo_type++)
						release_request(host, undo_root, undo_type);
				return status;
			}
		}
	}
	return EFI_SUCCESS;
}
