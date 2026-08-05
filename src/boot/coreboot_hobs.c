/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Freestanding HOB construction from a validated coreboot handoff.
 */

#include "coreboot_hobs.h"

#include <guid/memory_allocation_hob.h>

#define CDK2_COREBOOT_HOB_RESOURCE_ATTRIBUTES                                  \
	(EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED | \
	 EFI_RESOURCE_ATTRIBUTE_TESTED | EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |  \
	 EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |                            \
	 EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |                      \
	 EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE)

#define CDK2_COREBOOT_1MB_MASK 0xfffffULL
#define CDK2_COREBOOT_4GB      0x100000000ULL

static const EFI_GUID m_cdk2_payload_resource_handoff_hob_guid = {
	0xc263a6a9,
	0x6938,
	0x495e,
	{0x95, 0xb6, 0x6a, 0x1a, 0x0b, 0x6b, 0xa8, 0x8e}
};

static BOOLEAN cdk2_coreboot_align_up8(UINTN value, UINTN *aligned_value)
{
	if (aligned_value == NULL || value > MAX_UINTN - 7U) {
		return FALSE;
	}

	*aligned_value = (value + 7U) & ~(UINTN)7U;
	return TRUE;
}

static BOOLEAN cdk2_coreboot_align_up1_mb(UINT64 value, UINT64 *aligned_value)
{
	if (aligned_value == NULL || value > MAX_UINT64 - CDK2_COREBOOT_1MB_MASK) {
		return FALSE;
	}

	*aligned_value = (value + CDK2_COREBOOT_1MB_MASK) & ~CDK2_COREBOOT_1MB_MASK;
	return TRUE;
}

static BOOLEAN cdk2_coreboot_range_valid(UINTN bottom, UINTN top)
{
	return bottom <= top;
}

static BOOLEAN cdk2_coreboot_memory_range_end(const struct cdk2_coreboot_memory_range *range,
					      UINT64 *end)
{
	if (range == NULL || end == NULL || range->size == 0 ||
	    range->base > MAX_UINT64 - range->size) {
		return FALSE;
	}

	*end = range->base + range->size;
	return TRUE;
}

static BOOLEAN cdk2_coreboot_hob_memory_range(
	const struct cdk2_coreboot_memory_range *range,
	struct cdk2_coreboot_memory_range *hob_range)
{
	UINT64 end;

	if (range == NULL || hob_range == NULL) {
		return FALSE;
	}

	*hob_range = *range;
	if (range->type != CB_MEM_RAM) {
		return TRUE;
	}

	if (!cdk2_coreboot_memory_range_end(range, &end) ||
	    range->base >= CDK2_COREBOOT_TEMP_MAP_LIMIT) {
		return FALSE;
	}

	if (end > CDK2_COREBOOT_TEMP_MAP_LIMIT) {
		hob_range->size = CDK2_COREBOOT_TEMP_MAP_LIMIT - range->base;
	}

	return hob_range->size != 0;
}

static BOOLEAN cdk2_coreboot_uintn_range_fits(UINT64 base, UINT64 length)
{
	if (base > MAX_UINTN) {
		return FALSE;
	}

	return length <= (UINT64)(MAX_UINTN - (UINTN)base);
}

static BOOLEAN cdk2_coreboot_descriptor_range_valid(EFI_PHYSICAL_ADDRESS base_address,
						    UINT64 length)
{
	return (length != 0) && (base_address <= MAX_UINT64 - length);
}

EFI_STATUS
cdk2_coreboot_find_hob_memory_base(const struct cdk2_coreboot_handoff *coreboot,
				   EFI_PHYSICAL_ADDRESS payload_base, UINTN payload_size,
				   UINTN hob_region_size, UINT64 temporary_map_limit,
				   UINTN *hob_mem_base)
{
	const struct cdk2_coreboot_memory_range *range;
	UINT64 payload_end;
	UINT64 base;
	UINT64 end;
	UINTN index;

	if (coreboot == NULL || hob_mem_base == NULL || payload_size == 0 ||
	    hob_region_size == 0 || temporary_map_limit == 0 ||
	    payload_base > MAX_UINT64 - payload_size) {
		return EFI_INVALID_PARAMETER;
	}

	if (coreboot->memory_range_count > ARRAY_SIZE(coreboot->memory_ranges)) {
		return EFI_COMPROMISED_DATA;
	}

	payload_end = payload_base + payload_size;
	for (index = 0; index < coreboot->memory_range_count; index++) {
		range = &coreboot->memory_ranges[index];
		if (range->type != CB_MEM_RAM) {
			continue;
		}

		if (!cdk2_coreboot_memory_range_end(range, &end)) {
			return EFI_COMPROMISED_DATA;
		}

		if (range->base >= temporary_map_limit) {
			continue;
		}

		if (!cdk2_coreboot_align_up1_mb(range->base, &base)) {
			continue;
		}

		if (base >= temporary_map_limit) {
			continue;
		}

		if (end > temporary_map_limit) {
			end = temporary_map_limit;
		}

		if ((base < payload_end) && (payload_base < end)) {
			if (!cdk2_coreboot_align_up1_mb(payload_end, &base)) {
				continue;
			}
		}

		if ((end > base) && (end - base >= hob_region_size) &&
		    cdk2_coreboot_uintn_range_fits(base, hob_region_size)) {
			*hob_mem_base = (UINTN)base;
			return EFI_SUCCESS;
		}
	}

	return EFI_OUT_OF_RESOURCES;
}

static EFI_STATUS
cdk2_coreboot_validate_memory_ranges(const struct cdk2_coreboot_handoff *coreboot)
{
	UINTN index;
	UINTN other_index;
	UINT64 end;
	UINT64 other_end;

	if (coreboot->memory_range_count > ARRAY_SIZE(coreboot->memory_ranges)) {
		return EFI_COMPROMISED_DATA;
	}

	for (index = 0; index < coreboot->memory_range_count; index++) {
		if (!cdk2_coreboot_memory_range_end(&coreboot->memory_ranges[index], &end)) {
			return EFI_COMPROMISED_DATA;
		}

		for (other_index = index + 1; other_index < coreboot->memory_range_count;
		     other_index++) {
			if (!cdk2_coreboot_memory_range_end(&coreboot->memory_ranges[other_index],
							    &other_end)) {
				return EFI_COMPROMISED_DATA;
			}

			if ((coreboot->memory_ranges[index].base < other_end) &&
			    (coreboot->memory_ranges[other_index].base < end)) {
				return EFI_COMPROMISED_DATA;
			}
		}
	}

	return EFI_SUCCESS;
}

static void *cdk2_coreboot_append_hob(UINTN *cursor, UINTN limit, UINT16 type, UINTN length)
{
	EFI_HOB_GENERIC_HEADER *hob;
	UINTN aligned_length;

	if (cursor == NULL || length < sizeof(EFI_HOB_GENERIC_HEADER) || length > MAX_UINT16) {
		return NULL;
	}

	if (!cdk2_coreboot_align_up8(length, &aligned_length)) {
		return NULL;
	}

	if (aligned_length > MAX_UINT16) {
		return NULL;
	}

	if (*cursor > limit || aligned_length > limit - *cursor) {
		return NULL;
	}

	hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)*cursor;
	for (UINTN index = 0; index < aligned_length; index++) {
		((UINT8 *)(void *)hob)[index] = 0;
	}

	hob->hob_type = type;
	hob->hob_length = (UINT16)aligned_length;
	*cursor += aligned_length;
	return hob;
}

static UINT64 cdk2_coreboot_find_tolud(const struct cdk2_coreboot_handoff *coreboot)
{
	UINT64 tolud;
	UINTN index;
	UINT64 end;
	BOOLEAN changed;

	tolud = 0;
	for (index = 0; index < coreboot->memory_range_count; index++) {
		if ((coreboot->memory_ranges[index].type != CB_MEM_RAM) &&
		    (coreboot->memory_ranges[index].type != CB_MEM_ACPI) &&
		    (coreboot->memory_ranges[index].type != CB_MEM_NVS)) {
			continue;
		}

		if (!cdk2_coreboot_memory_range_end(&coreboot->memory_ranges[index], &end)) {
			continue;
		}

		if (end <= CDK2_COREBOOT_4GB && end > tolud) {
			tolud = end;
		}
	}

	do {
		changed = FALSE;
		for (index = 0; index < coreboot->memory_range_count; index++) {
			if (!cdk2_coreboot_memory_range_end(&coreboot->memory_ranges[index], &end)) {
				continue;
			}

			if (end <= CDK2_COREBOOT_4GB &&
			    coreboot->memory_ranges[index].base <= tolud && end > tolud) {
				tolud = end;
				changed = TRUE;
			}
		}
	} while (changed);

	return tolud;
}

static BOOLEAN cdk2_coreboot_range_contains(UINT64 base, UINT64 length, UINT64 inner_base,
					    UINT64 inner_length)
{
	if (length == 0 || inner_length == 0 || base > MAX_UINT64 - length ||
	    inner_base > MAX_UINT64 - inner_length) {
		return FALSE;
	}

	return base <= inner_base && base + length >= inner_base + inner_length;
}

static EFI_RESOURCE_TYPE
cdk2_coreboot_resource_type(const struct cdk2_coreboot_handoff *coreboot,
			    const struct cdk2_coreboot_memory_range *range, UINT64 tolud)
{
	if (range->type == CB_MEM_TABLE) {
		return EFI_RESOURCE_MEMORY_RESERVED;
	}

	if ((range->type == CB_MEM_RAM) || (range->type == CB_MEM_ACPI) ||
	    (range->type == CB_MEM_NVS)) {
		return EFI_RESOURCE_SYSTEM_MEMORY;
	}

	if (cdk2_coreboot_range_contains(range->base, range->size, coreboot->pcie_base_address,
					 coreboot->pcie_base_size)) {
		return EFI_RESOURCE_MEMORY_MAPPED_IO;
	}

	if (range->base < tolud) {
		return EFI_RESOURCE_MEMORY_RESERVED;
	}

	if (range->base < CDK2_COREBOOT_4GB) {
		return EFI_RESOURCE_MEMORY_MAPPED_IO;
	}

	return EFI_RESOURCE_MEMORY_RESERVED;
}

static EFI_MEMORY_TYPE cdk2_coreboot_allocation_type(UINT32 type)
{
	if (type == CB_MEM_ACPI) {
		return efi_acpi_reclaim_memory;
	}

	if (type == CB_MEM_NVS) {
		return efi_acpi_memory_nvs;
	}

	if (type == CB_MEM_UNUSABLE) {
		return efi_unusable_memory;
	}

	return efi_reserved_memory_type;
}

static EFI_STATUS cdk2_coreboot_validate_append_handoff(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
							EFI_HOB_GENERIC_HEADER **end)
{
	EFI_HOB_GENERIC_HEADER *hob;
	EFI_PHYSICAL_ADDRESS expected_free_memory_bottom;
	UINTN end_address;
	UINTN hob_address;
	UINTN hob_length;

	if (handoff == NULL || end == NULL || handoff->efi_end_of_hob_list == 0) {
		return EFI_INVALID_PARAMETER;
	}

	if (handoff->header.hob_type != EFI_HOB_TYPE_HANDOFF ||
	    handoff->header.hob_length != sizeof(*handoff) ||
	    handoff->efi_memory_bottom > handoff->efi_memory_top ||
	    handoff->efi_free_memory_bottom > handoff->efi_free_memory_top ||
	    handoff->efi_free_memory_bottom < handoff->efi_memory_bottom ||
	    handoff->efi_free_memory_top > handoff->efi_memory_top ||
	    handoff->efi_end_of_hob_list > (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - sizeof(**end))) {
		return EFI_COMPROMISED_DATA;
	}

	expected_free_memory_bottom = handoff->efi_end_of_hob_list + sizeof(**end);
	if (handoff->efi_free_memory_bottom != expected_free_memory_bottom ||
	    expected_free_memory_bottom > handoff->efi_free_memory_top) {
		return EFI_COMPROMISED_DATA;
	}

	end_address = (UINTN)handoff->efi_end_of_hob_list;
	hob = (EFI_HOB_GENERIC_HEADER *)(void *)handoff;
	while ((UINTN)hob < end_address) {
		hob_address = (UINTN)hob;
		if (end_address - hob_address < sizeof(*hob)) {
			return EFI_COMPROMISED_DATA;
		}

		hob_length = hob->hob_length;
		if (hob_length < sizeof(*hob) || hob_length > end_address - hob_address ||
		    (hob_length & 7U) != 0 || hob->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST) {
			return EFI_COMPROMISED_DATA;
		}

		hob = (EFI_HOB_GENERIC_HEADER *)(void *)((UINT8 *)(void *)hob + hob_length);
	}

	if ((UINTN)hob != end_address) {
		return EFI_COMPROMISED_DATA;
	}

	*end = (EFI_HOB_GENERIC_HEADER *)(UINTN)handoff->efi_end_of_hob_list;
	if ((*end)->hob_type != EFI_HOB_TYPE_END_OF_HOB_LIST ||
	    (*end)->hob_length != sizeof(**end)) {
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_append_before_end(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
						  UINT16 type, UINTN length, void **new_hob)
{
	EFI_HOB_GENERIC_HEADER *end;
	UINTN cursor;
	UINTN limit;
	UINTN first_length;
	UINTN end_length;
	EFI_STATUS status;

	if (new_hob == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_validate_append_handoff(handoff, &end);
	if (EFI_ERROR(status)) {
		return status;
	}

	cursor = (UINTN)end;
	limit = (UINTN)handoff->efi_free_memory_top;
	if (cursor > limit) {
		return EFI_COMPROMISED_DATA;
	}

	if (!cdk2_coreboot_align_up8(length, &first_length) ||
	    !cdk2_coreboot_align_up8(sizeof(*end), &end_length)) {
		return EFI_OUT_OF_RESOURCES;
	}

	if (first_length > limit - cursor || end_length > limit - cursor - first_length) {
		return EFI_OUT_OF_RESOURCES;
	}

	*new_hob = cdk2_coreboot_append_hob(&cursor, limit, type, length);
	if (*new_hob == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	end = (EFI_HOB_GENERIC_HEADER *)cdk2_coreboot_append_hob(
		&cursor, limit, EFI_HOB_TYPE_END_OF_HOB_LIST, sizeof(*end));
	if (end == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	handoff->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)end;
	handoff->efi_free_memory_bottom = cursor;
	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_append_resource(const struct cdk2_coreboot_handoff *coreboot,
						UINTN *cursor, UINTN limit,
						const struct cdk2_coreboot_memory_range *range,
						UINT64 tolud)
{
	EFI_HOB_RESOURCE_DESCRIPTOR *resource;

	resource = (EFI_HOB_RESOURCE_DESCRIPTOR *)cdk2_coreboot_append_hob(
		cursor, limit, EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, sizeof(*resource));
	if (resource == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	resource->resource_type = cdk2_coreboot_resource_type(coreboot, range, tolud);
	resource->resource_attribute = CDK2_COREBOOT_HOB_RESOURCE_ATTRIBUTES;
	resource->physical_start = range->base;
	resource->resource_length = range->size;
	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_append_fv_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
			    EFI_PHYSICAL_ADDRESS base_address, UINT64 length)
{
	EFI_HOB_FIRMWARE_VOLUME *fv;
	EFI_STATUS status;

	if (!cdk2_coreboot_descriptor_range_valid(base_address, length)) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_append_before_end(handoff, EFI_HOB_TYPE_FV, sizeof(*fv),
						 (void **)&fv);
	if (EFI_ERROR(status)) {
		return status;
	}

	fv->base_address = base_address;
	fv->length = length;
	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_append_capsule_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
				 EFI_PHYSICAL_ADDRESS base_address, UINT64 length)
{
	EFI_HOB_UEFI_CAPSULE *capsule;
	EFI_STATUS status;

	if (!cdk2_coreboot_descriptor_range_valid(base_address, length)) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_append_before_end(handoff, EFI_HOB_TYPE_UEFI_CAPSULE,
						 sizeof(*capsule), (void **)&capsule);
	if (EFI_ERROR(status)) {
		return status;
	}

	capsule->base_address = base_address;
	capsule->length = length;
	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_append_guid_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff, const EFI_GUID *guid,
			      const void *data, UINTN data_length)
{
	EFI_HOB_GUID_TYPE *guid_hob;
	EFI_STATUS status;
	UINT8 *destination;
	const UINT8 *source;
	UINTN index;

	if (handoff == NULL || guid == NULL || (data == NULL && data_length != 0) ||
	    data_length > MAX_UINT16 - sizeof(*guid_hob)) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_append_before_end(handoff, EFI_HOB_TYPE_GUID_EXTENSION,
						 sizeof(*guid_hob) + data_length,
						 (void **)&guid_hob);
	if (EFI_ERROR(status)) {
		return status;
	}

	guid_hob->name = *guid;
	destination = (UINT8 *)(void *)(guid_hob + 1);
	source = (const UINT8 *)data;
	for (index = 0; index < data_length; index++) {
		destination[index] = source[index];
	}

	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_append_memory_allocation_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
					   EFI_PHYSICAL_ADDRESS base_address, UINT64 length,
					   EFI_MEMORY_TYPE memory_type)
{
	EFI_HOB_MEMORY_ALLOCATION *allocation;
	EFI_STATUS status;

	if (!cdk2_coreboot_descriptor_range_valid(base_address, length)) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_append_before_end(handoff, EFI_HOB_TYPE_MEMORY_ALLOCATION,
						 sizeof(*allocation), (void **)&allocation);
	if (EFI_ERROR(status)) {
		return status;
	}

	allocation->alloc_descriptor.memory_base_address = base_address;
	allocation->alloc_descriptor.memory_length = length;
	allocation->alloc_descriptor.memory_type = memory_type;
	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_append_stack_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
			       EFI_PHYSICAL_ADDRESS base_address, UINT64 length)
{
	EFI_HOB_MEMORY_ALLOCATION_STACK *stack;
	EFI_GUID allocation_guid;
	EFI_STATUS status;

	if (!cdk2_coreboot_descriptor_range_valid(base_address, length) ||
	    ((base_address & EFI_PAGE_MASK) != 0) || ((length & EFI_PAGE_MASK) != 0)) {
		return EFI_INVALID_PARAMETER;
	}

	allocation_guid = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_STACK_GUID;
	status = cdk2_coreboot_append_before_end(handoff, EFI_HOB_TYPE_MEMORY_ALLOCATION,
						 sizeof(*stack), (void **)&stack);
	if (EFI_ERROR(status)) {
		return status;
	}

	stack->alloc_descriptor.name = allocation_guid;
	stack->alloc_descriptor.memory_base_address = base_address;
	stack->alloc_descriptor.memory_length = length;
	stack->alloc_descriptor.memory_type = efi_boot_services_data;
	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_append_cpu_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff, UINT8 size_of_memory_space,
			     UINT8 size_of_io_space)
{
	EFI_HOB_CPU *cpu;
	EFI_STATUS status;

	status = cdk2_coreboot_append_before_end(handoff, EFI_HOB_TYPE_CPU, sizeof(*cpu),
						 (void **)&cpu);
	if (EFI_ERROR(status)) {
		return status;
	}

	cpu->size_of_memory_space = size_of_memory_space;
	cpu->size_of_io_space = size_of_io_space;
	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_append_module_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
				const EFI_GUID *module_name, EFI_PHYSICAL_ADDRESS base_address,
				UINT64 length, EFI_PHYSICAL_ADDRESS entry_point)
{
	EFI_HOB_MEMORY_ALLOCATION_MODULE *module;
	EFI_GUID allocation_guid;
	EFI_STATUS status;
	UINT8 *destination;
	const UINT8 *source;
	UINTN index;

	if (module_name == NULL ||
	    !cdk2_coreboot_descriptor_range_valid(base_address, length)) {
		return EFI_INVALID_PARAMETER;
	}

	allocation_guid = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_MODULE_GUID;
	status = cdk2_coreboot_append_before_end(handoff, EFI_HOB_TYPE_MEMORY_ALLOCATION,
						 sizeof(*module), (void **)&module);
	if (EFI_ERROR(status)) {
		return status;
	}

	module->memory_allocation_header.name = allocation_guid;
	module->memory_allocation_header.memory_base_address = base_address;
	module->memory_allocation_header.memory_length = length;
	module->memory_allocation_header.memory_type = efi_boot_services_code;
	source = (const UINT8 *)module_name;
	destination = (UINT8 *)&module->module_name;
	for (index = 0; index < sizeof(EFI_GUID); index++) {
		destination[index] = source[index];
	}

	module->entry_point = entry_point;
	return EFI_SUCCESS;
}

static BOOLEAN cdk2_coreboot_range_needs_allocation(
	const struct cdk2_coreboot_handoff *coreboot,
	const struct cdk2_coreboot_memory_range *range)
{
	if ((range->type == CB_MEM_ACPI) || (range->type == CB_MEM_NVS) ||
	    (range->type == CB_MEM_UNUSABLE)) {
		return TRUE;
	}

	return cdk2_coreboot_range_contains(range->base, range->size,
					    coreboot->pcie_base_address,
					    coreboot->pcie_base_size);
}

static EFI_STATUS
cdk2_coreboot_append_allocation(const struct cdk2_coreboot_handoff *coreboot, UINTN *cursor,
				UINTN limit, const struct cdk2_coreboot_memory_range *range)
{
	EFI_HOB_MEMORY_ALLOCATION *allocation;

	if (!cdk2_coreboot_range_needs_allocation(coreboot, range)) {
		return EFI_SUCCESS;
	}

	allocation = (EFI_HOB_MEMORY_ALLOCATION *)cdk2_coreboot_append_hob(
		cursor, limit, EFI_HOB_TYPE_MEMORY_ALLOCATION, sizeof(*allocation));
	if (allocation == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	allocation->alloc_descriptor.memory_base_address = range->base;
	allocation->alloc_descriptor.memory_length = range->size;
	allocation->alloc_descriptor.memory_type = cdk2_coreboot_allocation_type(range->type);
	return EFI_SUCCESS;
}

static EFI_STATUS
cdk2_coreboot_append_payload_resource_handoff_hob(UINTN *cursor, UINTN limit,
						  const struct cdk2_coreboot_handoff *coreboot)
{
	EFI_HOB_GUID_TYPE *guid_hob;
	const struct cb_payload_resource_handoff *payload_resource;
	UINTN length;
	UINTN aligned_length;
	UINTN end_length;
	UINTN index;
	UINT8 *destination;
	const UINT8 *source;

	if (coreboot->payload_resource_handoff_status != EFI_SUCCESS ||
	    coreboot->payload_resource_handoff == NULL) {
		return EFI_SUCCESS;
	}

	payload_resource = coreboot->payload_resource_handoff;
	if (payload_resource->size > MAX_UINT16 - sizeof(*guid_hob)) {
		return EFI_OUT_OF_RESOURCES;
	}

	length = sizeof(*guid_hob) + payload_resource->size;
	if (!cdk2_coreboot_align_up8(length, &aligned_length) || aligned_length > MAX_UINT16) {
		return EFI_OUT_OF_RESOURCES;
	}

	if (!cdk2_coreboot_align_up8(sizeof(EFI_HOB_GENERIC_HEADER), &end_length)) {
		return EFI_OUT_OF_RESOURCES;
	}

	if (*cursor > limit || aligned_length > limit - *cursor ||
	    end_length > limit - *cursor - aligned_length) {
		return EFI_OUT_OF_RESOURCES;
	}

	guid_hob = (EFI_HOB_GUID_TYPE *)cdk2_coreboot_append_hob(
		cursor, limit, EFI_HOB_TYPE_GUID_EXTENSION, length);
	if (guid_hob == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	guid_hob->name = m_cdk2_payload_resource_handoff_hob_guid;
	destination = (UINT8 *)(void *)(guid_hob + 1);
	source = (const UINT8 *)payload_resource;
	for (index = 0; index < payload_resource->size; index++) {
		destination[index] = source[index];
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_resolve_boot_mode(const struct cdk2_coreboot_handoff *coreboot,
						  BOOLEAN capsule_support_enabled,
						  EFI_BOOT_MODE *boot_mode)
{
	EFI_STATUS status;
	const void *record;
	const struct lb_boot_mode *coreboot_boot_mode;
	const struct cb_boot_info *boot_info;

	if (coreboot == NULL || boot_mode == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*boot_mode = BOOT_WITH_FULL_CONFIGURATION;
	if (coreboot->header == NULL && coreboot->record_count == 0) {
		return EFI_SUCCESS;
	}

	if (capsule_support_enabled) {
		status = cdk2_coreboot_find_record(coreboot, CB_TAG_CAPSULE,
						   sizeof(struct cb_range), &record);
		if (!EFI_ERROR(status)) {
			*boot_mode = BOOT_ON_FLASH_UPDATE;
			return EFI_SUCCESS;
		}

		if (status != EFI_NOT_FOUND) {
			return status;
		}

		status = cdk2_coreboot_find_record(coreboot, CB_TAG_BOOT_INFO,
						   sizeof(*boot_info), &record);
		if (!EFI_ERROR(status)) {
			boot_info = (const struct cb_boot_info *)record;
			if (boot_info->is_disk_capsules_boot != 0) {
				*boot_mode = BOOT_ON_FLASH_UPDATE;
				return EFI_SUCCESS;
			}
		} else if (status != EFI_NOT_FOUND) {
			return status;
		}
	}

	status = cdk2_coreboot_find_record(coreboot, CB_TAG_BOOT_MODE,
					   sizeof(*coreboot_boot_mode), &record);
	if (status == EFI_NOT_FOUND) {
		return EFI_SUCCESS;
	}

	if (EFI_ERROR(status)) {
		return status;
	}

	coreboot_boot_mode = (const struct lb_boot_mode *)record;
	switch (coreboot_boot_mode->boot_mode) {
	case LB_BOOT_MODE_NORMAL:
		break;
	case LB_BOOT_MODE_FLASH_UPDATE:
		*boot_mode = BOOT_ON_FLASH_UPDATE;
		break;
	default:
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_build_hobs(const struct cdk2_coreboot_handoff *coreboot, void *efi_memory_bottom,
			 void *efi_memory_top, void *efi_free_memory_bottom,
			 void *efi_free_memory_top, BOOLEAN capsule_support_enabled,
			 void **handoff)
{
	EFI_HOB_HANDOFF_INFO_TABLE *hob_info;
	EFI_HOB_GENERIC_HEADER *end;
	UINTN memory_bottom;
	UINTN memory_top;
	UINTN free_memory_bottom;
	UINTN free_memory_top;
	UINTN cursor;
	UINT64 tolud;
	UINTN index;
	struct cdk2_coreboot_memory_range hob_range;
	EFI_BOOT_MODE boot_mode;
	EFI_STATUS status;

	if (coreboot == NULL || handoff == NULL || efi_memory_bottom == NULL ||
	    efi_memory_top == NULL || efi_free_memory_bottom == NULL ||
	    efi_free_memory_top == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	memory_bottom = (UINTN)efi_memory_bottom;
	memory_top = (UINTN)efi_memory_top;
	free_memory_bottom = (UINTN)efi_free_memory_bottom;
	free_memory_top = (UINTN)efi_free_memory_top;
	if (!cdk2_coreboot_range_valid(memory_bottom, memory_top) ||
	    !cdk2_coreboot_range_valid(free_memory_bottom, free_memory_top) ||
	    free_memory_bottom < memory_bottom || free_memory_top > memory_top) {
		return EFI_INVALID_PARAMETER;
	}

	if (!cdk2_coreboot_align_up8(free_memory_bottom, &cursor)) {
		return EFI_INVALID_PARAMETER;
	}

	if (cursor > free_memory_top) {
		return EFI_OUT_OF_RESOURCES;
	}

	status = cdk2_coreboot_validate_memory_ranges(coreboot);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_resolve_boot_mode(coreboot, capsule_support_enabled, &boot_mode);
	if (EFI_ERROR(status)) {
		return status;
	}

	hob_info = (EFI_HOB_HANDOFF_INFO_TABLE *)cdk2_coreboot_append_hob(
		&cursor, free_memory_top, EFI_HOB_TYPE_HANDOFF, sizeof(*hob_info));
	if (hob_info == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	hob_info->version = EFI_HOB_HANDOFF_TABLE_VERSION;
	hob_info->boot_mode = boot_mode;
	hob_info->efi_memory_bottom = memory_bottom;
	hob_info->efi_memory_top = memory_top;
	hob_info->efi_free_memory_top = free_memory_top;
	hob_info->efi_free_memory_bottom = cursor;
	tolud = cdk2_coreboot_find_tolud(coreboot);

	for (index = 0; index < coreboot->memory_range_count; index++) {
		if (!cdk2_coreboot_hob_memory_range(&coreboot->memory_ranges[index],
						    &hob_range)) {
			continue;
		}

		status = cdk2_coreboot_append_resource(coreboot, &cursor, free_memory_top,
						       &hob_range, tolud);
		if (EFI_ERROR(status)) {
			return status;
		}

		status = cdk2_coreboot_append_allocation(coreboot, &cursor, free_memory_top,
							 &hob_range);
		if (EFI_ERROR(status)) {
			return status;
		}
	}

	status = cdk2_coreboot_append_payload_resource_handoff_hob(&cursor, free_memory_top,
								   coreboot);
	if (EFI_ERROR(status)) {
		return status;
	}

	end = (EFI_HOB_GENERIC_HEADER *)cdk2_coreboot_append_hob(
		&cursor, free_memory_top, EFI_HOB_TYPE_END_OF_HOB_LIST, sizeof(*end));
	if (end == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	hob_info->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)end;
	hob_info->efi_free_memory_bottom = cursor;
	*handoff = hob_info;
	return EFI_SUCCESS;
}
