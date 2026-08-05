/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Freestanding coreboot table validation for the native cdk2 stage.
 */

#include "coreboot.h"

#define CDK2_COREBOOT_PRH_MEMORY_ATTRIBUTE_MASK                              \
	(EFI_CACHE_ATTRIBUTE_MASK | EFI_MEMORY_ACCESS_MASK | EFI_MEMORY_NV | \
	 EFI_MEMORY_MORE_RELIABLE | EFI_MEMORY_SP | EFI_MEMORY_CPU_CRYPTO |  \
	 EFI_MEMORY_HOT_PLUGGABLE | EFI_MEMORY_RUNTIME)

#define CDK2_COREBOOT_4GB 0x100000000ULL

#define CDK2_COREBOOT_PCI_MAX_BAR                  6U
#define CDK2_COREBOOT_PRH_MEMORY_POLICY_MAX_COUNT  1024U
#define CDK2_COREBOOT_PRH_PCI_ASSIGNMENT_MAX_COUNT 256U
#define CDK2_COREBOOT_PRH_MEMORY_AUTHORITATIVE_FLAGS                                  \
	(CB_PRH_MEMORY_CACHE_AUTHORITATIVE | CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE | \
	 CB_PRH_MEMORY_GCD_AUTHORITATIVE | CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE)
#define CDK2_COREBOOT_PRH_MEMORY_COVERAGE_FLAGS \
	(CDK2_COREBOOT_PRH_MEMORY_AUTHORITATIVE_FLAGS | CB_PRH_MEMORY_DELEGATED_TO_PAYLOAD)

#define CDK2_COREBOOT_MTRR_TYPE_UC                   0U
#define CDK2_COREBOOT_MTRR_TYPE_WC                   1U
#define CDK2_COREBOOT_MTRR_TYPE_WT                   4U
#define CDK2_COREBOOT_MTRR_TYPE_WP                   5U
#define CDK2_COREBOOT_MTRR_TYPE_WB                   6U
#define CDK2_COREBOOT_MTRR_TYPE_UC_MINUS             7U
#define CDK2_COREBOOT_MTRR_FIXED_ENABLE              BIT10
#define CDK2_COREBOOT_MTRR_ENABLE                    BIT11
#define CDK2_COREBOOT_MTRR_VALID                     BIT11
#define CDK2_COREBOOT_MTRR_MIN_PHYSICAL_ADDRESS_BITS 32U
#define CDK2_COREBOOT_MTRR_MAX_PHYSICAL_ADDRESS_BITS 52U
#define CDK2_COREBOOT_MTRR_DEFAULT_TYPE_VALID_MASK   0x0000000000000CFFULL

#define CDK2_COREBOOT_1MB 0x100000ULL

static UINT64 cdk2_coreboot_unpack64(const struct cbuint64 *value)
{
	return (UINT64)value->lo | ((UINT64)value->hi << 32);
}

static UINT64 cdk2_coreboot_unpack64_at(const void *base, UINTN offset)
{
	return cdk2_coreboot_unpack64(
		(const struct cbuint64 *)(const void *)((const UINT8 *)base + offset));
}

UINT16
cdk2_coreboot_checksum16(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT32 sum;
	UINTN index;

	if (buffer == NULL) {
		return 0;
	}

	bytes = (const UINT8 *)buffer;
	sum = 0;
	for (index = 0; index < length; index++) {
		sum += (index & 1) ? ((UINT32)bytes[index] << 8) : bytes[index];
		if (sum >= 0x10000U) {
			sum = (sum + (sum >> 16)) & 0xffffU;
		}
	}

	return (UINT16)(~sum & 0xffffU);
}

static UINT32 cdk2_coreboot_crc32_update(UINT32 crc, UINT8 byte)
{
	UINTN bit_index;

	crc ^= (UINT32)byte << 24;
	for (bit_index = 0; bit_index < 8; bit_index++) {
		if ((crc & BIT31) != 0) {
			crc = (crc << 1) ^ 0x04C11DB7U;
		} else {
			crc <<= 1;
		}
	}

	return crc;
}

UINT32
cdk2_coreboot_calculate_crc32(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT32 crc;
	UINTN index;

	if (buffer == NULL) {
		return 0;
	}

	bytes = (const UINT8 *)buffer;
	crc = 0;
	for (index = 0; index < length; index++) {
		crc = cdk2_coreboot_crc32_update(crc, bytes[index]);
	}

	return crc;
}

static BOOLEAN cdk2_coreboot_aligned4(UINTN value)
{
	return (value & 3U) == 0;
}

static BOOLEAN cdk2_coreboot_u32_range_within(UINT32 offset, UINT32 length, UINT32 limit,
					      UINT32 *end)
{
	if (offset > limit || length > limit - offset) {
		return FALSE;
	}

	if (end != NULL) {
		*end = offset + length;
	}

	return TRUE;
}

static BOOLEAN cdk2_coreboot_is_power_of_two64(UINT64 value)
{
	return (value != 0) && ((value & (value - 1U)) == 0);
}

static UINTN cdk2_coreboot_bit_count64(UINT64 value)
{
	UINTN count;

	count = 0;
	while (value != 0) {
		count += (UINTN)(value & 1U);
		value >>= 1;
	}

	return count;
}

static BOOLEAN cdk2_coreboot_mtrr_type_valid(UINT8 type)
{
	return (type == CDK2_COREBOOT_MTRR_TYPE_UC) || (type == CDK2_COREBOOT_MTRR_TYPE_WC) ||
	       (type == CDK2_COREBOOT_MTRR_TYPE_WT) || (type == CDK2_COREBOOT_MTRR_TYPE_WP) ||
	       (type == CDK2_COREBOOT_MTRR_TYPE_WB);
}

static BOOLEAN cdk2_coreboot_pat_type_valid(UINT8 type)
{
	return cdk2_coreboot_mtrr_type_valid(type) ||
	       (type == CDK2_COREBOOT_MTRR_TYPE_UC_MINUS);
}

static BOOLEAN cdk2_coreboot_pat_msr_valid(UINT64 pat_msr)
{
	UINTN index;
	UINT8 entry_type;

	for (index = 0; index < 8; index++) {
		entry_type = (UINT8)((pat_msr >> (index * 8U)) & 0xffU);
		if (!cdk2_coreboot_pat_type_valid(entry_type)) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOLEAN cdk2_coreboot_cache_attribute_to_mtrr_type(UINT64 attributes, UINT8 *type)
{
	if (type == NULL) {
		return FALSE;
	}

	switch (attributes & EFI_CACHE_ATTRIBUTE_MASK) {
	case EFI_MEMORY_UC:
		*type = CDK2_COREBOOT_MTRR_TYPE_UC;
		return TRUE;
	case EFI_MEMORY_WC:
		*type = CDK2_COREBOOT_MTRR_TYPE_WC;
		return TRUE;
	case EFI_MEMORY_WT:
		*type = CDK2_COREBOOT_MTRR_TYPE_WT;
		return TRUE;
	case EFI_MEMORY_WP:
		*type = CDK2_COREBOOT_MTRR_TYPE_WP;
		return TRUE;
	case EFI_MEMORY_WB:
		*type = CDK2_COREBOOT_MTRR_TYPE_WB;
		return TRUE;
	default:
		return FALSE;
	}
}

static BOOLEAN cdk2_coreboot_pat_contains_type(UINT64 pat_msr, UINT8 type)
{
	BOOLEAN found;
	UINTN index;
	UINT8 entry_type;

	found = FALSE;
	for (index = 0; index < 8; index++) {
		entry_type = (UINT8)((pat_msr >> (index * 8U)) & 0xffU);
		if (!cdk2_coreboot_pat_type_valid(entry_type)) {
			return FALSE;
		}

		if (entry_type == type) {
			found = TRUE;
		}
	}

	return found;
}

static BOOLEAN cdk2_coreboot_u64_range_end(UINT64 base, UINT64 length, UINT64 *end)
{
	if (end == NULL || length == 0 || base > MAX_UINT64 - length) {
		return FALSE;
	}

	*end = base + length;
	return TRUE;
}

static BOOLEAN cdk2_coreboot_u64_range_within(UINT64 base, UINT64 length, UINT64 container_base,
					      UINT64 container_length)
{
	UINT64 end;
	UINT64 container_end;

	if (!cdk2_coreboot_u64_range_end(base, length, &end) ||
	    !cdk2_coreboot_u64_range_end(container_base, container_length, &container_end)) {
		return FALSE;
	}

	return (base >= container_base) && (end <= container_end);
}

static BOOLEAN cdk2_coreboot_u64_ranges_overlap(UINT64 first_base, UINT64 first_length,
						UINT64 second_base, UINT64 second_length)
{
	UINT64 first_end;
	UINT64 second_end;

	if (!cdk2_coreboot_u64_range_end(first_base, first_length, &first_end) ||
	    !cdk2_coreboot_u64_range_end(second_base, second_length, &second_end)) {
		return FALSE;
	}

	return (first_base < second_end) && (second_base < first_end);
}

static BOOLEAN cdk2_coreboot_efi_memory_type_vendor_reserved(UINT32 efi_memory_type)
{
	return ((efi_memory_type >= MEMORY_TYPE_OEM_RESERVED_MIN) &&
		(efi_memory_type <= MEMORY_TYPE_OEM_RESERVED_MAX)) ||
	       ((efi_memory_type >= MEMORY_TYPE_OS_RESERVED_MIN) &&
		(efi_memory_type <= MEMORY_TYPE_OS_RESERVED_MAX));
}

static BOOLEAN cdk2_coreboot_efi_memory_type_valid(UINT32 efi_memory_type)
{
	return (efi_memory_type < efi_max_memory_type) ||
	       cdk2_coreboot_efi_memory_type_vendor_reserved(efi_memory_type);
}

static BOOLEAN cdk2_coreboot_efi_type_matches_gcd_type(UINT32 gcd_type, UINT32 efi_memory_type)
{
	switch (gcd_type) {
	case CB_PRH_GCD_MEMORY_TYPE_NON_EXISTENT:
		return efi_memory_type == efi_reserved_memory_type;

	case CB_PRH_GCD_MEMORY_TYPE_RESERVED:
		return (efi_memory_type == efi_reserved_memory_type) ||
		       (efi_memory_type == efi_unusable_memory) ||
		       (efi_memory_type == efi_acpi_reclaim_memory) ||
		       (efi_memory_type == efi_acpi_memory_nvs) || (efi_memory_type == efi_pal_code);

	case CB_PRH_GCD_MEMORY_TYPE_SYSTEM:
	case CB_PRH_GCD_MEMORY_TYPE_RELIABLE:
		if (cdk2_coreboot_efi_memory_type_vendor_reserved(efi_memory_type)) {
			return TRUE;
		}

		return (efi_memory_type == efi_loader_code) || (efi_memory_type == efi_loader_data) ||
		       (efi_memory_type == efi_boot_services_code) ||
		       (efi_memory_type == efi_boot_services_data) ||
		       (efi_memory_type == efi_runtime_services_code) ||
		       (efi_memory_type == efi_runtime_services_data) ||
		       (efi_memory_type == efi_conventional_memory) ||
		       (efi_memory_type == efi_acpi_reclaim_memory) ||
		       (efi_memory_type == efi_acpi_memory_nvs);

	case CB_PRH_GCD_MEMORY_TYPE_MMIO:
		return (efi_memory_type == efi_memory_mapped_io) ||
		       (efi_memory_type == efi_memory_mapped_io_port_space);

	case CB_PRH_GCD_MEMORY_TYPE_PERSISTENT:
		return efi_memory_type == efi_persistent_memory;

	case CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED:
		return efi_memory_type == efi_unaccepted_memory_type;

	default:
		return FALSE;
	}
}

static BOOLEAN cdk2_coreboot_memory_policy_covers_range_by_owner_flags(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *section, UINT32 required_owner_flags,
	BOOLEAN require_all_owner_flags, BOOLEAN require_gcd_type, UINT32 gcd_type, UINT64 base,
	UINT64 length)
{
	const UINT8 *section_base;
	const struct cb_prh_memory_policy_entry *entry;
	UINT64 range_end;
	UINT64 covered;
	UINT64 entry_base;
	UINT64 entry_length;
	UINT64 entry_end;
	UINTN index;

	if ((record == NULL) || (section == NULL) ||
	    ((section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0)) {
		return FALSE;
	}

	if (!cdk2_coreboot_u64_range_end(base, length, &range_end)) {
		return FALSE;
	}

	section_base = (const UINT8 *)record + section->offset;
	covered = base;
	index = 0;
	while (covered < range_end) {
		for (; index < section->entry_count; index++) {
			entry = (const struct cb_prh_memory_policy_entry
					 *)(const void *)(section_base +
							  index * section->entry_size);
			entry_base = cdk2_coreboot_unpack64_at(
				entry, OFFSET_OF(struct cb_prh_memory_policy_entry, base));
			entry_length = cdk2_coreboot_unpack64_at(
				entry, OFFSET_OF(struct cb_prh_memory_policy_entry, length));
			if (!cdk2_coreboot_u64_range_end(entry_base, entry_length, &entry_end)) {
				return FALSE;
			}

			if (entry_end <= covered) {
				continue;
			}

			if (entry_base > covered) {
				return FALSE;
			}

			if (require_all_owner_flags) {
				if ((entry->owner_flags & required_owner_flags) !=
				    required_owner_flags) {
					return FALSE;
				}
			} else if ((entry->owner_flags & required_owner_flags) == 0) {
				return FALSE;
			}

			if (require_gcd_type && (entry->gcd_type != gcd_type)) {
				return FALSE;
			}

			covered = (entry_end < range_end) ? entry_end : range_end;
			index++;
			break;
		}

		if ((index == section->entry_count) && (covered < range_end)) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOLEAN cdk2_coreboot_memory_policy_covers_range_with_any_owner(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *section, UINT32 owner_flags, UINT64 base,
	UINT64 length)
{
	return cdk2_coreboot_memory_policy_covers_range_by_owner_flags(
		record, section, owner_flags, FALSE, FALSE, 0, base, length);
}

static BOOLEAN cdk2_coreboot_memory_policy_covers_range_with_gcd_type(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *section, UINT32 required_owner_flags,
	UINT32 gcd_type, UINT64 base, UINT64 length)
{
	return cdk2_coreboot_memory_policy_covers_range_by_owner_flags(
		record, section, required_owner_flags, TRUE, TRUE, gcd_type, base, length);
}

static BOOLEAN cdk2_coreboot_u64_range_below4_gb(UINT64 base, UINT64 length)
{
	UINT64 end;

	if (length == 0) {
		return TRUE;
	}

	if (!cdk2_coreboot_u64_range_end(base, length, &end)) {
		return FALSE;
	}

	return (base < CDK2_COREBOOT_4GB) && (end <= CDK2_COREBOOT_4GB);
}

static UINT64
cdk2_coreboot_payload_resource_lifetime(const struct cb_payload_resource_handoff *record)
{
	return cdk2_coreboot_unpack64_at(record, OFFSET_OF(struct cb_payload_resource_handoff,
							   lifetime_flags));
}

static UINT64 cdk2_coreboot_payload_resource_producer_generation(
	const struct cb_payload_resource_handoff *record)
{
	return cdk2_coreboot_unpack64_at(record, OFFSET_OF(struct cb_payload_resource_handoff,
							   producer_generation));
}

static UINT32
cdk2_coreboot_payload_resource_crc32(const struct cb_payload_resource_handoff *record)
{
	const UINT8 *bytes;
	UINT32 crc;
	UINTN crc_offset;
	UINTN index;
	UINT8 byte;

	if (record == NULL) {
		return 0;
	}

	bytes = (const UINT8 *)record;
	crc = 0;
	crc_offset = OFFSET_OF(struct cb_payload_resource_handoff, crc32);
	for (index = 0; index < record->size; index++) {
		byte = ((index >= crc_offset) && (index < crc_offset + sizeof(record->crc32))) ?
			       0 :
			       bytes[index];
		crc = cdk2_coreboot_crc32_update(crc, byte);
	}

	return crc;
}

static EFI_STATUS cdk2_coreboot_validate_payload_resource_section_bounds(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *section, UINT32 section_table_end)
{
	UINT32 payload_end;
	UINT64 entry_bytes;

	if (section->header_length < CDK2_COREBOOT_PAYLOAD_RESOURCE_SECTION_MIN_SIZE ||
	    section->header_length > record->section_header_length ||
	    (section->flags & ~CB_PRH_SECTION_FLAG_VALID_MASK) != 0 ||
	    !cdk2_coreboot_aligned4(section->header_length) ||
	    !cdk2_coreboot_aligned4(section->offset) ||
	    !cdk2_coreboot_aligned4(section->length)) {
		return ((section->flags & ~CB_PRH_SECTION_FLAG_VALID_MASK) != 0) ?
			       EFI_UNSUPPORTED :
			       EFI_COMPROMISED_DATA;
	}

	if (!cdk2_coreboot_u32_range_within(section->offset, section->length, record->size,
					    &payload_end)) {
		return EFI_COMPROMISED_DATA;
	}

	if (section->length != 0 && section->offset < section_table_end) {
		return EFI_COMPROMISED_DATA;
	}

	if (section->entry_size == 0) {
		return (section->entry_count == 0) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
	}

	if (!cdk2_coreboot_aligned4(section->entry_size)) {
		return EFI_COMPROMISED_DATA;
	}

	entry_bytes = (UINT64)section->entry_size * section->entry_count;
	if (entry_bytes > section->length) {
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_validate_payload_resource_fixed_entries(
	const struct cb_payload_resource_section *section, UINT32 minimum_entry_size,
	BOOLEAN require_entries)
{
	UINT64 entry_bytes;

	if (section->entry_size < minimum_entry_size ||
	    !cdk2_coreboot_aligned4(section->entry_size)) {
		return EFI_COMPROMISED_DATA;
	}

	if (require_entries && section->entry_count == 0) {
		return EFI_COMPROMISED_DATA;
	}

	entry_bytes = (UINT64)section->entry_size * section->entry_count;
	if (entry_bytes != section->length) {
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS
cdk2_coreboot_validate_memory_policy_section(const struct cb_payload_resource_handoff *record,
					     const struct cb_payload_resource_section *section)
{
	const UINT8 *base;
	const struct cb_prh_memory_policy_entry *entry;
	UINT64 previous_end;
	UINT64 range_base;
	UINT64 range_length;
	UINT64 range_end;
	UINT64 capabilities;
	UINT64 attributes;
	UINT64 unsupported_attributes;
	UINTN index;
	EFI_STATUS status;

	status = cdk2_coreboot_validate_payload_resource_fixed_entries(
		section, sizeof(struct cb_prh_memory_policy_entry), TRUE);
	if (EFI_ERROR(status)) {
		return status;
	}

	if (section->entry_count > CDK2_COREBOOT_PRH_MEMORY_POLICY_MAX_COUNT) {
		return EFI_COMPROMISED_DATA;
	}

	base = (const UINT8 *)record + section->offset;
	previous_end = 0;
	for (index = 0; index < section->entry_count; index++) {
		entry = (const struct cb_prh_memory_policy_entry
				 *)(const void *)(base + index * section->entry_size);
		range_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_memory_policy_entry, base));
		range_length = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_memory_policy_entry, length));
		if (!cdk2_coreboot_u64_range_end(range_base, range_length, &range_end) ||
		    (index != 0 && range_base < previous_end)) {
			return EFI_COMPROMISED_DATA;
		}

		capabilities = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities));
		attributes = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_memory_policy_entry, attributes));
		unsupported_attributes = (capabilities | attributes) &
					~CDK2_COREBOOT_PRH_MEMORY_ATTRIBUTE_MASK;
		if (unsupported_attributes != 0) {
			return EFI_UNSUPPORTED;
		}

		if ((attributes & ~capabilities) != 0) {
			return EFI_COMPROMISED_DATA;
		}

		if ((entry->owner_flags & ~CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK) != 0 ||
		    entry->reserved != 0) {
			return ((entry->owner_flags & ~CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK) !=
				0) ?
				       EFI_UNSUPPORTED :
				       EFI_COMPROMISED_DATA;
		}

		if (((section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0) &&
		    ((entry->owner_flags & CDK2_COREBOOT_PRH_MEMORY_AUTHORITATIVE_FLAGS) !=
		     0)) {
			return EFI_COMPROMISED_DATA;
		}

		if ((entry->owner_flags & CB_PRH_MEMORY_GCD_AUTHORITATIVE) != 0 &&
		    entry->gcd_type > CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED) {
			return EFI_UNSUPPORTED;
		}

		if ((entry->owner_flags & CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE) != 0 &&
		    !cdk2_coreboot_efi_memory_type_valid(entry->efi_memory_type)) {
			return EFI_UNSUPPORTED;
		}

		if (((entry->owner_flags & CB_PRH_MEMORY_GCD_AUTHORITATIVE) != 0) &&
		    ((entry->owner_flags & CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE) != 0) &&
		    !cdk2_coreboot_efi_type_matches_gcd_type(entry->gcd_type,
							     entry->efi_memory_type)) {
			return EFI_COMPROMISED_DATA;
		}

		if ((entry->owner_flags & CB_PRH_MEMORY_CACHE_AUTHORITATIVE) != 0 &&
		    cdk2_coreboot_bit_count64(attributes & EFI_CACHE_ATTRIBUTE_MASK) != 1) {
			return EFI_COMPROMISED_DATA;
		}

		if ((((attributes & EFI_MEMORY_RUNTIME) != 0) ||
		     ((entry->owner_flags & CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE) != 0)) &&
		    (((range_base | range_length) & EFI_PAGE_MASK) != 0)) {
			return EFI_COMPROMISED_DATA;
		}

		previous_end = range_end;
	}

	return EFI_SUCCESS;
}

static BOOLEAN cdk2_coreboot_mtrr_address_mask(const struct cb_prh_x86_cache_state *cache_state,
					       UINT64 *address_mask)
{
	UINT32 physical_address_bits;

	if ((cache_state == NULL) || (address_mask == NULL)) {
		return FALSE;
	}

	physical_address_bits = cache_state->physical_address_bits;
	if ((physical_address_bits < CDK2_COREBOOT_MTRR_MIN_PHYSICAL_ADDRESS_BITS) ||
	    (physical_address_bits > CDK2_COREBOOT_MTRR_MAX_PHYSICAL_ADDRESS_BITS)) {
		return FALSE;
	}

	*address_mask = ((1ULL << physical_address_bits) - 1U) & ~(UINT64)EFI_PAGE_MASK;
	return TRUE;
}

static BOOLEAN cdk2_coreboot_default_mtrr_valid(UINT64 default_type_msr, UINT8 *default_type)
{
	UINT8 type;

	type = (UINT8)(default_type_msr & 0xffU);
	if (((default_type_msr & ~CDK2_COREBOOT_MTRR_DEFAULT_TYPE_VALID_MASK) != 0) ||
	    ((default_type_msr & CDK2_COREBOOT_MTRR_ENABLE) == 0) ||
	    !cdk2_coreboot_mtrr_type_valid(type)) {
		return FALSE;
	}

	if (default_type != NULL) {
		*default_type = type;
	}

	return TRUE;
}

static BOOLEAN
cdk2_coreboot_variable_mtrr_decode(const struct cb_prh_x86_variable_mtrr *variable_mtrr,
				   UINT64 mtrr_address_mask, BOOLEAN *active, UINT8 *type,
				   UINT64 *base, UINT64 *length);

static EFI_STATUS
cdk2_coreboot_validate_x86_cache_section(const struct cb_payload_resource_handoff *record,
					 const struct cb_payload_resource_section *section)
{
	const struct cb_prh_x86_cache_state *cache_state;
	const struct cb_prh_x86_variable_mtrr *variable_mtrr;
	const UINT8 *variable_base;
	UINT64 default_type_msr;
	UINT64 pat_msr;
	UINT64 variable_bytes;
	UINT64 lifetime_flags;
	UINT64 mtrr_address_mask;
	BOOLEAN active;
	UINTN index;

	if (section->length < sizeof(struct cb_prh_x86_cache_state) ||
	    section->entry_size < sizeof(struct cb_prh_x86_variable_mtrr) ||
	    !cdk2_coreboot_aligned4(section->entry_size)) {
		return EFI_COMPROMISED_DATA;
	}

	cache_state =
		(const struct cb_prh_x86_cache_state *)(const void *)((const UINT8 *)record +
								      section->offset);
	if (cache_state->variable_count != section->entry_count) {
		return EFI_COMPROMISED_DATA;
	}

	if ((cache_state->flags & ~CB_PRH_X86_CACHE_FLAG_VALID_MASK) != 0) {
		return EFI_UNSUPPORTED;
	}

	if (cache_state->reserved != 0) {
		return EFI_COMPROMISED_DATA;
	}

	lifetime_flags = cdk2_coreboot_payload_resource_lifetime(record);
	if (((cache_state->flags & CB_PRH_X86_CACHE_FLAG_S3_VALID) != 0) &&
	    ((lifetime_flags & CB_PRH_LIFETIME_S3_RESUME) == 0)) {
		return EFI_COMPROMISED_DATA;
	}

	variable_bytes = (UINT64)section->entry_size * section->entry_count;
	if (variable_bytes != section->length - sizeof(*cache_state)) {
		return EFI_COMPROMISED_DATA;
	}

	if (!cdk2_coreboot_mtrr_address_mask(cache_state, &mtrr_address_mask)) {
		return EFI_COMPROMISED_DATA;
	}

	default_type_msr = cdk2_coreboot_unpack64_at(
		cache_state, OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr));
	if (!cdk2_coreboot_default_mtrr_valid(default_type_msr, NULL)) {
		return EFI_COMPROMISED_DATA;
	}

	pat_msr = cdk2_coreboot_unpack64_at(cache_state,
					   OFFSET_OF(struct cb_prh_x86_cache_state, pat_msr));
	if (!cdk2_coreboot_pat_msr_valid(pat_msr)) {
		return EFI_COMPROMISED_DATA;
	}

	variable_base = (const UINT8 *)(cache_state + 1);
	for (index = 0; index < section->entry_count; index++) {
		variable_mtrr =
			(const struct cb_prh_x86_variable_mtrr
				 *)(const void *)(variable_base + index * section->entry_size);
		if (!cdk2_coreboot_variable_mtrr_decode(variable_mtrr, mtrr_address_mask, &active,
							NULL, NULL, NULL)) {
			return EFI_COMPROMISED_DATA;
		}
	}

	return EFI_SUCCESS;
}

static BOOLEAN
cdk2_coreboot_variable_mtrr_decode(const struct cb_prh_x86_variable_mtrr *variable_mtrr,
				   UINT64 mtrr_address_mask, BOOLEAN *active, UINT8 *type,
				   UINT64 *base, UINT64 *length)
{
	UINT64 phys_base_msr;
	UINT64 phys_mask_msr;
	UINT64 mask;
	UINT64 range_mask;
	UINT64 mtrr_base;
	UINT64 mtrr_length;
	UINT64 phys_base_valid_mask;
	UINT64 phys_mask_valid_mask;
	UINT8 mtrr_type;

	phys_base_valid_mask = mtrr_address_mask | 0xffULL;
	phys_mask_valid_mask = mtrr_address_mask | CDK2_COREBOOT_MTRR_VALID;
	phys_mask_msr = cdk2_coreboot_unpack64_at(
		variable_mtrr, OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr));
	if ((active == NULL) || (mtrr_address_mask == 0) ||
	    ((phys_mask_msr & ~phys_mask_valid_mask) != 0)) {
		return FALSE;
	}

	phys_base_msr = cdk2_coreboot_unpack64_at(
		variable_mtrr, OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_base_msr));
	mtrr_type = (UINT8)(phys_base_msr & 0xffU);
	mtrr_base = phys_base_msr & mtrr_address_mask;
	if (((phys_base_msr & ~phys_base_valid_mask) != 0) ||
	    !cdk2_coreboot_mtrr_type_valid(mtrr_type)) {
		return FALSE;
	}

	if ((phys_mask_msr & CDK2_COREBOOT_MTRR_VALID) == 0) {
		*active = FALSE;
		return TRUE;
	}

	mask = phys_mask_msr & mtrr_address_mask;
	range_mask = ~mask & mtrr_address_mask;
	if (range_mask > MAX_UINT64 - SIZE_4KB) {
		return FALSE;
	}

	mtrr_length = range_mask + SIZE_4KB;
	if (!cdk2_coreboot_is_power_of_two64(mtrr_length) ||
	    ((mtrr_base & (mtrr_length - 1U)) != 0)) {
		return FALSE;
	}

	*active = TRUE;
	if (type != NULL) {
		*type = mtrr_type;
	}

	if (base != NULL) {
		*base = mtrr_base;
	}

	if (length != NULL) {
		*length = mtrr_length;
	}

	return TRUE;
}

static BOOLEAN cdk2_coreboot_merge_variable_mtrr_types(UINT8 first, UINT8 second, UINT8 *merged)
{
	if (merged == NULL) {
		return FALSE;
	}

	if (first == second) {
		*merged = first;
		return TRUE;
	}

	if ((first == CDK2_COREBOOT_MTRR_TYPE_UC) || (second == CDK2_COREBOOT_MTRR_TYPE_UC)) {
		*merged = CDK2_COREBOOT_MTRR_TYPE_UC;
		return TRUE;
	}

	if (((first == CDK2_COREBOOT_MTRR_TYPE_WB) && (second == CDK2_COREBOOT_MTRR_TYPE_WT)) ||
	    ((first == CDK2_COREBOOT_MTRR_TYPE_WT) && (second == CDK2_COREBOOT_MTRR_TYPE_WB))) {
		*merged = CDK2_COREBOOT_MTRR_TYPE_WT;
		return TRUE;
	}

	return FALSE;
}

static BOOLEAN
cdk2_coreboot_effective_mtrr_type_at(const struct cb_prh_x86_cache_state *cache_state,
				     const struct cb_payload_resource_section *cache_section,
				     UINT64 mtrr_address_mask, UINT8 default_type, UINT64 address,
				     UINT64 limit, UINT8 *effective_type, UINT64 *next_address)
{
	const struct cb_prh_x86_variable_mtrr *variable_mtrr;
	const UINT8 *variable_base;
	UINT64 variable_base_address;
	UINT64 variable_length;
	UINT64 variable_end;
	UINT64 next;
	UINT8 current_type;
	UINT8 variable_type;
	BOOLEAN active;
	BOOLEAN matched;
	UINTN index;

	if ((cache_state == NULL) || (cache_section == NULL) || (effective_type == NULL) ||
	    (next_address == NULL) || (address >= limit)) {
		return FALSE;
	}

	current_type = default_type;
	matched = FALSE;
	next = limit;
	variable_base = (const UINT8 *)(cache_state + 1);
	for (index = 0; index < cache_section->entry_count; index++) {
		variable_mtrr = (const struct cb_prh_x86_variable_mtrr
					*)(const void *)(variable_base +
							 index * cache_section->entry_size);
		if (!cdk2_coreboot_variable_mtrr_decode(variable_mtrr, mtrr_address_mask, &active,
							&variable_type, &variable_base_address,
							&variable_length)) {
			return FALSE;
		}

		if (!active) {
			continue;
		}

		if (!cdk2_coreboot_u64_range_end(variable_base_address, variable_length,
						 &variable_end)) {
			return FALSE;
		}

		if (address < variable_base_address) {
			if (variable_base_address < next) {
				next = variable_base_address;
			}

			continue;
		}

		if (address >= variable_end) {
			continue;
		}

		if (variable_end < next) {
			next = variable_end;
		}

		if (!matched) {
			current_type = variable_type;
			matched = TRUE;
		} else if (!cdk2_coreboot_merge_variable_mtrr_types(current_type, variable_type,
								    &current_type)) {
			return FALSE;
		}
	}

	if (next <= address) {
		return FALSE;
	}

	*effective_type = current_type;
	*next_address = next;
	return TRUE;
}

static BOOLEAN cdk2_coreboot_cache_range_covered_by_mtrr(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *cache_section, UINT8 default_type, UINT8 type,
	UINT64 base, UINT64 length)
{
	const struct cb_prh_x86_cache_state *cache_state;
	UINT64 default_type_msr;
	UINT64 mtrr_address_mask;
	UINT64 range_end;
	UINT64 covered;
	UINT64 next;
	UINT8 effective_type;

	if (!cdk2_coreboot_u64_range_end(base, length, &range_end)) {
		return FALSE;
	}

	cache_state =
		(const struct cb_prh_x86_cache_state *)(const void *)((const UINT8 *)record +
								      cache_section->offset);
	if (!cdk2_coreboot_mtrr_address_mask(cache_state, &mtrr_address_mask)) {
		return FALSE;
	}

	if (range_end > mtrr_address_mask + SIZE_4KB) {
		return FALSE;
	}

	default_type_msr = cdk2_coreboot_unpack64_at(
		cache_state, OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr));
	if ((base < CDK2_COREBOOT_1MB) &&
	    (((cache_state->flags & CB_PRH_X86_CACHE_FLAG_FIXED_VALID) != 0) ||
	     ((default_type_msr & CDK2_COREBOOT_MTRR_FIXED_ENABLE) != 0))) {
		return FALSE;
	}

	covered = base;
	while (covered < range_end) {
		if (!cdk2_coreboot_effective_mtrr_type_at(cache_state, cache_section,
							  mtrr_address_mask, default_type, covered,
							  range_end, &effective_type, &next)) {
			return FALSE;
		}

		if (effective_type != type) {
			return FALSE;
		}

		covered = next;
	}

	return TRUE;
}

static EFI_STATUS cdk2_coreboot_validate_memory_policy_against_cache_state(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *memory_section,
	const struct cb_payload_resource_section *cache_section)
{
	const UINT8 *section_base;
	const struct cb_prh_memory_policy_entry *entry;
	const struct cb_prh_x86_cache_state *cache_state;
	UINT64 attributes;
	UINT64 base;
	UINT64 length;
	UINT64 default_type_msr;
	UINT64 pat_msr;
	UINT8 default_type;
	UINT8 type;
	UINTN index;

	cache_state =
		(const struct cb_prh_x86_cache_state *)(const void *)((const UINT8 *)record +
								      cache_section->offset);
	default_type_msr = cdk2_coreboot_unpack64_at(
		cache_state, OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr));
	if (!cdk2_coreboot_default_mtrr_valid(default_type_msr, &default_type)) {
		return EFI_COMPROMISED_DATA;
	}

	pat_msr = cdk2_coreboot_unpack64_at(cache_state,
					   OFFSET_OF(struct cb_prh_x86_cache_state, pat_msr));
	section_base = (const UINT8 *)record + memory_section->offset;
	for (index = 0; index < memory_section->entry_count; index++) {
		entry = (const struct cb_prh_memory_policy_entry
				 *)(const void *)(section_base +
						  index * memory_section->entry_size);
		if ((entry->owner_flags & CB_PRH_MEMORY_CACHE_AUTHORITATIVE) == 0) {
			continue;
		}

		attributes = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_memory_policy_entry, attributes));
		if (!cdk2_coreboot_cache_attribute_to_mtrr_type(attributes, &type)) {
			return EFI_UNSUPPORTED;
		}

		if (!cdk2_coreboot_pat_contains_type(pat_msr, type)) {
			return EFI_COMPROMISED_DATA;
		}

		base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_memory_policy_entry, base));
		length = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_memory_policy_entry, length));
		if (!cdk2_coreboot_cache_range_covered_by_mtrr(
			    record, cache_section, default_type, type, base, length)) {
			return EFI_COMPROMISED_DATA;
		}
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_validate_pci_root_bridges_section(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *section)
{
	const UINT8 *base;
	const struct cb_prh_pci_root_bridge_entry *entry;
	const struct cb_prh_pci_root_bridge_entry *other_entry;
	UINT64 window_base;
	UINT64 window_length;
	UINT64 window_end;
	UINTN index;
	UINTN other_index;
	EFI_STATUS status;

	status = cdk2_coreboot_validate_payload_resource_fixed_entries(
		section, sizeof(struct cb_prh_pci_root_bridge_entry), TRUE);
	if (EFI_ERROR(status)) {
		return status;
	}

	base = (const UINT8 *)record + section->offset;
	for (index = 0; index < section->entry_count; index++) {
		entry = (const struct cb_prh_pci_root_bridge_entry
				 *)(const void *)(base + index * section->entry_size);
		if (entry->bus_start > entry->bus_end || entry->flags != 0) {
			return (entry->flags != 0) ? EFI_UNSUPPORTED : EFI_COMPROMISED_DATA;
		}

		for (other_index = 0; other_index < index; other_index++) {
			other_entry =
				(const struct cb_prh_pci_root_bridge_entry
					 *)(const void *)(base +
							  other_index * section->entry_size);
			if ((entry->segment == other_entry->segment) &&
			    (entry->bus_start <= other_entry->bus_end) &&
			    (other_entry->bus_start <= entry->bus_end)) {
				return EFI_COMPROMISED_DATA;
			}
		}

		window_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, io_base));
		window_length = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, io_length));
		if (window_length != 0 &&
		    !cdk2_coreboot_u64_range_end(window_base, window_length, &window_end)) {
			return EFI_COMPROMISED_DATA;
		}

		window_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_base));
		window_length = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_length));
		if (!cdk2_coreboot_u64_range_below4_gb(window_base, window_length)) {
			return EFI_COMPROMISED_DATA;
		}

		window_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem64_base));
		window_length = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem64_length));
		if (window_length != 0 &&
		    !cdk2_coreboot_u64_range_end(window_base, window_length, &window_end)) {
			return EFI_COMPROMISED_DATA;
		}

		window_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem32_base));
		window_length = cdk2_coreboot_unpack64_at(
			entry,
			OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem32_length));
		if (!cdk2_coreboot_u64_range_below4_gb(window_base, window_length)) {
			return EFI_COMPROMISED_DATA;
		}

		window_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem64_base));
		window_length = cdk2_coreboot_unpack64_at(
			entry,
			OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem64_length));
		if (window_length != 0 &&
		    !cdk2_coreboot_u64_range_end(window_base, window_length, &window_end)) {
			return EFI_COMPROMISED_DATA;
		}
	}

	return EFI_SUCCESS;
}

static BOOLEAN cdk2_coreboot_pci_resource_mmio32(UINT8 resource_type)
{
	return (resource_type == CB_PRH_PCI_RESOURCE_MMIO32) ||
	       (resource_type == CB_PRH_PCI_RESOURCE_PREFETCH_MMIO32);
}

static BOOLEAN cdk2_coreboot_pci_resource_mmio64(UINT8 resource_type)
{
	return (resource_type == CB_PRH_PCI_RESOURCE_MMIO64) ||
	       (resource_type == CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64);
}

static BOOLEAN cdk2_coreboot_pci_resource_memory(UINT8 resource_type)
{
	return resource_type != CB_PRH_PCI_RESOURCE_IO;
}

static EFI_STATUS cdk2_coreboot_validate_pci_assignments_section(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *section)
{
	const UINT8 *base;
	const struct cb_prh_pci_assignment_entry *entry;
	const struct cb_prh_pci_assignment_entry *other_entry;
	UINT64 resource_base;
	UINT64 resource_length;
	UINT64 resource_end;
	UINT64 resource_attributes;
	UINT64 other_resource_base;
	UINT64 other_resource_length;
	UINTN index;
	UINTN other_index;
	EFI_STATUS status;

	status = cdk2_coreboot_validate_payload_resource_fixed_entries(
		section, sizeof(struct cb_prh_pci_assignment_entry), TRUE);
	if (EFI_ERROR(status)) {
		return status;
	}

	if (section->entry_count > CDK2_COREBOOT_PRH_PCI_ASSIGNMENT_MAX_COUNT) {
		return EFI_COMPROMISED_DATA;
	}

	base = (const UINT8 *)record + section->offset;
	for (index = 0; index < section->entry_count; index++) {
		entry = (const struct cb_prh_pci_assignment_entry
				 *)(const void *)(base + index * section->entry_size);
		if (entry->device > 31 || entry->function > 7 ||
		    entry->bar >= CDK2_COREBOOT_PCI_MAX_BAR ||
		    entry->resource_type < CB_PRH_PCI_RESOURCE_IO ||
		    entry->resource_type > CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64) {
			return EFI_COMPROMISED_DATA;
		}

		if (entry->flags != 0) {
			return EFI_UNSUPPORTED;
		}

		if (cdk2_coreboot_pci_resource_mmio64(entry->resource_type) &&
		    (entry->bar >= CDK2_COREBOOT_PCI_MAX_BAR - 1U)) {
			return EFI_COMPROMISED_DATA;
		}

		for (other_index = 0; other_index < index; other_index++) {
			UINT8 entry_bar_end;
			UINT8 other_bar_end;

			other_entry =
				(const struct cb_prh_pci_assignment_entry
					 *)(const void *)(base +
							  other_index * section->entry_size);
			if ((entry->segment == other_entry->segment) &&
			    (entry->bus == other_entry->bus) &&
			    (entry->device == other_entry->device) &&
			    (entry->function == other_entry->function)) {
				entry_bar_end = entry->bar;
				if (cdk2_coreboot_pci_resource_mmio64(entry->resource_type)) {
					entry_bar_end++;
				}

				other_bar_end = other_entry->bar;
				if (cdk2_coreboot_pci_resource_mmio64(
					    other_entry->resource_type)) {
					other_bar_end++;
				}

				if ((entry->bar <= other_bar_end) &&
				    (other_entry->bar <= entry_bar_end)) {
					return EFI_COMPROMISED_DATA;
				}
			}
		}

		resource_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_assignment_entry, base));
		resource_length = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_assignment_entry, length));
		if (!cdk2_coreboot_u64_range_end(resource_base, resource_length, &resource_end)) {
			return EFI_COMPROMISED_DATA;
		}

		if (resource_base == 0) {
			return EFI_COMPROMISED_DATA;
		}

		if (!cdk2_coreboot_is_power_of_two64(resource_length) ||
		    ((resource_base & (resource_length - 1U)) != 0)) {
			return EFI_COMPROMISED_DATA;
		}

		for (other_index = 0; other_index < index; other_index++) {
			other_entry =
				(const struct cb_prh_pci_assignment_entry
					 *)(const void *)(base +
							  other_index * section->entry_size);
			if (cdk2_coreboot_pci_resource_memory(entry->resource_type) !=
			    cdk2_coreboot_pci_resource_memory(other_entry->resource_type)) {
				continue;
			}

			other_resource_base = cdk2_coreboot_unpack64_at(
				other_entry,
				OFFSET_OF(struct cb_prh_pci_assignment_entry, base));
			other_resource_length = cdk2_coreboot_unpack64_at(
				other_entry,
				OFFSET_OF(struct cb_prh_pci_assignment_entry, length));
			if (cdk2_coreboot_u64_ranges_overlap(resource_base, resource_length,
							     other_resource_base,
							     other_resource_length)) {
				return EFI_COMPROMISED_DATA;
			}
		}

		if (cdk2_coreboot_pci_resource_mmio32(entry->resource_type) &&
		    !cdk2_coreboot_u64_range_below4_gb(resource_base, resource_length)) {
			return EFI_COMPROMISED_DATA;
		}

		resource_attributes = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_pci_assignment_entry, attributes));
		if (cdk2_coreboot_pci_resource_memory(entry->resource_type)) {
			if ((resource_attributes & ~CDK2_COREBOOT_PRH_MEMORY_ATTRIBUTE_MASK) !=
			    0) {
				return EFI_UNSUPPORTED;
			}
		} else if (resource_attributes != 0) {
			return EFI_COMPROMISED_DATA;
		}
	}

	return EFI_SUCCESS;
}

static BOOLEAN cdk2_coreboot_pixel_mask_valid(UINT8 position, UINT8 size, UINT8 bits_per_pixel,
					      UINT64 *mask)
{
	UINT64 local_mask;

	if (mask == NULL || bits_per_pixel == 0 || bits_per_pixel > 32) {
		return FALSE;
	}

	if (size == 0) {
		if (position != 0) {
			return FALSE;
		}

		*mask = 0;
		return TRUE;
	}

	if ((position >= bits_per_pixel) || (size > bits_per_pixel) ||
	    (size > bits_per_pixel - position)) {
		return FALSE;
	}

	if (size == 64) {
		local_mask = MAX_UINT64;
	} else {
		local_mask = (1ULL << size) - 1U;
	}

	*mask = local_mask << position;
	return TRUE;
}

static EFI_STATUS
cdk2_coreboot_validate_framebuffer_section(const struct cb_payload_resource_handoff *record,
					   const struct cb_payload_resource_section *section)
{
	const UINT8 *base;
	const struct cb_prh_framebuffer_entry *entry;
	UINT64 framebuffer_base;
	UINT64 framebuffer_size;
	UINT64 framebuffer_end;
	UINT64 minimum_line_bits;
	UINT64 minimum_line_bytes;
	UINT64 minimum_size;
	UINT64 red_mask;
	UINT64 green_mask;
	UINT64 blue_mask;
	UINT64 reserved_mask;
	UINTN index;
	EFI_STATUS status;

	status = cdk2_coreboot_validate_payload_resource_fixed_entries(
		section, CDK2_COREBOOT_PRH_FRAMEBUFFER_MIN_SIZE, TRUE);
	if (EFI_ERROR(status)) {
		return status;
	}

	base = (const UINT8 *)record + section->offset;
	for (index = 0; index < section->entry_count; index++) {
		entry = (const struct cb_prh_framebuffer_entry
				 *)(const void *)(base + index * section->entry_size);
		if ((entry->owner_flags & ~CB_PRH_FRAMEBUFFER_OWNER_FLAG_VALID_MASK) != 0) {
			return EFI_UNSUPPORTED;
		}

		if ((section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0 &&
		    (entry->owner_flags & CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE) == 0) {
			return EFI_COMPROMISED_DATA;
		}

		if (entry->reserved[0] != 0 || entry->reserved[1] != 0 ||
		    entry->reserved[2] != 0 || entry->bits_per_pixel == 0 ||
		    entry->bits_per_pixel > 32 || entry->x_resolution == 0 ||
		    entry->y_resolution == 0 || entry->bytes_per_line == 0) {
			return EFI_COMPROMISED_DATA;
		}

		minimum_line_bits = (UINT64)entry->x_resolution * entry->bits_per_pixel;
		minimum_line_bytes = (minimum_line_bits + 7U) / 8U;
		minimum_size = (UINT64)entry->bytes_per_line * entry->y_resolution;
		if (minimum_line_bytes > entry->bytes_per_line) {
			return EFI_COMPROMISED_DATA;
		}

		if (!cdk2_coreboot_pixel_mask_valid(entry->red_mask_pos, entry->red_mask_size,
						    entry->bits_per_pixel, &red_mask) ||
		    !cdk2_coreboot_pixel_mask_valid(entry->green_mask_pos,
						    entry->green_mask_size,
						    entry->bits_per_pixel, &green_mask) ||
		    !cdk2_coreboot_pixel_mask_valid(entry->blue_mask_pos, entry->blue_mask_size,
						    entry->bits_per_pixel, &blue_mask) ||
		    !cdk2_coreboot_pixel_mask_valid(entry->reserved_mask_pos,
						    entry->reserved_mask_size,
						    entry->bits_per_pixel, &reserved_mask)) {
			return EFI_COMPROMISED_DATA;
		}

		if (((red_mask & green_mask) != 0) || ((red_mask & blue_mask) != 0) ||
		    ((red_mask & reserved_mask) != 0) || ((green_mask & blue_mask) != 0) ||
		    ((green_mask & reserved_mask) != 0) || ((blue_mask & reserved_mask) != 0)) {
			return EFI_COMPROMISED_DATA;
		}

		framebuffer_base = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_framebuffer_entry, physical_address));
		framebuffer_size = cdk2_coreboot_unpack64_at(
			entry, OFFSET_OF(struct cb_prh_framebuffer_entry, size));
		if (!cdk2_coreboot_u64_range_end(framebuffer_base, framebuffer_size,
						 &framebuffer_end) ||
		    framebuffer_size < minimum_size) {
			return EFI_COMPROMISED_DATA;
		}
	}

	return EFI_SUCCESS;
}

static BOOLEAN cdk2_coreboot_pci_assignment_fits_bridge_window(
	const struct cb_prh_pci_root_bridge_entry *bridge, UINT8 resource_type,
	UINT64 resource_base, UINT64 resource_length)
{
	UINT64 window_base;
	UINT64 window_length;

	switch (resource_type) {
	case CB_PRH_PCI_RESOURCE_IO:
		window_base = cdk2_coreboot_unpack64_at(
			bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, io_base));
		window_length = cdk2_coreboot_unpack64_at(
			bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, io_length));
		break;

	case CB_PRH_PCI_RESOURCE_MMIO32:
		window_base = cdk2_coreboot_unpack64_at(
			bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_base));
		window_length = cdk2_coreboot_unpack64_at(
			bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_length));
		break;

	case CB_PRH_PCI_RESOURCE_MMIO64:
		window_base = cdk2_coreboot_unpack64_at(
			bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem64_base));
		window_length = cdk2_coreboot_unpack64_at(
			bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem64_length));
		break;

	case CB_PRH_PCI_RESOURCE_PREFETCH_MMIO32:
		window_base = cdk2_coreboot_unpack64_at(
			bridge,
			OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem32_base));
		window_length = cdk2_coreboot_unpack64_at(
			bridge,
			OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem32_length));
		break;

	case CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64:
		window_base = cdk2_coreboot_unpack64_at(
			bridge,
			OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem64_base));
		window_length = cdk2_coreboot_unpack64_at(
			bridge,
			OFFSET_OF(struct cb_prh_pci_root_bridge_entry, pref_mem64_length));
		break;

	default:
		return FALSE;
	}

	return cdk2_coreboot_u64_range_within(resource_base, resource_length, window_base,
					      window_length);
}

static BOOLEAN cdk2_coreboot_pci_assignment_has_owning_bridge(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *root_bridge_section,
	const struct cb_prh_pci_assignment_entry *assignment)
{
	const UINT8 *base;
	const struct cb_prh_pci_root_bridge_entry *bridge;
	UINT64 resource_base;
	UINT64 resource_length;
	UINTN index;

	resource_base = cdk2_coreboot_unpack64_at(
		assignment, OFFSET_OF(struct cb_prh_pci_assignment_entry, base));
	resource_length = cdk2_coreboot_unpack64_at(
		assignment, OFFSET_OF(struct cb_prh_pci_assignment_entry, length));

	base = (const UINT8 *)record + root_bridge_section->offset;
	for (index = 0; index < root_bridge_section->entry_count; index++) {
		bridge =
			(const struct cb_prh_pci_root_bridge_entry
				 *)(const void *)(base + index * root_bridge_section->entry_size);
		if ((assignment->segment == bridge->segment) &&
		    (assignment->bus >= bridge->bus_start) &&
		    (assignment->bus <= bridge->bus_end) &&
		    cdk2_coreboot_pci_assignment_fits_bridge_window(
			    bridge, assignment->resource_type, resource_base, resource_length)) {
			return TRUE;
		}
	}

	return FALSE;
}

static EFI_STATUS cdk2_coreboot_validate_pci_assignments_against_root_bridges(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *root_bridge_section,
	const struct cb_payload_resource_section *assignment_section)
{
	const UINT8 *base;
	const struct cb_prh_pci_assignment_entry *assignment;
	UINTN index;

	if ((assignment_section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0) {
		return EFI_SUCCESS;
	}

	if ((root_bridge_section == NULL) ||
	    ((root_bridge_section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0)) {
		return EFI_UNSUPPORTED;
	}

	base = (const UINT8 *)record + assignment_section->offset;
	for (index = 0; index < assignment_section->entry_count; index++) {
		assignment =
			(const struct cb_prh_pci_assignment_entry
				 *)(const void *)(base + index * assignment_section->entry_size);
		if (!cdk2_coreboot_pci_assignment_has_owning_bridge(record, root_bridge_section,
								    assignment)) {
			return EFI_COMPROMISED_DATA;
		}
	}

	return EFI_SUCCESS;
}

static BOOLEAN cdk2_coreboot_pci_assignment_covers_range(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *assignment_section, UINT64 base, UINT64 length)
{
	const UINT8 *section_base;
	const struct cb_prh_pci_assignment_entry *assignment;
	UINT64 assignment_base;
	UINT64 assignment_length;
	UINTN index;

	if ((record == NULL) || (assignment_section == NULL) ||
	    ((assignment_section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0)) {
		return FALSE;
	}

	section_base = (const UINT8 *)record + assignment_section->offset;
	for (index = 0; index < assignment_section->entry_count; index++) {
		assignment = (const struct cb_prh_pci_assignment_entry
				      *)(const void *)(section_base +
						       index * assignment_section->entry_size);
		if (!cdk2_coreboot_pci_resource_memory(assignment->resource_type)) {
			continue;
		}

		assignment_base = cdk2_coreboot_unpack64_at(
			assignment, OFFSET_OF(struct cb_prh_pci_assignment_entry, base));
		assignment_length = cdk2_coreboot_unpack64_at(
			assignment, OFFSET_OF(struct cb_prh_pci_assignment_entry, length));
		if (cdk2_coreboot_u64_range_within(base, length, assignment_base,
						   assignment_length)) {
			return TRUE;
		}
	}

	return FALSE;
}

static EFI_STATUS cdk2_coreboot_validate_framebuffer_ownership(
	const struct cb_payload_resource_handoff *record,
	const struct cb_payload_resource_section *framebuffer_section,
	const struct cb_payload_resource_section *memory_section,
	const struct cb_payload_resource_section *pci_assignment_section)
{
	const UINT8 *section_base;
	const struct cb_prh_framebuffer_entry *framebuffer;
	UINT64 framebuffer_base;
	UINT64 framebuffer_size;
	UINTN index;

	if (framebuffer_section == NULL) {
		return EFI_SUCCESS;
	}

	section_base = (const UINT8 *)record + framebuffer_section->offset;
	for (index = 0; index < framebuffer_section->entry_count; index++) {
		framebuffer = (const struct cb_prh_framebuffer_entry
				       *)(const void *)(section_base +
							index * framebuffer_section->entry_size);
		if ((framebuffer->owner_flags & CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE) ==
		    0) {
			continue;
		}

		framebuffer_base = cdk2_coreboot_unpack64_at(
			framebuffer,
			OFFSET_OF(struct cb_prh_framebuffer_entry, physical_address));
		framebuffer_size = cdk2_coreboot_unpack64_at(
			framebuffer, OFFSET_OF(struct cb_prh_framebuffer_entry, size));
		if (!cdk2_coreboot_memory_policy_covers_range_with_gcd_type(
			    record, memory_section,
			    CB_PRH_MEMORY_CACHE_AUTHORITATIVE | CB_PRH_MEMORY_GCD_AUTHORITATIVE,
			    CB_PRH_GCD_MEMORY_TYPE_MMIO, framebuffer_base, framebuffer_size) ||
		    !cdk2_coreboot_pci_assignment_covers_range(
			    record, pci_assignment_section, framebuffer_base, framebuffer_size)) {
			return EFI_UNSUPPORTED;
		}
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_validate_payload_resource_cross_section_rules(
	const struct cb_payload_resource_handoff *record,
	const struct cdk2_coreboot_handoff *handoff)
{
	const struct cb_payload_resource_section *section;
	const struct cb_payload_resource_section *memory_policy_section;
	const struct cb_payload_resource_section *x86_cache_section;
	const struct cb_payload_resource_section *pci_root_bridge_section;
	const struct cb_payload_resource_section *pci_assignment_section;
	const struct cb_payload_resource_section *framebuffer_section;
	const struct cb_prh_memory_policy_entry *memory_entry;
	const struct cb_prh_x86_cache_state *cache_state;
	const UINT8 *section_base;
	UINT64 lifetime_flags;
	BOOLEAN authoritative_section;
	BOOLEAN memory_ownership_policy;
	BOOLEAN cache_authoritative_memory;
	BOOLEAN protection_authoritative_memory;
	BOOLEAN pci_assignment_authoritative;
	UINTN index;
	UINTN entry_index;
	EFI_STATUS status;

	lifetime_flags = cdk2_coreboot_payload_resource_lifetime(record);
	if ((lifetime_flags & ~CB_PRH_LIFETIME_VALID_MASK) != 0) {
		return EFI_UNSUPPORTED;
	}

	memory_policy_section = NULL;
	x86_cache_section = NULL;
	pci_root_bridge_section = NULL;
	pci_assignment_section = NULL;
	framebuffer_section = NULL;
	authoritative_section = FALSE;
	memory_ownership_policy = FALSE;
	cache_authoritative_memory = FALSE;
	protection_authoritative_memory = FALSE;
	pci_assignment_authoritative = FALSE;
	for (index = 0; index < record->section_count; index++) {
		section = (const struct cb_payload_resource_section
				   *)(const void *)((const UINT8 *)record +
						    record->header_length +
						    index * record->section_header_length);
		if ((section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0) {
			authoritative_section = TRUE;
		}

		if (section->type == CB_PRH_SECTION_MEMORY_POLICY) {
			memory_policy_section = section;
			section_base = (const UINT8 *)record + section->offset;
			for (entry_index = 0; entry_index < section->entry_count; entry_index++) {
				memory_entry =
					(const struct cb_prh_memory_policy_entry
						 *)(const void *)(section_base +
								  entry_index *
									  section->entry_size);
				if ((memory_entry->owner_flags &
				     CDK2_COREBOOT_PRH_MEMORY_COVERAGE_FLAGS) != 0) {
					memory_ownership_policy = TRUE;
				}

				if ((memory_entry->owner_flags &
				     CB_PRH_MEMORY_CACHE_AUTHORITATIVE) != 0) {
					cache_authoritative_memory = TRUE;
				}

				if ((memory_entry->owner_flags &
				     CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE) != 0) {
					protection_authoritative_memory = TRUE;
				}
			}
		} else if (section->type == CB_PRH_SECTION_X86_CACHE_STATE) {
			x86_cache_section = section;
		} else if (section->type == CB_PRH_SECTION_PCI_ROOT_BRIDGES) {
			pci_root_bridge_section = section;
		} else if (section->type == CB_PRH_SECTION_PCI_ASSIGNMENTS) {
			pci_assignment_section = section;
			if ((section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0) {
				pci_assignment_authoritative = TRUE;
			}
		} else if (section->type == CB_PRH_SECTION_FRAMEBUFFER) {
			framebuffer_section = section;
		}
	}

	if (authoritative_section &&
	    (((lifetime_flags & CB_PRH_LIFETIME_COLD_BOOT) == 0) ||
	     ((lifetime_flags & CB_PRH_LIFETIME_VALID_UNTIL_MASK) == 0))) {
		return EFI_COMPROMISED_DATA;
	}

	if (((lifetime_flags & CB_PRH_LIFETIME_S3_RESUME) != 0) &&
	    cdk2_coreboot_payload_resource_producer_generation(record) == 0) {
		return EFI_COMPROMISED_DATA;
	}

	if (cache_authoritative_memory) {
		if (x86_cache_section == NULL ||
		    (x86_cache_section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0) {
			return EFI_UNSUPPORTED;
		}

		cache_state = (const struct cb_prh_x86_cache_state
				      *)(const void *)((const UINT8 *)record +
						       x86_cache_section->offset);
		if ((cache_state->flags & CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC) == 0) {
			return EFI_UNSUPPORTED;
		}

		if (((lifetime_flags & CB_PRH_LIFETIME_S3_RESUME) != 0) &&
		    ((cache_state->flags & CB_PRH_X86_CACHE_FLAG_S3_VALID) == 0)) {
			return EFI_UNSUPPORTED;
		}

		status = cdk2_coreboot_validate_memory_policy_against_cache_state(
			record, memory_policy_section, x86_cache_section);
		if (EFI_ERROR(status)) {
			return status;
		}
	}

	if (memory_ownership_policy && (handoff != NULL) && (handoff->memory_range_count != 0)) {
		for (index = 0; index < handoff->memory_range_count; index++) {
			if (!cdk2_coreboot_memory_policy_covers_range_with_any_owner(
				    record, memory_policy_section,
				    CDK2_COREBOOT_PRH_MEMORY_COVERAGE_FLAGS,
				    handoff->memory_ranges[index].base,
				    handoff->memory_ranges[index].size)) {
				return EFI_COMPROMISED_DATA;
			}
		}
	}

	if ((lifetime_flags & CB_PRH_LIFETIME_S3_RESUME) != 0) {
		return EFI_UNSUPPORTED;
	}

	if (protection_authoritative_memory) {
		return EFI_UNSUPPORTED;
	}

	if (pci_assignment_authoritative) {
		status = cdk2_coreboot_validate_pci_assignments_against_root_bridges(
			record, pci_root_bridge_section, pci_assignment_section);
		if (EFI_ERROR(status)) {
			return status;
		}
	}

	status = cdk2_coreboot_validate_framebuffer_ownership(
		record, framebuffer_section, memory_policy_section, pci_assignment_section);
	if (EFI_ERROR(status)) {
		return status;
	}

	return EFI_SUCCESS;
}

static BOOLEAN cdk2_coreboot_payload_resource_section_type_known(UINT16 type)
{
	switch (type) {
	case CB_PRH_SECTION_MEMORY_POLICY:
	case CB_PRH_SECTION_X86_CACHE_STATE:
	case CB_PRH_SECTION_PCI_ROOT_BRIDGES:
	case CB_PRH_SECTION_PCI_ASSIGNMENTS:
	case CB_PRH_SECTION_BOOT_INTENT:
	case CB_PRH_SECTION_RUNTIME_POLICY:
	case CB_PRH_SECTION_FRAMEBUFFER:
		return TRUE;

	default:
		return FALSE;
	}
}

static EFI_STATUS cdk2_coreboot_validate_payload_resource_handoff(
	const struct cb_payload_resource_handoff *record,
	const struct cdk2_coreboot_handoff *handoff)
{
	const struct cb_payload_resource_section *section;
	const struct cb_payload_resource_section *other_section;
	UINT64 section_bytes;
	UINT32 section_table_end;
	UINTN index;
	UINTN other_index;
	EFI_STATUS status;

	if (record->tag != CB_TAG_PAYLOAD_RESOURCE_HANDOFF ||
	    record->size < CDK2_COREBOOT_PAYLOAD_RESOURCE_HANDOFF_MIN_SIZE ||
	    !cdk2_coreboot_aligned4(record->size) ||
	    record->header_length < CDK2_COREBOOT_PAYLOAD_RESOURCE_HANDOFF_MIN_SIZE ||
	    record->header_length > record->size ||
	    !cdk2_coreboot_aligned4(record->header_length) ||
	    record->section_header_length < CDK2_COREBOOT_PAYLOAD_RESOURCE_SECTION_MIN_SIZE ||
	    !cdk2_coreboot_aligned4(record->section_header_length) ||
	    record->section_count > CDK2_COREBOOT_PAYLOAD_RESOURCE_MAX_SECTIONS) {
		return EFI_COMPROMISED_DATA;
	}

	if (record->revision != CB_PAYLOAD_RESOURCE_HANDOFF_REVISION) {
		return EFI_UNSUPPORTED;
	}

	if (record->flags != 0) {
		return EFI_UNSUPPORTED;
	}

	if ((cdk2_coreboot_payload_resource_lifetime(record) & ~CB_PRH_LIFETIME_VALID_MASK) !=
	    0) {
		return EFI_UNSUPPORTED;
	}

	section_bytes = (UINT64)record->section_header_length * record->section_count;
	if (section_bytes > MAX_UINT32 ||
	    !cdk2_coreboot_u32_range_within(record->header_length, (UINT32)section_bytes,
					    record->size, &section_table_end)) {
		return EFI_COMPROMISED_DATA;
	}

	if (cdk2_coreboot_payload_resource_crc32(record) != record->crc32) {
		return EFI_CRC_ERROR;
	}

	for (index = 0; index < record->section_count; index++) {
		section = (const struct cb_payload_resource_section
				   *)(const void *)((const UINT8 *)record +
						    record->header_length +
						    index * record->section_header_length);
		status = cdk2_coreboot_validate_payload_resource_section_bounds(
			record, section, section_table_end);
		if (EFI_ERROR(status)) {
			return status;
		}

		for (other_index = 0; other_index < index; other_index++) {
			other_section =
				(const struct cb_payload_resource_section
					 *)(const void *)((const UINT8 *)record +
							  record->header_length +
							  other_index *
								  record->section_header_length);
			if ((section->type == other_section->type) &&
			    cdk2_coreboot_payload_resource_section_type_known(section->type)) {
				return EFI_COMPROMISED_DATA;
			}

			if ((section->length != 0) && (other_section->length != 0) &&
			    ((section->offset < other_section->offset + other_section->length) &&
			     (other_section->offset < section->offset + section->length))) {
				return EFI_COMPROMISED_DATA;
			}
		}

		switch (section->type) {
		case CB_PRH_SECTION_MEMORY_POLICY:
			status = cdk2_coreboot_validate_memory_policy_section(record, section);
			break;

		case CB_PRH_SECTION_X86_CACHE_STATE:
			status = cdk2_coreboot_validate_x86_cache_section(record, section);
			break;

		case CB_PRH_SECTION_PCI_ROOT_BRIDGES:
			status = cdk2_coreboot_validate_pci_root_bridges_section(record,
										 section);
			break;

		case CB_PRH_SECTION_PCI_ASSIGNMENTS:
			status =
				cdk2_coreboot_validate_pci_assignments_section(record, section);
			break;

		case CB_PRH_SECTION_FRAMEBUFFER:
			status = cdk2_coreboot_validate_framebuffer_section(record, section);
			break;

		case CB_PRH_SECTION_BOOT_INTENT:
		case CB_PRH_SECTION_RUNTIME_POLICY:
			/* These sections are reserved until their semantic contracts exist. */
			status = EFI_UNSUPPORTED;
			break;

		default:
			status = ((section->flags & CB_PRH_SECTION_FLAG_MANDATORY) != 0) ?
					 EFI_UNSUPPORTED :
					 EFI_SUCCESS;
			break;
		}

		if (EFI_ERROR(status)) {
			return status;
		}
	}

	return cdk2_coreboot_validate_payload_resource_cross_section_rules(record, handoff);
}

static EFI_STATUS cdk2_coreboot_parse_one_table(const void *table, UINTN table_size,
						struct cdk2_coreboot_handoff *handoff)
{
	const struct cb_header *header;
	const UINT8 *record_bytes;
	const struct cb_record *record;
	const struct cb_memory *memory;
	const struct cb_memory_range *range;
	const struct cb_forward *forward;
	UINTN header_bytes;
	UINTN records_remaining;
	UINTN record_index;
	UINTN range_count;
	UINTN range_index;
	UINT64 base;
	UINT64 size;
	UINT64 end;

	if (table == NULL || handoff == NULL || table_size < sizeof(struct cb_header)) {
		return EFI_INVALID_PARAMETER;
	}

	header = (const struct cb_header *)table;
	header_bytes = header->header_bytes;
	if (header->signature != CB_HEADER_SIGNATURE ||
	    header_bytes < sizeof(struct cb_header) || header_bytes > table_size ||
	    header->table_bytes == 0 || header->table_bytes > CDK2_COREBOOT_MAX_TABLE_BYTES ||
	    header->table_bytes > table_size - header_bytes || header->table_entries == 0 ||
	    header->table_entries > CDK2_COREBOOT_MAX_RECORDS) {
		return EFI_COMPROMISED_DATA;
	}

	if (cdk2_coreboot_checksum16(header, header_bytes) != 0 ||
	    cdk2_coreboot_checksum16((const UINT8 *)header + header_bytes,
				     header->table_bytes) != (UINT16)header->table_checksum) {
		return EFI_COMPROMISED_DATA;
	}

	*handoff = (struct cdk2_coreboot_handoff){0};
	handoff->header = header;
	handoff->table_size = header_bytes + header->table_bytes;
	handoff->payload_resource_handoff_status = EFI_NOT_FOUND;

	record_bytes = (const UINT8 *)header + header_bytes;
	records_remaining = header->table_bytes;
	record_index = 0;
	while (record_index < header->table_entries) {
		if (records_remaining < sizeof(struct cb_record)) {
			return EFI_COMPROMISED_DATA;
		}

		record = (const struct cb_record *)(record_bytes +
						    (header->table_bytes - records_remaining));
		if (record->size < sizeof(struct cb_record) ||
		    record->size > records_remaining) {
			return EFI_COMPROMISED_DATA;
		}

		handoff->record_count++;
		switch (record->tag) {
		case CB_TAG_MEMORY:
			if (record->size < sizeof(struct cb_memory)) {
				return EFI_COMPROMISED_DATA;
			}

			range_count = (record->size - sizeof(struct cb_memory)) /
				     sizeof(struct cb_memory_range);
			if ((record->size - sizeof(struct cb_memory)) %
					    sizeof(struct cb_memory_range) !=
				    0 ||
			    range_count > CDK2_COREBOOT_MAX_MEMORY_RANGES -
						 handoff->memory_range_count) {
				return EFI_COMPROMISED_DATA;
			}

			memory = (const struct cb_memory *)record;
			for (range_index = 0; range_index < range_count; range_index++) {
				range = &memory->map[range_index];
				base = cdk2_coreboot_unpack64(&range->start);
				size = cdk2_coreboot_unpack64(&range->size);
				end = base + size;
				if (size == 0 || end < base) {
					return EFI_COMPROMISED_DATA;
				}

				handoff->memory_ranges[handoff->memory_range_count].base = base;
				handoff->memory_ranges[handoff->memory_range_count].size = size;
				handoff->memory_ranges[handoff->memory_range_count].type =
					range->type;
				handoff->memory_range_count++;

				if (range->type == CB_MEM_RAM) {
					handoff->usable_ram_count++;
					if (size > handoff->largest_usable_ram_size) {
						handoff->largest_usable_ram_base = base;
						handoff->largest_usable_ram_size = size;
					}
				}
			}

			break;

		case CB_TAG_FORWARD:
			if (record->size != sizeof(struct cb_forward) ||
			    handoff->forward_address != 0) {
				return EFI_COMPROMISED_DATA;
			}

			forward = (const struct cb_forward *)record;
			if (forward->forward == 0) {
				return EFI_COMPROMISED_DATA;
			}

			handoff->forward_address = forward->forward;
			break;

		case CB_TAG_PAYLOAD_RESOURCE_HANDOFF:
			if (handoff->payload_resource_handoff_status != EFI_NOT_FOUND) {
				handoff->payload_resource_handoff_status = EFI_COMPROMISED_DATA;
				handoff->payload_resource_handoff = NULL;
				break;
			}

			handoff->payload_resource_handoff_status = EFI_SUCCESS;
			handoff->payload_resource_handoff =
				(const struct cb_payload_resource_handoff *)record;

			break;

		default:
			break;
		}

		records_remaining -= record->size;
		record_index++;
	}

	if (records_remaining != 0) {
		return EFI_COMPROMISED_DATA;
	}

	if ((handoff->payload_resource_handoff_status == EFI_SUCCESS) &&
	    (handoff->payload_resource_handoff != NULL)) {
		handoff->payload_resource_handoff_status =
			cdk2_coreboot_validate_payload_resource_handoff(
				handoff->payload_resource_handoff, handoff);
		if (EFI_ERROR(handoff->payload_resource_handoff_status)) {
			handoff->payload_resource_handoff = NULL;
		}
	}

	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_coreboot_parse_table(const void *table, UINTN table_size,
			  struct cdk2_coreboot_handoff *handoff)
{
	return cdk2_coreboot_parse_one_table(table, table_size, handoff);
}

EFI_STATUS
cdk2_coreboot_parse(UINTN bootloader_parameter, struct cdk2_coreboot_handoff *handoff)
{
	const void *table;
	UINTN depth;
	EFI_STATUS status;

	if (bootloader_parameter == 0 || handoff == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	table = (const void *)(UINTN)bootloader_parameter;
	for (depth = 0; depth < CDK2_COREBOOT_MAX_FORWARD_DEPTH; depth++) {
		status = cdk2_coreboot_parse_one_table(
			table, sizeof(struct cb_header) + CDK2_COREBOOT_MAX_TABLE_BYTES,
			handoff);
		if (EFI_ERROR(status)) {
			return status;
		}

		if (handoff->forward_address == 0) {
			return EFI_SUCCESS;
		}

		if (handoff->forward_address > MAX_UINTN ||
		    handoff->forward_address == (UINT64)(UINTN)table) {
			return EFI_COMPROMISED_DATA;
		}

		table = (const void *)(UINTN)handoff->forward_address;
	}

	return EFI_COMPROMISED_DATA;
}

EFI_STATUS
cdk2_coreboot_find_record(const struct cdk2_coreboot_handoff *handoff, UINT32 tag,
			  UINT32 minimum_size, const void **record)
{
	const struct cb_record *current;
	const UINT8 *cursor;
	UINTN remaining;
	UINTN index;

	if (handoff == NULL || handoff->header == NULL || record == NULL ||
	    minimum_size < sizeof(struct cb_record) ||
	    handoff->header->header_bytes > handoff->table_size) {
		return EFI_INVALID_PARAMETER;
	}

	*record = NULL;
	cursor = (const UINT8 *)handoff->header + handoff->header->header_bytes;
	remaining = handoff->table_size - handoff->header->header_bytes;
	for (index = 0; index < handoff->record_count; index++) {
		if (remaining < sizeof(struct cb_record)) {
			return EFI_COMPROMISED_DATA;
		}

		current = (const struct cb_record *)(const void *)cursor;
		if (current->size < sizeof(struct cb_record) || current->size > remaining) {
			return EFI_COMPROMISED_DATA;
		}

		if (current->tag == tag) {
			if (current->size < minimum_size) {
				return EFI_COMPROMISED_DATA;
			}

			*record = current;
			return EFI_SUCCESS;
		}

		cursor += current->size;
		remaining -= current->size;
	}

	return EFI_NOT_FOUND;
}

EFI_STATUS
cdk2_coreboot_find_payload_resource_section(const struct cdk2_coreboot_handoff *handoff,
					    UINT16 type,
					    const struct cb_payload_resource_section **section)
{
	const struct cb_payload_resource_handoff *record;
	const struct cb_payload_resource_section *current;
	UINTN index;

	if (handoff == NULL || section == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*section = NULL;
	if (handoff->payload_resource_handoff_status != EFI_SUCCESS) {
		return handoff->payload_resource_handoff_status;
	}

	record = handoff->payload_resource_handoff;
	if (record == NULL) {
		return EFI_COMPROMISED_DATA;
	}

	for (index = 0; index < record->section_count; index++) {
		current = (const struct cb_payload_resource_section
				   *)(const void *)((const UINT8 *)record +
						    record->header_length +
						    index * record->section_header_length);
		if (current->type == type) {
			*section = current;
			return EFI_SUCCESS;
		}
	}

	return EFI_NOT_FOUND;
}
