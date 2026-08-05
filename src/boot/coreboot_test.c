/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host checks for the freestanding coreboot table parser.
 */

#include "coreboot.h"
#include "coreboot_hobs.h"
#include "services.h"

#include <guid/acpi_board_info.h>
#include <guid/memory_allocation_hob.h>
#include <industry_standard/acpi.h>
#include <industry_standard/mcfg.h>
#include <industry_standard/tpm20.h>
#include <industry_standard/tpm2_acpi.h>
#include <industry_standard/uefi_tcg_platform.h>
#include <library/hob_lib.h>
#include <universal_payload/smbios_table.h>
#include <stdio.h>
#include <string.h>

#define TEST_TABLE_SIZE                     4096U
#define TEST_LARGE_TABLE_SIZE               131072U
#define TEST_HOB_REGION_SIZE                0x04000000U
#define TEST_HOB_ALIGN8(size)               (((size) + 7U) & ~(UINTN)7U)
#define TEST_PRH_UNKNOWN_SECTION            0x7fffU
#define TEST_PRH_COUNT_LIMIT_EXCESS         257U
#define TEST_PRH_MEMORY_POLICY_LIMIT_EXCESS 1025U
#define TEST_TPM_EVENT_LOG_SIZE             256U
#define TEST_TPM_SPEC_ID_EVENT_NAME         "Spec ID Event"
#define TEST_ACPI_MCFG_ALLOCATION \
	EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE

struct test_acpi_root {
	EFI_ACPI_DESCRIPTION_HEADER header;
	UINT64 entries[2];
} __packed;

struct test_mcfg_table {
	EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER header;
	TEST_ACPI_MCFG_ALLOCATION allocation;
} __packed;

struct test_tpm2_table {
	EFI_TPM2_ACPI_TABLE header;
	UINT8 parameters[EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_5];
	UINT32 laml;
	UINT64 lasa;
} __packed;

#if defined(__GNUC__)
static UINT8 m_transfer_hob_storage[EFI_PAGE_SIZE] __aligned(EFI_PAGE_SIZE);
#else
static UINT8 m_transfer_hob_storage[EFI_PAGE_SIZE];
#endif
static UINT8 m_large_test_storage[TEST_LARGE_TABLE_SIZE];

EFI_STATUS
EFIAPI
cdk2_coreboot_test_transfer(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_coreboot_test_append_loaded_dxe_core_hobs(void *handoff,
					       EFI_PHYSICAL_ADDRESS fv_base, UINTN fv_size,
					       const void *module_name,
					       EFI_PHYSICAL_ADDRESS image_base,
					       UINTN image_size,
					       EFI_PHYSICAL_ADDRESS entry_point);

EFI_STATUS
EFIAPI
cdk2_coreboot_test_build_acpi_board_info(EFI_PHYSICAL_ADDRESS rsdp_address, void *board_info);

struct cdk2_coreboot_test_cbmem_result
EFIAPI
cdk2_coreboot_test_find_acpi_rsdp(const struct cdk2_coreboot_handoff *coreboot);

EFI_STATUS
EFIAPI
cdk2_coreboot_test_validate_framebuffer(const struct cb_framebuffer *framebuffer);

EFI_STATUS
EFIAPI
cdk2_coreboot_test_append_tpm_event_hobs(void *handoff,
					 EFI_ACPI_DESCRIPTION_HEADER *tpm2_table);

EFI_STATUS
EFIAPI
cdk2_coreboot_test_append_smbios_hob(void *handoff,
				     const struct cdk2_coreboot_handoff *coreboot);

void EFIAPI cdk2_platform_late_init(void)
{
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 coreboot test: %s\n", message);
		return 1;
	}

	return 0;
}

enum test_prh_fixture {
	test_prh_valid,
	test_prh_bad_crc,
	test_prh_short_header,
	test_prh_section_overflow,
	test_prh_section_overlap,
	test_prh_duplicate_type,
	test_prh_unknown_mandatory,
	test_prh_known_mandatory,
	test_prh_memory_zero_length,
	test_prh_memory_wrap,
	test_prh_memory_overlap,
	test_prh_memory_policy_limit,
	test_prh_cache_count_mismatch,
	test_prh_missing_lifetime,
	test_prh_memory_protection_no_paging,
	test_prh_framebuffer_bad_mask,
	test_prh_pci_bad_bar,
	test_prh_pci_duplicate,
	test_prh_pci_assignment_overlap,
	test_prh_pci_outside_bridge,
	test_prh_memory_attributes_exceed_capabilities,
	test_prh_unsupported_revision,
	test_prh_unsupported_flags,
	test_prh_unknown_lifetime_bit,
	test_prh_memory_unsupported_attributes,
	test_prh_memory_bad_gcd_type,
	test_prh_memory_multiple_cache_attributes,
	test_prh_cache_s3_without_lifetime,
	test_prh_s3_missing_generation,
	test_prh_s3_cache_not_valid,
	test_prh_pci_assignment_without_authoritative_root,
	test_prh_pci_mmio32_above4_gb,
	test_prh_pci_io_attributes,
	test_prh_runtime_policy_reserved,
	test_prh_memory_bad_gcd_efi_type,
	test_prh_memory_authority_without_section,
	test_prh_cache_mtrr_mismatch,
	test_prh_s3_unsupported,
	test_prh_pci_root_overlap,
	test_prh_pci_upper_slot_collision,
	test_prh_pci64_bar5,
	test_prh_pci_assignment_limit,
	test_prh_pci_zero_base,
	test_prh_framebuffer_overlap_mask,
	test_prh_framebuffer_mask_past_bpp,
	test_prh_framebuffer_no_resource_proof,
	test_prh_framebuffer_system_memory_policy,
	test_prh_cache_coverage_gap,
	test_prh_cache_bad_pat_slot,
	test_prh_memory_split_coverage,
	test_prh_cache_extended_mtrr_entries,
	test_prh_cache_bad_default_type,
	test_prh_cache_default_type_coverage,
	test_prh_cache_overlap_precedence,
	test_prh_pci_root_mem32_above4_gb,
	test_prh_unknown_duplicate_optional,
	test_prh_memory_oem_os_type,
	test_prh_cache4_k_variable_mtrr,
	test_prh_cache_physical_address_bits36,
	test_prh_cache_fixed_default_range,
	test_prh_cache_fixed_enabled_without_state,
	test_prh_cache_inactive_bad_base,
	test_prh_cache_bad_pat_without_cache_policy,
	test_prh_memory_runtime_unaligned,
	test_prh_memory_gcd_coverage,
	test_prh_memory_gcd_coverage_gap,
	test_prh_memory_delegated_coverage,
	test_prh_memory_oem_os_mmio_type,
	test_prh_cache_range_beyond_physical_bits
};

static void pack_cb_uint64(struct cbuint64 *value, UINT64 data)
{
	value->lo = (UINT32)data;
	value->hi = (UINT32)(data >> 32);
}

static void pack_cb_uint64_at(void *base, UINTN offset, UINT64 data)
{
	pack_cb_uint64((struct cbuint64 *)((UINT8 *)base + offset), data);
}

static void finalize_payload_resource_handoff(struct cb_payload_resource_handoff *handoff)
{
	handoff->crc32 = 0;
	handoff->crc32 = cdk2_coreboot_calculate_crc32(handoff, handoff->size);
}

static UINTN finalize_table_with_header_size(UINT8 *storage, UINTN storage_size,
					  UINTN header_bytes, UINTN table_bytes,
					  UINT32 table_entries)
{
	struct cb_header *header;

	if (storage == NULL || header_bytes < sizeof(struct cb_header) ||
	    header_bytes > MAX_UINT32 || storage_size < header_bytes ||
	    table_bytes > storage_size - header_bytes || table_bytes > MAX_UINT32) {
		return 0;
	}

	header = (struct cb_header *)(void *)storage;
	header->signature = CB_HEADER_SIGNATURE;
	header->header_bytes = (UINT32)header_bytes;
	header->table_bytes = (UINT32)table_bytes;
	header->table_entries = table_entries;
	header->table_checksum =
		cdk2_coreboot_checksum16(storage + header_bytes, table_bytes);
	header->header_checksum = 0;
	header->header_checksum = cdk2_coreboot_checksum16(header, header_bytes);
	return header_bytes + table_bytes;
}

static UINTN finalize_table(UINT8 *storage, UINTN storage_size, UINTN table_bytes,
			   UINT32 table_entries)
{
	return finalize_table_with_header_size(storage, storage_size, sizeof(struct cb_header),
					   table_bytes, table_entries);
}

static UINTN build_memory_table(UINT8 *storage, UINTN storage_size)
{
	struct cb_memory *memory;
	struct cb_memory_range *range;
	struct lb_boot_mode *boot_mode;

	memset(storage, 0, storage_size);
	memory = (struct cb_memory *)(void *)(storage + sizeof(struct cb_header));
	memory->tag = CB_TAG_MEMORY;
	memory->size = sizeof(*memory) + 3 * sizeof(struct cb_memory_range);

	range = &memory->map[0];
	range->start.lo = 0x00100000;
	range->start.hi = 0;
	range->size.lo = 0x00300000;
	range->size.hi = 0;
	range->type = CB_MEM_RAM;

	range = &memory->map[1];
	range->start.lo = 0x00000000;
	range->start.hi = 1;
	range->size.lo = 0x01000000;
	range->size.hi = 0;
	range->type = CB_MEM_RESERVED;

	range = &memory->map[2];
	range->start.lo = 0x00400000;
	range->start.hi = 0;
	range->size.lo = 0x00001000;
	range->size.hi = 0;
	range->type = CB_MEM_TABLE;

	boot_mode = (struct lb_boot_mode *)(void *)((UINT8 *)memory + memory->size);
	boot_mode->tag = CB_TAG_BOOT_MODE;
	boot_mode->size = sizeof(*boot_mode);
	boot_mode->boot_mode = LB_BOOT_MODE_FLASH_UPDATE;

	return finalize_table(storage, storage_size, memory->size + boot_mode->size, 2);
}

static UINTN build_boot_mode_table(UINT8 *storage, UINTN storage_size, enum cb_boot_mode mode)
{
	struct lb_boot_mode *boot_mode;

	memset(storage, 0, storage_size);
	boot_mode = (struct lb_boot_mode *)(void *)(storage + sizeof(struct cb_header));
	boot_mode->tag = CB_TAG_BOOT_MODE;
	boot_mode->size = sizeof(*boot_mode);
	boot_mode->boot_mode = mode;

	return finalize_table(storage, storage_size, boot_mode->size, 1);
}

static UINTN build_smbios_cbmem_table(UINT8 *storage, UINTN storage_size,
				      const void *smbios_entry, UINT32 smbios_size)
{
	struct cb_cbmem_entry *entry;
	UINT64 smbios_address;

	memset(storage, 0, storage_size);
	entry = (struct cb_cbmem_entry *)(void *)(storage + sizeof(struct cb_header));
	entry->tag = CB_TAG_CBMEM_ENTRY;
	entry->size = sizeof(*entry);
	smbios_address = (UINT64)(UINTN)smbios_entry;
	entry->address.lo = (UINT32)smbios_address;
	entry->address.hi = (UINT32)(smbios_address >> 32);
	entry->entry_size = smbios_size;
	entry->id = CBMEM_ID_SMBIOS;

	return finalize_table(storage, storage_size, entry->size, 1);
}

static UINTN build_forward_table(UINT8 *storage, UINTN storage_size, const void *target)
{
	struct cb_forward *forward;

	memset(storage, 0, storage_size);
	forward = (struct cb_forward *)(void *)(storage + sizeof(struct cb_header));
	forward->tag = CB_TAG_FORWARD;
	forward->size = sizeof(*forward);
	forward->forward = (UINT64)(UINTN)target;

	return finalize_table(storage, storage_size, forward->size, 1);
}

static UINTN build_legacy_serial_table(UINT8 *storage, UINTN storage_size)
{
	struct cb_serial *serial;

	memset(storage, 0, storage_size);
	serial = (struct cb_serial *)(void *)(storage + sizeof(struct cb_header));
	serial->tag = CB_TAG_SERIAL;
	serial->size = CDK2_COREBOOT_SERIAL_MIN_SIZE;
	serial->type = CB_SERIAL_TYPE_IO_MAPPED;
	serial->baseaddr = 0x3f8;
	serial->baud = 115200;
	serial->regwidth = 1;
	return finalize_table(storage, storage_size, serial->size, 1);
}

static UINTN build_legacy_framebuffer_table(UINT8 *storage, UINTN storage_size)
{
	struct cb_framebuffer *framebuffer;

	memset(storage, 0, storage_size);
	framebuffer = (struct cb_framebuffer *)(void *)(storage + sizeof(struct cb_header));
	framebuffer->tag = CB_TAG_FRAMEBUFFER;
	framebuffer->size = CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE;
	framebuffer->physical_address = 0xfd000000ULL;
	framebuffer->x_resolution = 1024;
	framebuffer->y_resolution = 768;
	framebuffer->bytes_per_line = 4096;
	framebuffer->bits_per_pixel = 32;
	framebuffer->red_mask_pos = 16;
	framebuffer->red_mask_size = 8;
	framebuffer->green_mask_pos = 8;
	framebuffer->green_mask_size = 8;
	framebuffer->blue_mask_pos = 0;
	framebuffer->blue_mask_size = 8;
	framebuffer->reserved_mask_pos = 24;
	framebuffer->reserved_mask_size = 8;
	return finalize_table(storage, storage_size, framebuffer->size, 1);
}

static UINTN build_payload_resource_handoff_table(UINT8 *storage, UINTN storage_size,
					      enum test_prh_fixture fixture)
{
	struct cb_payload_resource_handoff *prh;
	struct cb_payload_resource_section *sections;
	struct cb_prh_memory_policy_entry *memory_policy;
	struct cb_prh_x86_cache_state *cache_state;
	struct cb_prh_x86_variable_mtrr *variable_mtrr;
	struct cb_prh_pci_root_bridge_entry *root_bridge;
	struct cb_prh_pci_assignment_entry *pci_assignment;
	struct cb_prh_framebuffer_entry *framebuffer;
	UINT8 *payload;
	UINTN payload_offset;
	UINT64 variable_mtrr_mask;
	UINT32 cache_entry_size;
	UINT32 memory_entry_count;
	UINT32 pci_root_bridge_count;
	UINT32 pci_assignment_count;
	UINTN section_count;

	memset(storage, 0, storage_size);
	prh = (struct cb_payload_resource_handoff *)(void *)(storage +
							     sizeof(struct cb_header));
	prh->tag = CB_TAG_PAYLOAD_RESOURCE_HANDOFF;
	prh->revision = CB_PAYLOAD_RESOURCE_HANDOFF_REVISION;
	prh->header_length = sizeof(*prh);
	prh->section_header_length = sizeof(struct cb_payload_resource_section);
	prh->producer_stage = 1;
	pack_cb_uint64_at(prh, OFFSET_OF(struct cb_payload_resource_handoff, producer_generation),
		       1);
	pack_cb_uint64_at(prh, OFFSET_OF(struct cb_payload_resource_handoff, lifetime_flags),
		       CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_EXIT_BOOT_SERVICES);

	section_count = (fixture == test_prh_unknown_duplicate_optional) ? 7U : 6U;
	prh->section_count = (UINT32)section_count;
	sections = (struct cb_payload_resource_section *)(void *)((UINT8 *)prh +
								  prh->header_length);
	payload_offset = prh->header_length + section_count * prh->section_header_length;
	payload = (UINT8 *)prh + payload_offset;

	memory_entry_count = (fixture == test_prh_memory_policy_limit) ?
				   TEST_PRH_MEMORY_POLICY_LIMIT_EXCESS :
				   ((fixture == test_prh_memory_split_coverage) ? 3U : 2U);
	sections[0].type = CB_PRH_SECTION_MEMORY_POLICY;
	sections[0].flags = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
	sections[0].header_length = sizeof(sections[0]);
	sections[0].entry_size = sizeof(*memory_policy);
	sections[0].entry_count = memory_entry_count;
	sections[0].offset = (UINT32)payload_offset;
	sections[0].length = memory_entry_count * sizeof(*memory_policy);
	if (fixture == test_prh_memory_authority_without_section) {
		sections[0].flags = 0;
	}

	memory_policy = (struct cb_prh_memory_policy_entry *)(void *)payload;
	pack_cb_uint64_at(memory_policy, OFFSET_OF(struct cb_prh_memory_policy_entry, base),
		       0x00100000ULL);
	pack_cb_uint64_at(memory_policy, OFFSET_OF(struct cb_prh_memory_policy_entry, length),
		       0x00200000ULL);
	pack_cb_uint64_at(memory_policy, OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities),
		       EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB);
	pack_cb_uint64_at(memory_policy, OFFSET_OF(struct cb_prh_memory_policy_entry, attributes),
		       EFI_MEMORY_WB);
	memory_policy[0].gcd_type = CB_PRH_GCD_MEMORY_TYPE_SYSTEM;
	memory_policy[0].efi_memory_type = efi_conventional_memory;
	memory_policy[0].owner_flags = CB_PRH_MEMORY_CACHE_AUTHORITATIVE |
				      CB_PRH_MEMORY_GCD_AUTHORITATIVE |
				      CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE;
	pack_cb_uint64_at(&memory_policy[1], OFFSET_OF(struct cb_prh_memory_policy_entry, base),
		       0xfd000000ULL);
	pack_cb_uint64_at(&memory_policy[1], OFFSET_OF(struct cb_prh_memory_policy_entry, length),
		       0x00300000ULL);
	pack_cb_uint64_at(&memory_policy[1],
		       OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities),
		       EFI_MEMORY_UC | EFI_MEMORY_WC);
	pack_cb_uint64_at(&memory_policy[1],
		       OFFSET_OF(struct cb_prh_memory_policy_entry, attributes), EFI_MEMORY_UC);
	memory_policy[1].gcd_type = CB_PRH_GCD_MEMORY_TYPE_MMIO;
	memory_policy[1].efi_memory_type = efi_memory_mapped_io;
	memory_policy[1].owner_flags = CB_PRH_MEMORY_CACHE_AUTHORITATIVE |
				      CB_PRH_MEMORY_GCD_AUTHORITATIVE |
				      CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE;
	if (fixture == test_prh_memory_split_coverage) {
		memory_policy[2] = memory_policy[1];
		memory_policy[1] = memory_policy[0];
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length),
			       0x00100000ULL);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, base),
			       0x00200000ULL);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length),
			       0x00100000ULL);
	}

	if (fixture == test_prh_memory_zero_length) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length), 0);
	} else if (fixture == test_prh_memory_wrap) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, base),
			       MAX_UINT64 - 0xffULL);
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length), 0x200ULL);
	} else if (fixture == test_prh_memory_overlap) {
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, base),
			       0x00180000ULL);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length),
			       0x00100000ULL);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities),
			       EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, attributes),
			       EFI_MEMORY_WB);
		memory_policy[1].gcd_type = CB_PRH_GCD_MEMORY_TYPE_SYSTEM;
		memory_policy[1].efi_memory_type = efi_conventional_memory;
		memory_policy[1].owner_flags = memory_policy[0].owner_flags;
	} else if (fixture == test_prh_memory_protection_no_paging) {
		memory_policy[0].owner_flags |= CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE;
	} else if (fixture == test_prh_memory_attributes_exceed_capabilities) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities),
			       EFI_MEMORY_UC);
	} else if (fixture == test_prh_memory_unsupported_attributes) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities),
			       0x4000000000000000ULL);
	} else if (fixture == test_prh_memory_bad_gcd_type) {
		memory_policy[0].gcd_type = CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED + 1U;
	} else if (fixture == test_prh_memory_bad_gcd_efi_type) {
		memory_policy[0].gcd_type = CB_PRH_GCD_MEMORY_TYPE_MMIO;
	} else if (fixture == test_prh_memory_multiple_cache_attributes) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, attributes),
			       EFI_MEMORY_UC | EFI_MEMORY_WB);
	} else if (fixture == test_prh_memory_oem_os_type) {
		memory_policy[0].efi_memory_type = MEMORY_TYPE_OEM_RESERVED_MIN;
	} else if (fixture == test_prh_memory_oem_os_mmio_type) {
		memory_policy[0].gcd_type = CB_PRH_GCD_MEMORY_TYPE_MMIO;
		memory_policy[0].efi_memory_type = MEMORY_TYPE_OEM_RESERVED_MIN;
	} else if (fixture == test_prh_framebuffer_system_memory_policy) {
		memory_policy[1].gcd_type = CB_PRH_GCD_MEMORY_TYPE_SYSTEM;
		memory_policy[1].efi_memory_type = efi_conventional_memory;
	} else if (fixture == test_prh_cache_range_beyond_physical_bits) {
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, base),
			       0x1000000000ULL);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length), SIZE_4KB);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities),
			       EFI_MEMORY_UC | EFI_MEMORY_WB);
		pack_cb_uint64_at(&memory_policy[1],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, attributes),
			       EFI_MEMORY_WB);
		memory_policy[1].gcd_type = CB_PRH_GCD_MEMORY_TYPE_SYSTEM;
		memory_policy[1].efi_memory_type = efi_conventional_memory;
	} else if (fixture == test_prh_memory_runtime_unaligned) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, capabilities),
			       EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB |
				       EFI_MEMORY_RUNTIME);
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, attributes),
			       EFI_MEMORY_WB | EFI_MEMORY_RUNTIME);
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length),
			       0x00200001ULL);
	} else if ((fixture == test_prh_memory_gcd_coverage) ||
		   (fixture == test_prh_memory_gcd_coverage_gap)) {
		memory_policy[0].owner_flags &= ~CB_PRH_MEMORY_CACHE_AUTHORITATIVE;
		memory_policy[1].owner_flags &= ~CB_PRH_MEMORY_CACHE_AUTHORITATIVE;
	} else if (fixture == test_prh_memory_delegated_coverage) {
		memory_policy[0].owner_flags = CB_PRH_MEMORY_DELEGATED_TO_PAYLOAD;
	} else if (fixture == test_prh_cache4_k_variable_mtrr) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length), SIZE_4KB);
	} else if ((fixture == test_prh_cache_fixed_default_range) ||
		   (fixture == test_prh_cache_fixed_enabled_without_state)) {
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, base),
			       0x00080000ULL);
		pack_cb_uint64_at(&memory_policy[0],
			       OFFSET_OF(struct cb_prh_memory_policy_entry, length), SIZE_4KB);
	} else if (fixture == test_prh_cache_bad_pat_without_cache_policy) {
		memory_policy[0].owner_flags &= ~CB_PRH_MEMORY_CACHE_AUTHORITATIVE;
		memory_policy[1].owner_flags &= ~CB_PRH_MEMORY_CACHE_AUTHORITATIVE;
	}

	payload_offset += sections[0].length;
	payload = (UINT8 *)prh + payload_offset;

	cache_entry_size = sizeof(*variable_mtrr);
	if (fixture == test_prh_cache_extended_mtrr_entries) {
		cache_entry_size += sizeof(UINT64);
	}

	sections[1].type = CB_PRH_SECTION_X86_CACHE_STATE;
	sections[1].flags = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
	sections[1].header_length = sizeof(sections[1]);
	sections[1].entry_size = cache_entry_size;
	sections[1].entry_count = 2;
	sections[1].offset = (UINT32)payload_offset;
	sections[1].length = sizeof(*cache_state) + 2 * cache_entry_size;
	cache_state = (struct cb_prh_x86_cache_state *)(void *)payload;
	pack_cb_uint64_at(cache_state,
		       OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr),
		       0x800ULL);
	pack_cb_uint64_at(cache_state, OFFSET_OF(struct cb_prh_x86_cache_state, pat_msr),
		       0x0007040600070406ULL);
	pack_cb_uint64_at(cache_state, OFFSET_OF(struct cb_prh_x86_cache_state, fixed_mtrr_crc64),
		       0x12345678ULL);
	cache_state->variable_count = (fixture == test_prh_cache_count_mismatch) ? 3U : 2U;
	cache_state->physical_address_bits = ((fixture == test_prh_cache_physical_address_bits36) ||
					     (fixture == test_prh_cache_range_beyond_physical_bits)) ?
						    36U :
						    52U;
	cache_state->flags = CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC |
			    CB_PRH_X86_CACHE_FLAG_FIXED_VALID;
	if (fixture == test_prh_cache_fixed_enabled_without_state) {
		cache_state->flags &= ~CB_PRH_X86_CACHE_FLAG_FIXED_VALID;
	}

	if ((fixture == test_prh_cache_s3_without_lifetime) || (fixture == test_prh_s3_unsupported)) {
		cache_state->flags |= CB_PRH_X86_CACHE_FLAG_S3_VALID;
	}

	variable_mtrr_mask = ((fixture == test_prh_cache_physical_address_bits36) ||
			    (fixture == test_prh_cache_range_beyond_physical_bits)) ?
				   0x0000000fffc00000ULL :
				   0x000fffffffc00000ULL;
	variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)(cache_state + 1);
	pack_cb_uint64_at(&variable_mtrr[0],
		       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_base_msr),
		       0x00000000ULL | 6U);
	pack_cb_uint64_at(&variable_mtrr[0],
		       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr),
		       variable_mtrr_mask | BIT11);
	variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)((UINT8 *)variable_mtrr +
								   cache_entry_size);
	pack_cb_uint64_at(variable_mtrr, OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_base_msr),
		       0xfd000000ULL);
	pack_cb_uint64_at(variable_mtrr, OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr),
		       variable_mtrr_mask | BIT11);
	if (fixture == test_prh_cache_mtrr_mismatch) {
		variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)(cache_state + 1);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_base_msr),
			       0x00000000ULL);
	} else if ((fixture == test_prh_cache_bad_pat_slot) ||
		   (fixture == test_prh_cache_bad_pat_without_cache_policy)) {
		pack_cb_uint64_at(cache_state, OFFSET_OF(struct cb_prh_x86_cache_state, pat_msr),
			       0x0007040600020006ULL);
	} else if (fixture == test_prh_cache_bad_default_type) {
		pack_cb_uint64_at(cache_state,
			       OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr),
			       0x807ULL);
	} else if (fixture == test_prh_cache_default_type_coverage) {
		variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)(cache_state + 1);
		pack_cb_uint64_at(cache_state,
			       OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr),
			       0x806ULL);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr), 0);
	} else if (fixture == test_prh_cache_overlap_precedence) {
		variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)(cache_state + 1);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr),
			       0x000fffff00000000ULL | BIT11);
	} else if (fixture == test_prh_cache_range_beyond_physical_bits) {
		variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)(cache_state + 1);
		pack_cb_uint64_at(cache_state,
			       OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr),
			       0x806ULL);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr), 0);
		variable_mtrr =
			(struct cb_prh_x86_variable_mtrr *)(void *)((UINT8 *)variable_mtrr +
								    cache_entry_size);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr), 0);
	} else if (fixture == test_prh_cache4_k_variable_mtrr) {
		variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)(cache_state + 1);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_base_msr),
			       0x00100000ULL | 6U);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr),
			       0x000ffffffffff000ULL | BIT11);
	} else if ((fixture == test_prh_cache_fixed_default_range) ||
		   (fixture == test_prh_cache_fixed_enabled_without_state)) {
		variable_mtrr = (struct cb_prh_x86_variable_mtrr *)(void *)(cache_state + 1);
		pack_cb_uint64_at(cache_state,
			       OFFSET_OF(struct cb_prh_x86_cache_state, mtrr_default_type_msr),
			       (fixture == test_prh_cache_fixed_enabled_without_state) ? 0xc06ULL :
										   0x806ULL);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr), 0);
	} else if (fixture == test_prh_cache_inactive_bad_base) {
		variable_mtrr =
			(struct cb_prh_x86_variable_mtrr *)(void *)((UINT8 *)(cache_state + 1) +
								    cache_entry_size);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_base_msr),
			       0x100ULL | 6U);
		pack_cb_uint64_at(variable_mtrr,
			       OFFSET_OF(struct cb_prh_x86_variable_mtrr, phys_mask_msr), 0);
	}

	payload_offset += sections[1].length;
	payload = (UINT8 *)prh + payload_offset;

	sections[2].type = CB_PRH_SECTION_PCI_ROOT_BRIDGES;
	sections[2].flags = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
	sections[2].header_length = sizeof(sections[2]);
	sections[2].entry_size = sizeof(*root_bridge);
	pci_root_bridge_count = (fixture == test_prh_pci_root_overlap) ? 2U : 1U;
	sections[2].entry_count = pci_root_bridge_count;
	sections[2].offset = (UINT32)payload_offset;
	sections[2].length = pci_root_bridge_count * sizeof(*root_bridge);
	if (fixture == test_prh_pci_assignment_without_authoritative_root) {
		sections[2].flags = 0;
	}

	root_bridge = (struct cb_prh_pci_root_bridge_entry *)(void *)payload;
	root_bridge->bus_end = 0xff;
	pack_cb_uint64_at(root_bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, io_base),
		       0x1000);
	pack_cb_uint64_at(root_bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, io_length),
		       0xf000);
	pack_cb_uint64_at(root_bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_base),
		       0xe0000000ULL);
	pack_cb_uint64_at(root_bridge, OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_length),
		       0x20000000ULL);
	if (fixture == test_prh_pci_root_overlap) {
		root_bridge[1] = root_bridge[0];
		root_bridge[1].bus_start = 0x80;
	} else if (fixture == test_prh_pci_root_mem32_above4_gb) {
		pack_cb_uint64_at(root_bridge,
			       OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_base),
			       0x100000000ULL);
		pack_cb_uint64_at(root_bridge,
			       OFFSET_OF(struct cb_prh_pci_root_bridge_entry, mem32_length),
			       0x1000ULL);
	}

	payload_offset += sections[2].length;
	payload = (UINT8 *)prh + payload_offset;

	sections[3].type = CB_PRH_SECTION_PCI_ASSIGNMENTS;
	sections[3].flags = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
	sections[3].header_length = sizeof(sections[3]);
	sections[3].entry_size = sizeof(*pci_assignment);
	pci_assignment_count = ((fixture == test_prh_pci_duplicate) ||
			      (fixture == test_prh_pci_assignment_overlap) ||
			      (fixture == test_prh_pci_upper_slot_collision)) ?
				     2U :
				     1U;
	if (fixture == test_prh_pci_assignment_limit) {
		pci_assignment_count = 257U;
	}

	sections[3].entry_count = pci_assignment_count;
	sections[3].offset = (UINT32)payload_offset;
	sections[3].length = pci_assignment_count * sizeof(*pci_assignment);
	pci_assignment = (struct cb_prh_pci_assignment_entry *)(void *)payload;
	pci_assignment->device = 2;
	pci_assignment->bar = 0;
	pci_assignment->resource_type = CB_PRH_PCI_RESOURCE_MMIO32;
	pack_cb_uint64_at(pci_assignment, OFFSET_OF(struct cb_prh_pci_assignment_entry, base),
		       0xfd000000ULL);
	pack_cb_uint64_at(pci_assignment, OFFSET_OF(struct cb_prh_pci_assignment_entry, length),
		       0x400000ULL);
	pack_cb_uint64_at(pci_assignment, OFFSET_OF(struct cb_prh_pci_assignment_entry, attributes),
		       EFI_MEMORY_UC);
	if (fixture == test_prh_pci_bad_bar) {
		pci_assignment->bar = 6;
	} else if (fixture == test_prh_pci_outside_bridge) {
		pack_cb_uint64_at(pci_assignment,
			       OFFSET_OF(struct cb_prh_pci_assignment_entry, base),
			       0xd0000000ULL);
	} else if (fixture == test_prh_pci_duplicate) {
		pci_assignment[1] = pci_assignment[0];
	} else if (fixture == test_prh_pci_assignment_overlap) {
		pci_assignment[1] = pci_assignment[0];
		pci_assignment[1].device = 3;
		pci_assignment[1].bar = 2;
		pack_cb_uint64_at(&pci_assignment[1],
			       OFFSET_OF(struct cb_prh_pci_assignment_entry, base),
			       0xfd200000ULL);
		pack_cb_uint64_at(&pci_assignment[1],
			       OFFSET_OF(struct cb_prh_pci_assignment_entry, length),
			       0x200000ULL);
	} else if (fixture == test_prh_pci_upper_slot_collision) {
		pci_assignment->resource_type = CB_PRH_PCI_RESOURCE_MMIO64;
		pci_assignment[1] = pci_assignment[0];
		pci_assignment[1].bar = 1;
		pci_assignment[1].resource_type = CB_PRH_PCI_RESOURCE_MMIO32;
	} else if (fixture == test_prh_pci64_bar5) {
		pci_assignment->bar = 5;
		pci_assignment->resource_type = CB_PRH_PCI_RESOURCE_MMIO64;
	} else if (fixture == test_prh_pci_mmio32_above4_gb) {
		pack_cb_uint64_at(pci_assignment,
			       OFFSET_OF(struct cb_prh_pci_assignment_entry, base),
			       0x100000000ULL);
	} else if (fixture == test_prh_pci_io_attributes) {
		pci_assignment->resource_type = CB_PRH_PCI_RESOURCE_IO;
		pack_cb_uint64_at(pci_assignment,
			       OFFSET_OF(struct cb_prh_pci_assignment_entry, base), 0x1000ULL);
		pack_cb_uint64_at(pci_assignment,
			       OFFSET_OF(struct cb_prh_pci_assignment_entry, length), 0x100ULL);
	} else if (fixture == test_prh_pci_zero_base) {
		pack_cb_uint64_at(pci_assignment,
			       OFFSET_OF(struct cb_prh_pci_assignment_entry, base), 0);
	}

	if (fixture == test_prh_pci_root_mem32_above4_gb) {
		sections[3].flags = 0;
	}

	payload_offset += sections[3].length;
	payload = (UINT8 *)prh + payload_offset;

	sections[4].type = CB_PRH_SECTION_FRAMEBUFFER;
	sections[4].flags = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
	sections[4].header_length = sizeof(sections[4]);
	sections[4].entry_size = sizeof(*framebuffer);
	sections[4].entry_count = 1;
	sections[4].offset = (UINT32)payload_offset;
	sections[4].length = sizeof(*framebuffer);
	framebuffer = (struct cb_prh_framebuffer_entry *)(void *)payload;
	pack_cb_uint64_at(
		framebuffer, OFFSET_OF(struct cb_prh_framebuffer_entry, physical_address),
		(fixture == test_prh_framebuffer_no_resource_proof) ? 0xd0000000ULL : 0xfd000000ULL);
	pack_cb_uint64_at(framebuffer, OFFSET_OF(struct cb_prh_framebuffer_entry, size),
		       4096ULL * 768U);
	framebuffer->x_resolution = 1024;
	framebuffer->y_resolution = 768;
	framebuffer->bytes_per_line = 4096;
	framebuffer->bits_per_pixel = (fixture == test_prh_framebuffer_mask_past_bpp) ? 16 : 32;
	framebuffer->red_mask_pos = (fixture == test_prh_framebuffer_bad_mask) ? 31 : 16;
	framebuffer->red_mask_size = 8;
	framebuffer->green_mask_pos = (fixture == test_prh_framebuffer_overlap_mask) ? 16 : 8;
	framebuffer->green_mask_size = 8;
	framebuffer->blue_mask_pos = 0;
	framebuffer->blue_mask_size = 8;
	framebuffer->reserved_mask_pos = 24;
	framebuffer->reserved_mask_size = 8;
	framebuffer->owner_flags = CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE |
				   CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED;
	if (fixture == test_prh_pci_root_mem32_above4_gb) {
		sections[4].flags = 0;
		framebuffer->owner_flags = CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED;
	} else if ((fixture == test_prh_memory_gcd_coverage) ||
		   (fixture == test_prh_memory_gcd_coverage_gap) ||
		   (fixture == test_prh_cache_range_beyond_physical_bits)) {
		sections[4].flags = 0;
		framebuffer->owner_flags = CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED;
	}

	payload_offset += sections[4].length;
	payload = (UINT8 *)prh + payload_offset;

	sections[5].type = TEST_PRH_UNKNOWN_SECTION;
	sections[5].flags =
		(fixture == test_prh_unknown_mandatory) ? CB_PRH_SECTION_FLAG_MANDATORY : 0;
	sections[5].header_length = sizeof(sections[5]);
	sections[5].entry_size = sizeof(UINT32);
	sections[5].entry_count = 1;
	sections[5].offset = (UINT32)payload_offset;
	sections[5].length = sizeof(UINT32);
	*(UINT32 *)(void *)payload = 0xa5a5a5a5U;

	if (fixture == test_prh_unknown_duplicate_optional) {
		payload_offset += sections[5].length;
		payload = (UINT8 *)prh + payload_offset;

		sections[6].type = TEST_PRH_UNKNOWN_SECTION;
		sections[6].flags = 0;
		sections[6].header_length = sizeof(sections[6]);
		sections[6].entry_size = sizeof(UINT32);
		sections[6].entry_count = 1;
		sections[6].offset = (UINT32)payload_offset;
		sections[6].length = sizeof(UINT32);
		*(UINT32 *)(void *)payload = 0x5a5a5a5aU;
	}

	payload_offset += sections[section_count - 1U].length;
	prh->size = (UINT32)payload_offset;

	if (fixture == test_prh_short_header) {
		prh->header_length = sizeof(struct cb_record);
	} else if (fixture == test_prh_section_overflow) {
		sections[0].offset = prh->size - 4U;
		sections[0].length = 8U;
	} else if (fixture == test_prh_section_overlap) {
		sections[5].offset = sections[3].offset;
		sections[5].length = sizeof(UINT32);
	} else if (fixture == test_prh_duplicate_type) {
		sections[1].type = sections[0].type;
	} else if (fixture == test_prh_known_mandatory) {
		sections[5].type = CB_PRH_SECTION_BOOT_INTENT;
		sections[5].flags = CB_PRH_SECTION_FLAG_MANDATORY;
	} else if (fixture == test_prh_missing_lifetime) {
		pack_cb_uint64_at(
			prh, OFFSET_OF(struct cb_payload_resource_handoff, lifetime_flags), 0);
	} else if (fixture == test_prh_unsupported_revision) {
		prh->revision = CB_PAYLOAD_RESOURCE_HANDOFF_REVISION + 1U;
	} else if (fixture == test_prh_unsupported_flags) {
		prh->flags = 1;
	} else if (fixture == test_prh_unknown_lifetime_bit) {
		pack_cb_uint64_at(prh,
			       OFFSET_OF(struct cb_payload_resource_handoff, lifetime_flags),
			       CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_EXIT_BOOT_SERVICES |
				       0x8000000000000000ULL);
	} else if (fixture == test_prh_s3_missing_generation) {
		pack_cb_uint64_at(
			prh, OFFSET_OF(struct cb_payload_resource_handoff, producer_generation),
			0);
		pack_cb_uint64_at(prh,
			       OFFSET_OF(struct cb_payload_resource_handoff, lifetime_flags),
			       CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_S3_RESUME |
				       CB_PRH_LIFETIME_EXIT_BOOT_SERVICES);
	} else if (fixture == test_prh_s3_cache_not_valid) {
		pack_cb_uint64_at(prh,
			       OFFSET_OF(struct cb_payload_resource_handoff, lifetime_flags),
			       CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_S3_RESUME |
				       CB_PRH_LIFETIME_EXIT_BOOT_SERVICES);
	} else if (fixture == test_prh_s3_unsupported) {
		pack_cb_uint64_at(prh,
			       OFFSET_OF(struct cb_payload_resource_handoff, lifetime_flags),
			       CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_S3_RESUME |
				       CB_PRH_LIFETIME_EXIT_BOOT_SERVICES);
	} else if (fixture == test_prh_runtime_policy_reserved) {
		sections[5].type = CB_PRH_SECTION_RUNTIME_POLICY;
	}

	finalize_payload_resource_handoff(prh);
	if (fixture == test_prh_bad_crc) {
		prh->crc32 ^= 1U;
	}

	return finalize_table(storage, storage_size, prh->size, 1);
}

static UINTN build_memory_and_payload_resource_handoff_table(UINT8 *storage, UINTN storage_size,
						       enum test_prh_fixture fixture)
{
	UINT8 prh_storage[TEST_TABLE_SIZE];
	struct cb_memory *memory;
	struct cb_memory_range *range;
	const struct cb_record *prh;
	enum test_prh_fixture prh_fixture;
	UINTN prh_table_size;
	UINTN range_count;
	UINTN table_bytes;

	memset(storage, 0, storage_size);
	prh_fixture = (fixture == test_prh_cache_coverage_gap) ? test_prh_valid : fixture;
	prh_table_size =
		build_payload_resource_handoff_table(prh_storage, sizeof(prh_storage), prh_fixture);
	if (prh_table_size == 0) {
		return 0;
	}

	range_count = ((fixture == test_prh_cache_coverage_gap) ||
		      (fixture == test_prh_memory_gcd_coverage_gap)) ?
			     2U :
			     1U;
	memory = (struct cb_memory *)(void *)(storage + sizeof(struct cb_header));
	memory->tag = CB_TAG_MEMORY;
	memory->size = sizeof(*memory) + range_count * sizeof(struct cb_memory_range);

	range = &memory->map[0];
	range->start.lo = 0x00100000;
	range->start.hi = 0;
	range->size.lo = 0x00200000;
	range->size.hi = 0;
	range->type = CB_MEM_RAM;

	if ((fixture == test_prh_cache_coverage_gap) || (fixture == test_prh_memory_gcd_coverage_gap)) {
		range = &memory->map[1];
		range->start.lo = 0x01000000;
		range->start.hi = 0;
		range->size.lo = 0x00001000;
		range->size.hi = 0;
		range->type = CB_MEM_RESERVED;
	}

	prh = (const struct cb_record *)(const void *)(prh_storage + sizeof(struct cb_header));
	table_bytes = memory->size + prh->size;
	if (table_bytes > storage_size - sizeof(struct cb_header)) {
		return 0;
	}

	memcpy((UINT8 *)memory + memory->size, prh, prh->size);
	return finalize_table(storage, storage_size, table_bytes, 2);
}

static UINTN build_extended_header_memory_table(UINT8 *storage, UINTN storage_size)
{
	const UINTN header_bytes = sizeof(struct cb_header) + 16U;
	struct cb_memory *memory;
	struct cb_memory_range *range;

	if (storage == NULL || storage_size < header_bytes) {
		return 0;
	}

	memset(storage, 0, storage_size);
	memset(storage + sizeof(struct cb_header), 0xa5, header_bytes - sizeof(struct cb_header));

	memory = (struct cb_memory *)(void *)(storage + header_bytes);
	memory->tag = CB_TAG_MEMORY;
	memory->size = sizeof(*memory) + sizeof(struct cb_memory_range);

	range = &memory->map[0];
	range->start.lo = 0x00100000;
	range->start.hi = 0;
	range->size.lo = 0x00100000;
	range->size.hi = 0;
	range->type = CB_MEM_RAM;

	return finalize_table_with_header_size(storage, storage_size, header_bytes, memory->size, 1);
}

static UINT8 test_acpi_checksum8(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT8 checksum;
	UINTN index;

	bytes = (const UINT8 *)buffer;
	checksum = 0;
	for (index = 0; index < length; index++) {
		checksum = (UINT8)(checksum + bytes[index]);
	}

	return (UINT8)(0U - checksum);
}

static void test_update_acpi_table_checksum(EFI_ACPI_DESCRIPTION_HEADER *header)
{
	header->checksum = 0;
	header->checksum = test_acpi_checksum8(header, header->length);
}

static void
test_update_rsdp_checksums(EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *rsdp)
{
	rsdp->checksum = 0;
	rsdp->extended_checksum = 0;
	rsdp->checksum =
		test_acpi_checksum8(rsdp,
				    OFFSET_OF(EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER,
					      length));
	if (rsdp->revision != 0) {
		rsdp->extended_checksum = test_acpi_checksum8(rsdp, rsdp->length);
	}
}

static void build_test_acpi_tables(EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *rsdp,
				struct test_acpi_root *xsdt,
				EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *fadt,
				struct test_mcfg_table *mcfg)
{
	*rsdp = (EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER){0};
	rsdp->signature = EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE;
	rsdp->revision = 2;
	rsdp->length = sizeof(*rsdp);
	rsdp->xsdt_address = (UINT64)(UINTN)xsdt;

	*xsdt = (struct test_acpi_root){0};
	xsdt->header.signature = EFI_ACPI_3_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE;
	xsdt->header.length = sizeof(*xsdt);
	xsdt->entries[0] = (UINT64)(UINTN)fadt;
	xsdt->entries[1] = (UINT64)(UINTN)&mcfg->header;

	*fadt = (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE){0};
	fadt->header.signature = EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE;
	fadt->header.length = sizeof(*fadt);
	fadt->gpe0_blk_len = 2;

	*mcfg = (struct test_mcfg_table){0};
	mcfg->header.header.signature =
		EFI_ACPI_6_6_PCI_EXPRESS_MEMORY_MAPPED_CONFIGURATION_SPACE_BASE_ADDRESS_DESCRIPTION_TABLE_SIGNATURE;
	mcfg->header.header.length = sizeof(*mcfg);
	mcfg->allocation.base_address = 0xe0000000ULL;
	mcfg->allocation.start_bus_number = 0;
	mcfg->allocation.end_bus_number = 0xff;

	test_update_acpi_table_checksum(&fadt->header);
	test_update_acpi_table_checksum(&mcfg->header.header);
	test_update_acpi_table_checksum(&xsdt->header);
	test_update_rsdp_checksums(rsdp);
}

static UINTN build_tpm_spec_event(UINT8 *event_log)
{
	TCG_PCR_EVENT_HDR header;
	UINT32 event_size;

	header = (TCG_PCR_EVENT_HDR){0};
	header.event_type = EV_NO_ACTION;
	header.event_size = sizeof(TEST_TPM_SPEC_ID_EVENT_NAME) - 1U;
	memcpy(event_log, &header, sizeof(header));
	event_size = header.event_size;
	memcpy(event_log + sizeof(header), TEST_TPM_SPEC_ID_EVENT_NAME, event_size);
	return sizeof(header) + event_size;
}

static UINTN append_tpm_event2(UINT8 *event_log, UINTN offset, UINT32 pcr_index,
			     const char *event_data)
{
	UINT32 event_type;
	UINT32 digest_count;
	UINT32 event_data_size;
	UINT16 hash_alg;

	event_type = EV_NO_ACTION;
	digest_count = 1;
	event_data_size = (UINT32)strlen(event_data);
	hash_alg = TPM_ALG_SHA256;

	memcpy(event_log + offset, &pcr_index, sizeof(pcr_index));
	offset += sizeof(pcr_index);
	memcpy(event_log + offset, &event_type, sizeof(event_type));
	offset += sizeof(event_type);
	memcpy(event_log + offset, &digest_count, sizeof(digest_count));
	offset += sizeof(digest_count);
	memcpy(event_log + offset, &hash_alg, sizeof(hash_alg));
	offset += sizeof(hash_alg);
	memset(event_log + offset, 0xa5, SHA256_DIGEST_SIZE);
	offset += SHA256_DIGEST_SIZE;
	memcpy(event_log + offset, &event_data_size, sizeof(event_data_size));
	offset += sizeof(event_data_size);
	memcpy(event_log + offset, event_data, event_data_size);
	return offset + event_data_size;
}

int main(void)
{
	UINT8 storage[TEST_TABLE_SIZE];
	UINT8 forward_storage[TEST_TABLE_SIZE];
	UINT8 target_storage[TEST_TABLE_SIZE];
	UINT8 hob_storage[TEST_TABLE_SIZE];
	UINT8 tiny_hob_storage[64];
	UINT8 transaction_hob_storage[512];
	UINT8 legacy_cbmem_storage[DYN_CBMEM_ALIGN_SIZE];
	UINT8 tpm_event_log[TEST_TPM_EVENT_LOG_SIZE];
	UINT8 smbios2_entry[0x20];
	UINT8 smbios3_entry[0x20];
	struct cdk2_coreboot_handoff handoff;
	struct cdk2_coreboot_handoff transaction_handoff;
	struct cdk2_coreboot_test_cbmem_result found_cbmem;
	struct cbmem_root *legacy_root;
	struct imd_root *legacy_imd_root;
	EFI_HOB_HANDOFF_INFO_TABLE *hob_info;
	EFI_HOB_HANDOFF_INFO_TABLE *transaction_hob;
	EFI_HOB_GENERIC_HEADER *hob;
	EFI_HOB_GENERIC_HEADER previous_end_marker;
	EFI_HOB_GENERIC_HEADER transaction_end_marker;
	EFI_PEI_HOB_POINTERS hob_walker;
	UINTN hob_cursor;
	UINTN resource_count;
	UINTN allocation_count;
	UINTN stack_count;
	UINTN cpu_count;
	UINTN guid_count;
	UINTN pcr0_count;
	UINTN pcr1_count;
	UINTN unexpected_pcr_count;
	UINTN high_ram_resource_count;
	UINTN clipped_ram_resource_count;
	UINTN api_guid_count;
	UINTN payload_resource_guid_count;
	UINTN payload_resource_guid_address;
	UINTN tight_payload_resource_free_top;
	UINTN smbios2_guid_count;
	UINTN smbios3_guid_count;
	UINTN walker_count;
	UINTN code_allocation_count;
	UINTN module_count;
	EFI_PHYSICAL_ADDRESS previous_end_of_hob_list;
	EFI_PHYSICAL_ADDRESS previous_free_memory_bottom;
	EFI_PHYSICAL_ADDRESS bad_free_memory_bottom;
	EFI_PHYSICAL_ADDRESS transaction_end_of_hob_list;
	EFI_PHYSICAL_ADDRESS transaction_free_memory_bottom;
	EFI_PHYSICAL_ADDRESS transaction_free_memory_top;
	UINTN table_size;
	UINTN hob_mem_base;
	UINTN transaction_free_top_offset;
	const void *record;
	const struct cb_payload_resource_section *prh_section;
	const struct cb_serial *serial;
	const struct cb_framebuffer *framebuffer;
	struct cb_payload_resource_handoff oversized_prh;
	EFI_HOB_RESOURCE_DESCRIPTOR *resource;
	EFI_GUID test_guid;
	EFI_GUID payload_resource_guid;
	EFI_GUID stack_guid;
	EFI_GUID module_guid;
	EFI_GUID dxe_core_guid;
	EFI_GUID zero_guid;
	EFI_GUID tcg_event_guid;
	EFI_GUID smbios_table_guid;
	EFI_GUID smbios3_table_guid;
	EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER rsdp;
	struct test_acpi_root xsdt;
	EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE fadt;
	struct test_mcfg_table mcfg;
	ACPI_BOARD_INFO board_info;
	struct test_tpm2_table tpm2_table;
	UNIVERSAL_PAYLOAD_SMBIOS_TABLE *smbios_table;
	UINT8 test_data[4];
	struct cdk2_native_context transfer_context;
	EFI_HOB_HANDOFF_INFO_TABLE *transfer_hob;
	EFI_HOB_GENERIC_HEADER *transfer_end;
	EFI_PHYSICAL_ADDRESS transfer_free_bottom;
	EFI_PHYSICAL_ADDRESS transfer_free_top;
	EFI_STATUS status;
	int failures;

	failures = 0;
	payload_resource_guid = (EFI_GUID){
		0xc263a6a9, 0x6938, 0x495e, {0x95, 0xb6, 0x6a, 0x1a, 0x0b, 0x6b, 0xa8, 0x8e}
	};
	tcg_event_guid = (EFI_GUID){
		0xd26c221e, 0x2430, 0x4c8a, {0x91, 0x70, 0x3f, 0xcb, 0x45, 0x00, 0x41, 0x3f}
	};
	smbios_table_guid = (EFI_GUID){
		0x590a0d26, 0x06e5, 0x4d20, {0x8a, 0x82, 0x59, 0xea, 0x1b, 0x34, 0x98, 0x2d}
	};
	smbios3_table_guid = (EFI_GUID){
		0x92b7896c, 0x3362, 0x46ce, {0x99, 0xb3, 0x4f, 0x5e, 0x3c, 0x34, 0xeb, 0x42}
	};
	table_size = build_memory_table(storage, sizeof(storage));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "valid table rejected");
	failures += expect(handoff.record_count == 2, "record count is wrong");
	failures += expect(handoff.memory_range_count == 3, "memory range count is wrong");
	failures += expect(handoff.usable_ram_count == 1, "usable RAM count is wrong");
	failures +=
		expect(handoff.largest_usable_ram_base == 0x00100000, "usable RAM base is wrong");
	failures +=
		expect(handoff.largest_usable_ram_size == 0x00300000, "usable RAM size is wrong");
	failures += expect(handoff.payload_resource_handoff_status == EFI_NOT_FOUND,
			   "absent payload-resource record status is wrong");
	status = cdk2_coreboot_find_payload_resource_section(
		&handoff, CB_PRH_SECTION_MEMORY_POLICY, &prh_section);
	failures += expect(status == EFI_NOT_FOUND,
			   "absent payload-resource section did not fall back");

	memset(legacy_cbmem_storage, 0, sizeof(legacy_cbmem_storage));
	legacy_root = (struct cbmem_root *)(void *)legacy_cbmem_storage;
	legacy_root->max_entries = 4;
	legacy_root->num_entries = 1;
	legacy_root->entries[0].magic = CBMEM_ENTRY_MAGIC;
	legacy_root->entries[0].start = 0x12345000;
	legacy_root->entries[0].size = 0x20;
	legacy_root->entries[0].id = CBMEM_ID_SMBIOS;
	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 1;
	handoff.memory_ranges[0].base = (EFI_PHYSICAL_ADDRESS)(UINTN)legacy_cbmem_storage;
	handoff.memory_ranges[0].size = sizeof(legacy_cbmem_storage);
	handoff.memory_ranges[0].type = CB_MEM_TABLE;
	found_cbmem = cdk2_coreboot_test_find_cbmem_entry(&handoff, CBMEM_ID_SMBIOS, 1);
	failures += expect(found_cbmem.status == EFI_SUCCESS, "legacy CBMEM root lookup failed");
	failures += expect(found_cbmem.base == 0x12345000, "legacy CBMEM base is wrong");
	failures += expect(found_cbmem.size == 0x20, "legacy CBMEM size is wrong");

	memset(legacy_cbmem_storage, 0, sizeof(legacy_cbmem_storage));
	legacy_imd_root = (struct imd_root *)(void *)legacy_cbmem_storage;
	legacy_imd_root->max_entries = 4;
	legacy_imd_root->num_entries = 1;
	legacy_imd_root->entries[0].magic = IMD_ENTRY_MAGIC;
	legacy_imd_root->entries[0].start_offset = 0x80;
	legacy_imd_root->entries[0].size = 0x30;
	legacy_imd_root->entries[0].id = CBMEM_ID_ACPI;
	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 1;
	handoff.memory_ranges[0].base = (EFI_PHYSICAL_ADDRESS)(UINTN)legacy_cbmem_storage;
	handoff.memory_ranges[0].size = sizeof(legacy_cbmem_storage);
	handoff.memory_ranges[0].type = CB_MEM_TABLE;
	found_cbmem = cdk2_coreboot_test_find_cbmem_entry(&handoff, CBMEM_ID_ACPI, 1);
	failures += expect(found_cbmem.status == EFI_SUCCESS, "legacy IMD root lookup failed");
	failures += expect(found_cbmem.base ==
				   (EFI_PHYSICAL_ADDRESS)(UINTN)(legacy_cbmem_storage + 0x80),
			   "legacy IMD base is wrong");
	failures += expect(found_cbmem.size == 0x30, "legacy IMD size is wrong");

	memset(legacy_cbmem_storage, 0, sizeof(legacy_cbmem_storage));
	build_test_acpi_tables(&rsdp, &xsdt, &fadt, &mcfg);
	rsdp.revision = 0;
	test_update_rsdp_checksums(&rsdp);
	memcpy(legacy_cbmem_storage + 0x80, &rsdp,
	       OFFSET_OF(EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER, length));
	legacy_imd_root = (struct imd_root *)(void *)legacy_cbmem_storage;
	legacy_imd_root->max_entries = 4;
	legacy_imd_root->num_entries = 1;
	legacy_imd_root->entries[0].magic = IMD_ENTRY_MAGIC;
	legacy_imd_root->entries[0].start_offset = 0x80;
	legacy_imd_root->entries[0].size =
		OFFSET_OF(EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER, length);
	legacy_imd_root->entries[0].id = CBMEM_ID_ACPI;
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "ACPI 1.0 CBMEM fallback table rejected");
	handoff.memory_range_count = 1;
	handoff.memory_ranges[0].base = (EFI_PHYSICAL_ADDRESS)(UINTN)legacy_cbmem_storage;
	handoff.memory_ranges[0].size = sizeof(legacy_cbmem_storage);
	handoff.memory_ranges[0].type = CB_MEM_TABLE;
	found_cbmem = cdk2_coreboot_test_find_acpi_rsdp(&handoff);
	failures += expect(found_cbmem.status == EFI_SUCCESS,
			   "ACPI 1.0 CBMEM RSDP lookup failed");
	failures += expect(found_cbmem.base ==
				   (EFI_PHYSICAL_ADDRESS)(UINTN)(legacy_cbmem_storage + 0x80),
			   "ACPI 1.0 CBMEM RSDP base is wrong");

	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "valid table reparse rejected");
	status = cdk2_coreboot_find_record(&handoff, CB_TAG_MEMORY, sizeof(struct cb_memory),
					   &record);
	failures += expect(status == EFI_SUCCESS && record != NULL, "record lookup failed");
	status = cdk2_coreboot_find_record(
		&handoff, CB_TAG_MEMORY,
		sizeof(struct cb_memory) + 4 * sizeof(struct cb_memory_range), &record);
	failures += expect(status == EFI_COMPROMISED_DATA, "short record was accepted");

	table_size = build_extended_header_memory_table(storage, sizeof(storage));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "extended-header table rejected");
	failures += expect(handoff.table_size == table_size, "extended-header table size is wrong");
	failures += expect(handoff.memory_range_count == 1, "extended-header memory count is wrong");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_valid);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "valid payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "valid payload-resource record was not accepted");
	status = cdk2_coreboot_find_payload_resource_section(
		&handoff, CB_PRH_SECTION_MEMORY_POLICY, &prh_section);
	failures += expect(status == EFI_SUCCESS && prh_section != NULL &&
				   prh_section->entry_count == 2,
			   "payload-resource memory policy section lookup failed");
	status = cdk2_coreboot_find_payload_resource_section(
		&handoff, CB_PRH_SECTION_FRAMEBUFFER, &prh_section);
	failures += expect(status == EFI_SUCCESS && prh_section != NULL &&
				   prh_section->entry_count == 1,
			   "payload-resource framebuffer section lookup failed");
	status = cdk2_coreboot_find_payload_resource_section(&handoff, TEST_PRH_UNKNOWN_SECTION,
							     &prh_section);
	failures += expect(status == EFI_SUCCESS && prh_section != NULL,
			   "skippable unknown payload-resource section rejected");
	status = cdk2_coreboot_find_payload_resource_section(
		&handoff, CB_PRH_SECTION_RUNTIME_POLICY, &prh_section);
	failures +=
		expect(status == EFI_NOT_FOUND, "missing payload-resource section was found");

	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "payload-resource HOB construction failed");
	payload_resource_guid_count = 0;
	payload_resource_guid_address = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			EFI_HOB_GUID_TYPE *guid_hob;
			UINTN data_length;

			guid_hob = (EFI_HOB_GUID_TYPE *)(void *)hob;
			data_length = hob->hob_length - sizeof(*guid_hob);
			if (memcmp(&guid_hob->name, &payload_resource_guid,
				   sizeof(payload_resource_guid)) == 0) {
				failures += expect(
					data_length >= handoff.payload_resource_handoff->size &&
						memcmp(guid_hob + 1,
						       handoff.payload_resource_handoff,
						       handoff.payload_resource_handoff->size) ==
							0,
					"payload-resource GUID HOB data is wrong");
				payload_resource_guid_address = hob_cursor;
				payload_resource_guid_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(payload_resource_guid_count == 1,
			   "payload-resource GUID HOB count is wrong");

	if (payload_resource_guid_address != 0) {
		tight_payload_resource_free_top =
			payload_resource_guid_address + sizeof(EFI_HOB_GENERIC_HEADER);
		status = cdk2_coreboot_build_hobs(
			&handoff, hob_storage, hob_storage + sizeof(hob_storage), hob_storage,
			(void *)tight_payload_resource_free_top, FALSE, (void **)&hob_info);
		failures +=
			expect(status == EFI_OUT_OF_RESOURCES,
			       "tight payload-resource HOB space was silently dropped");
	}

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_extended_mtrr_entries);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS, "extended-MTRR payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "extended-MTRR payload-resource record was not accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_default_type_coverage);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS, "default-MTRR payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "default-MTRR payload-resource record was not accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_overlap_precedence);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "overlapping-MTRR payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "overlapping-MTRR payload-resource record was not accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache4_k_variable_mtrr);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "4K-MTRR payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "4K-MTRR payload-resource record was not accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_physical_address_bits36);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS, "36-bit MTRR payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "36-bit MTRR payload-resource record was not accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_oem_os_type);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "OEM memory type payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "OEM memory type payload-resource record was not accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_oem_os_mmio_type);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "OEM MMIO memory type payload-resource table rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "OEM MMIO memory type payload-resource record was accepted");

	memset(&oversized_prh, 0, sizeof(oversized_prh));
	oversized_prh.size = MAX_UINT16;
	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.payload_resource_handoff_status = EFI_SUCCESS;
	handoff.payload_resource_handoff = &oversized_prh;
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_OUT_OF_RESOURCES,
			   "oversized payload-resource HOB was silently dropped");

	memset(&oversized_prh, 0, sizeof(oversized_prh));
	oversized_prh.size = MAX_UINT16 - sizeof(EFI_HOB_GUID_TYPE) - 3U;
	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.payload_resource_handoff_status = EFI_SUCCESS;
	handoff.payload_resource_handoff = &oversized_prh;
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_OUT_OF_RESOURCES,
			   "aligned payload-resource HOB overflow was silently dropped");

	table_size = build_memory_and_payload_resource_handoff_table(storage, sizeof(storage),
							      test_prh_valid);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS, "memory-covered payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "memory-covered payload-resource record was not accepted");

	table_size = build_memory_and_payload_resource_handoff_table(storage, sizeof(storage),
							      test_prh_memory_split_coverage);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "split memory-covered payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "split memory-covered payload-resource record was not accepted");

	table_size = build_memory_and_payload_resource_handoff_table(storage, sizeof(storage),
							      test_prh_memory_gcd_coverage);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "GCD-only memory-covered payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "GCD-only memory-covered payload-resource record was not accepted");

	table_size = build_memory_and_payload_resource_handoff_table(storage, sizeof(storage),
							      test_prh_memory_delegated_coverage);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "delegated memory-covered payload-resource table rejected");
	failures += expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
				   handoff.payload_resource_handoff != NULL,
			   "delegated memory-covered payload-resource record was not accepted");

	table_size = build_memory_and_payload_resource_handoff_table(storage, sizeof(storage),
							      test_prh_cache_coverage_gap);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "payload-resource coverage gap rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "payload-resource cache-policy coverage gap was accepted");

	table_size = build_memory_and_payload_resource_handoff_table(storage, sizeof(storage),
							      test_prh_memory_gcd_coverage_gap);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "payload-resource GCD coverage gap rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "payload-resource GCD coverage gap was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_bad_crc);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "bad payload-resource CRC rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_CRC_ERROR &&
				   handoff.payload_resource_handoff == NULL,
			   "bad payload-resource CRC did not disable only the new ABI");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "bad payload-resource HOB fallback failed");
	payload_resource_guid_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			EFI_HOB_GUID_TYPE *guid_hob;

			guid_hob = (EFI_HOB_GUID_TYPE *)(void *)hob;
			if (memcmp(&guid_hob->name, &payload_resource_guid,
				   sizeof(payload_resource_guid)) == 0) {
				payload_resource_guid_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(payload_resource_guid_count == 0,
			   "bad payload-resource record published a HOB");

	table_size =
		build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_short_header);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "short payload-resource header rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "short payload-resource header was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_section_overflow);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "overflowing payload-resource section rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "overflowing payload-resource section was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_unknown_mandatory);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "mandatory unknown payload-resource section rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "mandatory unknown payload-resource section was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_known_mandatory);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "deferred payload-resource section rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "deferred mandatory payload-resource section was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_section_overlap);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "overlapping payload-resource sections rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "overlapping payload-resource sections were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_duplicate_type);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "duplicate payload-resource section types rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "duplicate payload-resource section types were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_unknown_duplicate_optional);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(
		status == EFI_SUCCESS,
		"duplicate unknown optional payload-resource sections rejected the whole table");
	failures +=
		expect(handoff.payload_resource_handoff_status == EFI_SUCCESS &&
			       handoff.payload_resource_handoff != NULL,
		       "duplicate unknown optional payload-resource sections were not skipped");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_zero_length);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "zero-length payload-resource memory range rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "zero-length payload-resource memory range was accepted");

	table_size =
		build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_memory_wrap);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "wrapping payload-resource memory range rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "wrapping payload-resource memory range was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_overlap);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "overlapping payload-resource memory ranges rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "overlapping payload-resource memory ranges were accepted");

	table_size = build_payload_resource_handoff_table(
		m_large_test_storage, sizeof(m_large_test_storage), test_prh_memory_policy_limit);
	status = cdk2_coreboot_parse_table(m_large_test_storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "oversized payload-resource memory policy rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "oversized payload-resource memory policy was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_count_mismatch);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS, "bad x86 cache payload rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "bad x86 cache payload was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_missing_lifetime);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "missing payload-resource lifetime rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "missing payload-resource lifetime was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_protection_no_paging);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "payload-resource paging contract gap rejected the whole table");
	failures += expect(
		handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
			handoff.payload_resource_handoff == NULL,
		"payload-resource protection ownership was accepted without paging proof");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_runtime_unaligned);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "unaligned runtime memory rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "unaligned runtime memory was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_framebuffer_bad_mask);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "bad payload-resource framebuffer rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "bad payload-resource framebuffer was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_framebuffer_overlap_mask);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(
		status == EFI_SUCCESS,
		"overlapping payload-resource framebuffer masks rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "overlapping payload-resource framebuffer masks were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_framebuffer_mask_past_bpp);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "past-bpp payload-resource framebuffer mask rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "past-bpp payload-resource framebuffer mask was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_framebuffer_no_resource_proof);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "unbacked payload-resource framebuffer rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "unbacked payload-resource framebuffer was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_framebuffer_system_memory_policy);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "system-memory payload-resource framebuffer rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "system-memory payload-resource framebuffer was accepted");

	table_size =
		build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_pci_bad_bar);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "bad payload-resource PCI BAR rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "bad payload-resource PCI BAR was accepted");

	table_size =
		build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_pci_duplicate);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "duplicate payload-resource PCI BAR rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "duplicate payload-resource PCI BAR was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_pci_assignment_overlap);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "overlapping payload-resource PCI assignment rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "overlapping payload-resource PCI assignment was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_pci_outside_bridge);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(
		status == EFI_SUCCESS,
		"out-of-window payload-resource PCI assignment rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "out-of-window payload-resource PCI assignment was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_pci_root_overlap);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "overlapping payload-resource PCI roots rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "overlapping payload-resource PCI roots were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_pci_upper_slot_collision);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "payload-resource PCI upper BAR collision rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "payload-resource PCI upper BAR collision was accepted");

	table_size =
		build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_pci64_bar5);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "payload-resource PCI 64-bit BAR5 rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "payload-resource PCI 64-bit BAR5 was accepted");

	table_size = build_payload_resource_handoff_table(
		m_large_test_storage, sizeof(m_large_test_storage), test_prh_pci_assignment_limit);
	status = cdk2_coreboot_parse_table(m_large_test_storage, table_size, &handoff);
	failures += expect(
		status == EFI_SUCCESS,
		"oversized payload-resource PCI assignment list rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "oversized payload-resource PCI assignment list was accepted");

	table_size =
		build_payload_resource_handoff_table(storage, sizeof(storage), test_prh_pci_zero_base);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "zero-base payload-resource PCI BAR rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "zero-base payload-resource PCI BAR was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_attributes_exceed_capabilities);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(
		status == EFI_SUCCESS,
		"impossible payload-resource memory attributes rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "impossible payload-resource memory attributes were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_unsupported_revision);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "future payload-resource revision rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "future payload-resource revision was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_unsupported_flags);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "unknown payload-resource flags rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "unknown payload-resource flags were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_unknown_lifetime_bit);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "unknown payload-resource lifetime bit rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "unknown payload-resource lifetime bit was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_unsupported_attributes);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(
		status == EFI_SUCCESS,
		"unsupported payload-resource memory attributes rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "unsupported payload-resource memory attributes were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_bad_gcd_type);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "unsupported payload-resource GCD type rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "unsupported payload-resource GCD type was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_bad_gcd_efi_type);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "conflicting payload-resource GCD/EFI type rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "conflicting payload-resource GCD/EFI type was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_authority_without_section);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(
		status == EFI_SUCCESS,
		"entry-authoritative non-authoritative memory section rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "entry-authoritative non-authoritative memory section was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_memory_multiple_cache_attributes);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "ambiguous payload-resource cache attributes rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "ambiguous payload-resource cache attributes were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_mtrr_mismatch);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "payload-resource cache/MTRR mismatch rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "payload-resource cache/MTRR mismatch was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_bad_pat_slot);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "bad payload-resource PAT rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "bad payload-resource PAT was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_bad_pat_without_cache_policy);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "unreferenced bad payload-resource PAT rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "unreferenced bad payload-resource PAT was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_bad_default_type);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "bad default MTRR rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "bad default MTRR was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_fixed_default_range);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "fixed-range default MTRR rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "fixed-range default MTRR was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_fixed_enabled_without_state);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "fixed-enabled MTRR without state rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "fixed-enabled MTRR without state was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_inactive_bad_base);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "inactive variable MTRR with bad base rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "inactive variable MTRR with bad base was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_range_beyond_physical_bits);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "out-of-width default MTRR range rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "out-of-width default MTRR range was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_cache_s3_without_lifetime);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "S3 cache state without S3 lifetime rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "S3 cache state without S3 lifetime was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_s3_missing_generation);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "S3 payload-resource without generation rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "S3 payload-resource without generation was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_s3_cache_not_valid);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "S3 payload-resource without S3 cache proof rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "S3 payload-resource without S3 cache proof was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_s3_unsupported);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "S3-valid payload-resource rejected the whole table");
	failures +=
		expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
			       handoff.payload_resource_handoff == NULL,
		       "S3-valid payload-resource was accepted without generation comparison");

	table_size = build_payload_resource_handoff_table(
		storage, sizeof(storage), test_prh_pci_assignment_without_authoritative_root);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "PCI assignment without authoritative root rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "PCI assignment without authoritative root was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_pci_mmio32_above4_gb);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "above-4GB payload-resource PCI MMIO32 rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "above-4GB payload-resource PCI MMIO32 was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_pci_root_mem32_above4_gb);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures +=
		expect(status == EFI_SUCCESS,
		       "above-4GB payload-resource PCI root MMIO32 rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "above-4GB payload-resource PCI root MMIO32 was accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_pci_io_attributes);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "payload-resource PCI I/O attributes rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_COMPROMISED_DATA &&
				   handoff.payload_resource_handoff == NULL,
			   "payload-resource PCI I/O attributes were accepted");

	table_size = build_payload_resource_handoff_table(storage, sizeof(storage),
						     test_prh_runtime_policy_reserved);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS,
			   "reserved payload-resource runtime policy rejected the whole table");
	failures += expect(handoff.payload_resource_handoff_status == EFI_UNSUPPORTED &&
				   handoff.payload_resource_handoff == NULL,
			   "reserved payload-resource runtime policy was accepted");

	table_size = build_legacy_serial_table(storage, sizeof(storage));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "legacy serial table rejected");
	status = cdk2_coreboot_find_record(&handoff, CB_TAG_SERIAL,
					   CDK2_COREBOOT_SERIAL_MIN_SIZE, &record);
	failures +=
		expect(status == EFI_SUCCESS && record != NULL, "legacy serial lookup failed");
	serial = (const struct cb_serial *)record;
	failures +=
		expect(serial->type == CB_SERIAL_TYPE_IO_MAPPED, "legacy serial type is wrong");
	failures += expect(serial->baseaddr == 0x3f8, "legacy serial base is wrong");
	failures += expect(serial->baud == 115200, "legacy serial baud is wrong");
	failures += expect(serial->regwidth == 1, "legacy serial regwidth is wrong");
	status = cdk2_coreboot_find_record(
		&handoff, CB_TAG_SERIAL,
		CDK2_COREBOOT_RECORD_FIELD_END(struct cb_serial, input_hertz), &record);
	failures += expect(status == EFI_COMPROMISED_DATA, "legacy serial exposed input_hertz");

	table_size = build_legacy_framebuffer_table(storage, sizeof(storage));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "legacy framebuffer table rejected");
	status = cdk2_coreboot_find_record(&handoff, CB_TAG_FRAMEBUFFER,
					   CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE, &record);
	failures += expect(status == EFI_SUCCESS && record != NULL,
			   "legacy framebuffer lookup failed");
	framebuffer = (const struct cb_framebuffer *)record;
	failures += expect(framebuffer->physical_address == 0xfd000000ULL,
			   "legacy framebuffer base is wrong");
	failures +=
		expect(framebuffer->x_resolution == 1024, "legacy framebuffer width is wrong");
	failures +=
		expect(framebuffer->y_resolution == 768, "legacy framebuffer height is wrong");
	failures += expect(framebuffer->bytes_per_line == 4096,
			   "legacy framebuffer stride is wrong");
	failures +=
		expect(framebuffer->bits_per_pixel == 32, "legacy framebuffer bpp is wrong");
	failures +=
		expect(framebuffer->red_mask_pos == 16, "legacy framebuffer red mask is wrong");
	failures += expect(framebuffer->blue_mask_pos == 0,
			   "legacy framebuffer blue mask is wrong");
	status = cdk2_coreboot_find_record(&handoff, CB_TAG_FRAMEBUFFER,
					   CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE + 1, &record);
	failures += expect(status == EFI_COMPROMISED_DATA,
			   "legacy framebuffer exposed trailing bytes");
	status = cdk2_coreboot_test_validate_framebuffer(framebuffer);
	failures += expect(status == EFI_SUCCESS, "valid legacy framebuffer rejected");
	((struct cb_framebuffer *)(void *)framebuffer)->bits_per_pixel = 24;
	((struct cb_framebuffer *)(void *)framebuffer)->bytes_per_line = 4100;
	status = cdk2_coreboot_test_validate_framebuffer(framebuffer);
	failures += expect(status == EFI_COMPROMISED_DATA,
			   "non-integral legacy framebuffer stride accepted");
	table_size = build_legacy_framebuffer_table(storage, sizeof(storage));

	status = cdk2_coreboot_parse_table(storage, table_size - 1, &handoff);
	failures += expect(status == EFI_COMPROMISED_DATA, "truncated table accepted");

	((struct cb_header *)(void *)storage)->table_checksum ^= 1;
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad checksum accepted");
	table_size = build_memory_table(storage, sizeof(storage));

	((struct cb_header *)(void *)storage)->table_bytes = CDK2_COREBOOT_MAX_TABLE_BYTES + 1;
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_COMPROMISED_DATA, "oversized table accepted");
	table_size = build_memory_table(storage, sizeof(storage));

	((struct cb_memory *)(void *)(storage + sizeof(struct cb_header)))->size =
		sizeof(struct cb_record);
	((struct cb_header *)(void *)storage)->table_checksum =
		cdk2_coreboot_checksum16(storage + sizeof(struct cb_header),
					 ((struct cb_header *)(void *)storage)->table_bytes);
	((struct cb_header *)(void *)storage)->header_checksum = 0;
	((struct cb_header *)(void *)storage)->header_checksum =
		cdk2_coreboot_checksum16(storage, sizeof(struct cb_header));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_COMPROMISED_DATA, "short memory record accepted");

	table_size = build_memory_table(target_storage, sizeof(target_storage));
	(void)table_size;
	build_forward_table(forward_storage, sizeof(forward_storage), target_storage);
	status = cdk2_coreboot_parse((UINTN)(void *)forward_storage, &handoff);
	failures += expect(status == EFI_SUCCESS, "forward table rejected");
	failures += expect(handoff.memory_range_count == 3, "forward target was not parsed");

	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), TRUE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "HOB construction failed");
	failures += expect(hob_info != NULL && hob_info->header.hob_type == EFI_HOB_TYPE_HANDOFF,
			   "PHIT is missing");
	failures += expect(hob_info->boot_mode == BOOT_ON_FLASH_UPDATE,
			   "coreboot boot mode not applied");

	table_size = build_boot_mode_table(storage, sizeof(storage), LB_BOOT_MODE_NORMAL);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "normal boot-mode table rejected");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), TRUE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "normal coreboot boot mode rejected");
	failures += expect(hob_info != NULL &&
				   hob_info->boot_mode == BOOT_WITH_FULL_CONFIGURATION,
			   "normal coreboot boot mode was not preserved");

	table_size = build_boot_mode_table(storage, sizeof(storage), LB_BOOT_MODE_LOW_BATTERY);
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "low-battery boot-mode table rejected");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), TRUE,
					  (void **)&hob_info);
	failures += expect(status == EFI_UNSUPPORTED,
			   "unsupported coreboot boot mode was accepted");

	table_size = build_memory_table(storage, sizeof(storage));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "valid table restore rejected");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), TRUE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "restored HOB construction failed");

	resource_count = 0;
	resource = NULL;
	hob_cursor = (UINTN)(void *)hob_info;
	while (hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		failures += expect(hob->hob_length >= sizeof(*hob), "HOB length is invalid");
		if (hob->hob_type == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
			resource_count++;
			resource = (EFI_HOB_RESOURCE_DESCRIPTOR *)(void *)hob;
			if (resource_count == 1) {
				failures += expect(resource->resource_type ==
							   EFI_RESOURCE_SYSTEM_MEMORY,
						   "RAM resource type is wrong");
			} else if (resource_count == 2) {
				failures += expect(resource->resource_type ==
							   EFI_RESOURCE_MEMORY_RESERVED,
						   "reserved resource type is wrong");
			} else if (resource_count == 3) {
				failures += expect(resource->resource_type ==
							   EFI_RESOURCE_MEMORY_RESERVED,
						   "coreboot table resource type is wrong");
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_info->efi_end_of_hob_list;
	failures += expect(hob->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST,
			   "HOB list has no end marker");
	failures += expect(resource_count == 3, "resource HOB count is wrong");
	failures += expect(hob_info->efi_free_memory_bottom > hob_info->efi_end_of_hob_list,
			   "HOB allocator did not advance");

	status = cdk2_coreboot_append_memory_allocation_hob(
		hob_info, (EFI_PHYSICAL_ADDRESS)(UINTN)storage, sizeof(storage),
		efi_boot_services_data);
	failures += expect(status == EFI_SUCCESS, "payload allocation HOB failed");
	status = cdk2_coreboot_append_stack_hob(hob_info, 0x00200000, EFI_PAGE_SIZE);
	failures += expect(status == EFI_SUCCESS, "stack allocation HOB failed");
	status = cdk2_coreboot_append_cpu_hob(hob_info, 36, 16);
	failures += expect(status == EFI_SUCCESS, "CPU HOB failed");

	allocation_count = 0;
	stack_count = 0;
	cpu_count = 0;
	stack_guid = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_STACK_GUID;
	zero_guid = (EFI_GUID){0};
	hob_cursor = (UINTN)(void *)hob_info;
	while (hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
			EFI_HOB_MEMORY_ALLOCATION *allocation;

			allocation = (EFI_HOB_MEMORY_ALLOCATION *)(void *)hob;
			allocation_count++;
			if (memcmp(&allocation->alloc_descriptor.name, &stack_guid,
				   sizeof(stack_guid)) == 0) {
				stack_count++;
			} else {
				failures += expect(memcmp(&allocation->alloc_descriptor.name,
							  &zero_guid, sizeof(zero_guid)) == 0,
						   "generic allocation HOB has an owner GUID");
			}
		} else if (hob->hob_type == EFI_HOB_TYPE_CPU) {
			cpu_count++;
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}
	failures += expect(allocation_count == 2, "allocation HOB count is wrong");
	failures += expect(stack_count == 1, "stack HOB owner GUID is wrong");
	failures += expect(cpu_count == 1, "CPU HOB count is wrong");

	dxe_core_guid = (EFI_GUID){
		0x86d70125, 0xbaa3, 0x4296, {0xa6, 0x2f, 0x60, 0x2b, 0xeb, 0xbb, 0x90, 0x8e}
	};
	status = cdk2_coreboot_append_memory_allocation_hob(
		hob_info, 0x00400000, 2 * EFI_PAGE_SIZE, efi_boot_services_code);
	failures += expect(status == EFI_SUCCESS, "loaded-image allocation HOB failed");
	status = cdk2_coreboot_append_module_hob(hob_info, &dxe_core_guid, 0x00400000,
						 2 * EFI_PAGE_SIZE, 0x00401000);
	failures += expect(status == EFI_SUCCESS, "module HOB failed");

	code_allocation_count = 0;
	module_count = 0;
	module_guid = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_MODULE_GUID;
	hob_cursor = (UINTN)(void *)hob_info;
	while (hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
			EFI_HOB_MEMORY_ALLOCATION *allocation;
			EFI_HOB_MEMORY_ALLOCATION_MODULE *module;

			allocation = (EFI_HOB_MEMORY_ALLOCATION *)(void *)hob;
			if (allocation->alloc_descriptor.memory_base_address == 0x00400000 &&
			    allocation->alloc_descriptor.memory_length == 2 * EFI_PAGE_SIZE) {
				if (memcmp(&allocation->alloc_descriptor.name, &zero_guid,
					   sizeof(zero_guid)) == 0) {
					failures +=
						expect(allocation->alloc_descriptor.memory_type ==
							       efi_boot_services_code,
						       "loaded-image allocation type is wrong");
					code_allocation_count++;
				} else if (memcmp(&allocation->alloc_descriptor.name,
						  &module_guid, sizeof(module_guid)) == 0) {
					module =
						(EFI_HOB_MEMORY_ALLOCATION_MODULE *)(void *)hob;
					failures += expect(
						module->memory_allocation_header.memory_type ==
							efi_boot_services_code,
						"module allocation type is wrong");
					failures +=
						expect(memcmp(&module->module_name, &dxe_core_guid,
							      sizeof(dxe_core_guid)) == 0,
						       "module name is wrong");
					failures += expect(module->entry_point == 0x00401000,
							   "module entry point is wrong");
					module_count++;
				}
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}
	failures +=
		expect(code_allocation_count == 1, "loaded-image allocation HOB count is wrong");
	failures += expect(module_count == 1, "loaded-image module HOB count is wrong");

	test_guid = (EFI_GUID){
		0x12345678, 0x9abc, 0xdef0, {1, 2, 3, 4, 5, 6, 7, 8}
	};
	test_data[0] = 0xaa;
	test_data[1] = 0xbb;
	test_data[2] = 0xcc;
	test_data[3] = 0xdd;
	status = cdk2_coreboot_append_guid_hob(hob_info, &test_guid, test_data, sizeof(test_data));
	failures += expect(status == EFI_SUCCESS, "GUID HOB construction failed");

	guid_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			EFI_HOB_GUID_TYPE *guid_hob;

			guid_hob = (EFI_HOB_GUID_TYPE *)(void *)hob;
			if (memcmp(&guid_hob->name, &test_guid, sizeof(test_guid)) == 0 &&
			    memcmp(guid_hob + 1, test_data, sizeof(test_data)) == 0) {
				guid_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}
	failures += expect(guid_count == 1, "GUID HOB data is wrong");

	api_guid_count = 0;
	walker_count = 0;
	hob_walker.raw = (UINT8 *)(void *)hob_info;
	while (!END_OF_HOB_LIST(hob_walker) && walker_count < 64) {
		if (GET_HOB_LENGTH(hob_walker) < sizeof(EFI_HOB_GENERIC_HEADER)) {
			failures += expect(0, "HOB traversal saw an invalid length");
			break;
		}

		failures += expect((GET_HOB_LENGTH(hob_walker) & 7U) == 0,
				   "HOB length is not traversal aligned");
		if (GET_HOB_TYPE(hob_walker) == EFI_HOB_TYPE_GUID_EXTENSION) {
			if (memcmp(&hob_walker.guid->name, &test_guid, sizeof(test_guid)) == 0 &&
			    memcmp(GET_GUID_HOB_DATA(hob_walker), test_data, sizeof(test_data)) ==
				    0) {
				api_guid_count++;
			}
		}

		hob_walker.raw = (UINT8 *)(void *)GET_NEXT_HOB(hob_walker);
		walker_count++;
	}

	failures += expect(END_OF_HOB_LIST(hob_walker), "HOB traversal missed the end marker");
	failures += expect(api_guid_count == 1, "HOB traversal missed the GUID HOB");

	memset(smbios2_entry, 0, sizeof(smbios2_entry));
	memcpy(smbios2_entry, "_SM_", 4);
	table_size = build_smbios_cbmem_table(storage, sizeof(storage), smbios2_entry,
					      sizeof(smbios2_entry));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "SMBIOS 2 CBMEM table rejected");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "SMBIOS 2 HOB base construction failed");
	status = cdk2_coreboot_test_append_smbios_hob(hob_info, &handoff);
	failures += expect(status == EFI_SUCCESS, "SMBIOS 2 HOB append failed");
	smbios2_guid_count = 0;
	smbios3_guid_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			EFI_HOB_GUID_TYPE *guid_hob;

			guid_hob = (EFI_HOB_GUID_TYPE *)(void *)hob;
			if (memcmp(&guid_hob->name, &smbios_table_guid,
				   sizeof(smbios_table_guid)) == 0) {
				failures += expect(
					hob->hob_length >= sizeof(*guid_hob) +
								   sizeof(*smbios_table),
					"SMBIOS 2 HOB is too short");
				smbios_table = (UNIVERSAL_PAYLOAD_SMBIOS_TABLE *)(void *)(guid_hob + 1);
				failures += expect(
					smbios_table->sm_bios_entry_point ==
						(EFI_PHYSICAL_ADDRESS)(UINTN)smbios2_entry,
					"SMBIOS 2 entry point address is wrong");
				smbios2_guid_count++;
			} else if (memcmp(&guid_hob->name, &smbios3_table_guid,
					  sizeof(smbios3_table_guid)) == 0) {
				smbios3_guid_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(smbios2_guid_count == 1, "SMBIOS 2 GUID HOB count is wrong");
	failures += expect(smbios3_guid_count == 0, "SMBIOS 2 table used SMBIOS 3 GUID");

	memset(smbios3_entry, 0, sizeof(smbios3_entry));
	memcpy(smbios3_entry, "_SM3_", 5);
	table_size = build_smbios_cbmem_table(storage, sizeof(storage), smbios3_entry,
					      sizeof(smbios3_entry));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "SMBIOS 3 CBMEM table rejected");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "SMBIOS 3 HOB base construction failed");
	status = cdk2_coreboot_test_append_smbios_hob(hob_info, &handoff);
	failures += expect(status == EFI_SUCCESS, "SMBIOS 3 HOB append failed");
	smbios2_guid_count = 0;
	smbios3_guid_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			EFI_HOB_GUID_TYPE *guid_hob;

			guid_hob = (EFI_HOB_GUID_TYPE *)(void *)hob;
			if (memcmp(&guid_hob->name, &smbios_table_guid,
				   sizeof(smbios_table_guid)) == 0) {
				smbios2_guid_count++;
			} else if (memcmp(&guid_hob->name, &smbios3_table_guid,
					  sizeof(smbios3_table_guid)) == 0) {
				failures += expect(
					hob->hob_length >= sizeof(*guid_hob) +
								   sizeof(*smbios_table),
					"SMBIOS 3 HOB is too short");
				smbios_table = (UNIVERSAL_PAYLOAD_SMBIOS_TABLE *)(void *)(guid_hob + 1);
				failures += expect(
					smbios_table->sm_bios_entry_point ==
						(EFI_PHYSICAL_ADDRESS)(UINTN)smbios3_entry,
					"SMBIOS 3 entry point address is wrong");
				smbios3_guid_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(smbios2_guid_count == 0, "SMBIOS 3 table used SMBIOS 2 GUID");
	failures += expect(smbios3_guid_count == 1, "SMBIOS 3 GUID HOB count is wrong");

	memset(smbios2_entry, 0, sizeof(smbios2_entry));
	memcpy(smbios2_entry, "BAD!", 4);
	table_size = build_smbios_cbmem_table(storage, sizeof(storage), smbios2_entry,
					      sizeof(smbios2_entry));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "malformed SMBIOS CBMEM table rejected");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "malformed SMBIOS HOB base construction failed");
	status = cdk2_coreboot_test_append_smbios_hob(hob_info, &handoff);
	failures += expect(status == EFI_COMPROMISED_DATA,
			   "malformed SMBIOS anchor was accepted");

	table_size = build_memory_table(storage, sizeof(storage));
	status = cdk2_coreboot_parse_table(storage, table_size, &handoff);
	failures += expect(status == EFI_SUCCESS, "valid table restore after SMBIOS rejected");
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), TRUE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "restored HOB construction after SMBIOS failed");

	previous_end_of_hob_list = hob_info->efi_end_of_hob_list;
	previous_free_memory_bottom = hob_info->efi_free_memory_bottom;
	status = cdk2_coreboot_append_memory_allocation_hob(
		hob_info, MAX_UINT64 - EFI_PAGE_SIZE + 1, EFI_PAGE_SIZE, efi_boot_services_data);
	failures += expect(status == EFI_INVALID_PARAMETER, "wrapping allocation HOB accepted");
	status = cdk2_coreboot_append_stack_hob(hob_info, MAX_UINT64 - EFI_PAGE_SIZE + 1,
						EFI_PAGE_SIZE);
	failures += expect(status == EFI_INVALID_PARAMETER, "wrapping stack HOB accepted");
	status = cdk2_coreboot_append_module_hob(hob_info, &dxe_core_guid,
						 MAX_UINT64 - EFI_PAGE_SIZE + 1, EFI_PAGE_SIZE,
						 MAX_UINT64);
	failures += expect(status == EFI_INVALID_PARAMETER, "wrapping module HOB accepted");
	status = cdk2_coreboot_append_fv_hob(hob_info, MAX_UINT64 - EFI_PAGE_SIZE + 1,
					     EFI_PAGE_SIZE);
	failures += expect(status == EFI_INVALID_PARAMETER, "wrapping FV HOB accepted");
	failures += expect(hob_info->efi_end_of_hob_list == previous_end_of_hob_list,
			   "rejected descriptor append moved the end marker");
	failures += expect(hob_info->efi_free_memory_bottom == previous_free_memory_bottom,
			   "rejected descriptor append moved free bottom");

	previous_end_of_hob_list = hob_info->efi_end_of_hob_list;
	previous_free_memory_bottom = hob_info->efi_free_memory_bottom;
	previous_end_marker = *(EFI_HOB_GENERIC_HEADER *)(UINTN)previous_end_of_hob_list;
	bad_free_memory_bottom = previous_free_memory_bottom + sizeof(EFI_HOB_GENERIC_HEADER);
	hob_info->efi_free_memory_bottom = bad_free_memory_bottom;
	status = cdk2_coreboot_append_cpu_hob(hob_info, 36, 16);
	failures +=
		expect(status == EFI_COMPROMISED_DATA, "desynchronized PHIT append accepted");
	failures += expect(hob_info->efi_end_of_hob_list == previous_end_of_hob_list,
			   "desynchronized PHIT append moved the end marker");
	failures += expect(hob_info->efi_free_memory_bottom == bad_free_memory_bottom,
			   "desynchronized PHIT append rewrote free bottom");
	hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)previous_end_of_hob_list;
	failures += expect(hob->hob_type == previous_end_marker.hob_type &&
				   hob->hob_length == previous_end_marker.hob_length,
			   "desynchronized PHIT append overwrote the end marker");
	hob_info->efi_end_of_hob_list = previous_end_of_hob_list;
	hob_info->efi_free_memory_bottom = previous_free_memory_bottom;
	*(EFI_HOB_GENERIC_HEADER *)(UINTN)previous_end_of_hob_list = previous_end_marker;

	transaction_handoff = (struct cdk2_coreboot_handoff){0};
	transaction_free_top_offset = TEST_HOB_ALIGN8(sizeof(EFI_HOB_HANDOFF_INFO_TABLE)) +
				   TEST_HOB_ALIGN8(sizeof(EFI_HOB_FIRMWARE_VOLUME)) +
				   TEST_HOB_ALIGN8(sizeof(EFI_HOB_MEMORY_ALLOCATION)) +
				   TEST_HOB_ALIGN8(sizeof(EFI_HOB_GENERIC_HEADER));
	status = cdk2_coreboot_build_hobs(&transaction_handoff, transaction_hob_storage,
					  transaction_hob_storage + sizeof(transaction_hob_storage),
					  transaction_hob_storage,
					  transaction_hob_storage + transaction_free_top_offset,
					  FALSE, (void **)&transaction_hob);
	failures += expect(status == EFI_SUCCESS, "transactional HOB construction failed");
	if (!EFI_ERROR(status)) {
		transaction_end_of_hob_list = transaction_hob->efi_end_of_hob_list;
		transaction_free_memory_bottom = transaction_hob->efi_free_memory_bottom;
		transaction_free_memory_top = transaction_hob->efi_free_memory_top;
		transaction_end_marker =
			*(EFI_HOB_GENERIC_HEADER *)(UINTN)transaction_end_of_hob_list;
		status = cdk2_coreboot_test_append_loaded_dxe_core_hobs(
			transaction_hob, 0x00100000, EFI_PAGE_SIZE, &dxe_core_guid, 0x00400000,
			EFI_PAGE_SIZE, 0x00400100);
		failures +=
			expect(status == EFI_OUT_OF_RESOURCES, "partial DXE HOB append status");
		failures += expect(transaction_hob->efi_end_of_hob_list == transaction_end_of_hob_list,
				   "partial DXE HOB append moved the end marker");
		failures += expect(transaction_hob->efi_free_memory_bottom ==
					   transaction_free_memory_bottom,
				   "partial DXE HOB append moved free bottom");
		failures += expect(transaction_hob->efi_free_memory_top == transaction_free_memory_top,
				   "partial DXE HOB append moved free top");
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)transaction_end_of_hob_list;
		failures += expect(hob->hob_type == transaction_end_marker.hob_type &&
					   hob->hob_length == transaction_end_marker.hob_length,
				   "partial DXE HOB append overwrote the end marker");
	}

	memset(m_transfer_hob_storage, 0, sizeof(m_transfer_hob_storage));
	transfer_hob = (EFI_HOB_HANDOFF_INFO_TABLE *)(void *)m_transfer_hob_storage;
	transfer_end = (EFI_HOB_GENERIC_HEADER *)(void *)(transfer_hob + 1);
	transfer_free_bottom = (EFI_PHYSICAL_ADDRESS)(UINTN)(transfer_end + 1);
	transfer_free_top = transfer_free_bottom + 0x20 * EFI_PAGE_SIZE;
	transfer_hob->header.hob_type = EFI_HOB_TYPE_HANDOFF;
	transfer_hob->header.hob_length = sizeof(*transfer_hob);
	transfer_hob->version = EFI_HOB_HANDOFF_TABLE_VERSION;
	transfer_hob->boot_mode = BOOT_WITH_FULL_CONFIGURATION;
	transfer_hob->efi_memory_bottom = (EFI_PHYSICAL_ADDRESS)(UINTN)m_transfer_hob_storage;
	transfer_hob->efi_memory_top = transfer_free_top;
	transfer_hob->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)transfer_end;
	transfer_hob->efi_free_memory_bottom = transfer_free_bottom;
	transfer_hob->efi_free_memory_top = transfer_free_top;
	transfer_end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	transfer_end->hob_length = sizeof(*transfer_end);
	transfer_context = (struct cdk2_native_context){0};
	transfer_context.hob_list = transfer_hob;
	transfer_context.hob_list_size = sizeof(*transfer_hob) + sizeof(*transfer_end);
	transfer_context.image_base = 0x00400000;
	transfer_context.image_size = 0x00020000;
	transfer_context.image_entry_point = 0x00401000;
	transfer_context.allocation_bottom = transfer_free_bottom;
	transfer_context.allocation_top = transfer_free_top;
	transfer_context.image_size = 0;
	status = cdk2_coreboot_test_transfer(&transfer_context);
	failures += expect(status == EFI_NOT_READY, "transfer accepted invalid handoff image");
	transfer_context.image_size = 0x00020000;
	status = cdk2_coreboot_test_transfer(&transfer_context);
	failures +=
		expect(status == EFI_OUT_OF_RESOURCES, "transfer stack HOB exhaustion status");
	failures += expect(transfer_context.allocation_bottom == transfer_free_bottom,
			   "failed transfer moved allocation bottom");
	failures += expect(transfer_context.allocation_top == transfer_free_top,
			   "failed transfer moved allocation top");
	failures += expect(transfer_hob->efi_free_memory_top == transfer_free_top,
			   "failed transfer moved PHIT free top");
	failures +=
		expect(transfer_hob->efi_end_of_hob_list == (EFI_PHYSICAL_ADDRESS)(UINTN)transfer_end,
		       "failed transfer moved HOB end marker");

	status = cdk2_coreboot_build_hobs(
		&handoff, tiny_hob_storage, tiny_hob_storage + sizeof(tiny_hob_storage),
		tiny_hob_storage, tiny_hob_storage + sizeof(tiny_hob_storage), FALSE,
		(void **)&hob_info);
	failures += expect(status == EFI_OUT_OF_RESOURCES, "HOB exhaustion was not rejected");

	status = cdk2_coreboot_build_hobs(&handoff, (void *)(UINTN)0x1000,
					  (void *)(UINTN)MAX_UINTN,
					  (void *)(UINTN)(MAX_UINTN - 3U),
					  (void *)(UINTN)MAX_UINTN, FALSE, (void **)&hob_info);
	failures += expect(status == EFI_INVALID_PARAMETER, "wrapped HOB free bottom accepted");

	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 1;
	handoff.memory_ranges[0].base = CDK2_COREBOOT_TEMP_MAP_LIMIT - TEST_HOB_REGION_SIZE;
	handoff.memory_ranges[0].size = TEST_HOB_REGION_SIZE;
	handoff.memory_ranges[0].type = CB_MEM_RAM;
	hob_mem_base = 0;
	status = cdk2_coreboot_find_hob_memory_base(
		&handoff, 0x00100000, 0x00100000, TEST_HOB_REGION_SIZE,
		CDK2_COREBOOT_TEMP_MAP_LIMIT, &hob_mem_base);
	failures += expect(status == EFI_SUCCESS, "temp-map edge HOB memory rejected");
	failures += expect(
		hob_mem_base == (UINTN)(CDK2_COREBOOT_TEMP_MAP_LIMIT - TEST_HOB_REGION_SIZE),
		"temp-map edge HOB memory base is wrong");

	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 1;
	handoff.memory_ranges[0].base = MAX_UINT64 - 0xfffULL;
	handoff.memory_ranges[0].size = 0x800;
	handoff.memory_ranges[0].type = CB_MEM_RAM;
	status = cdk2_coreboot_find_hob_memory_base(
		&handoff, 0x00100000, 0x00100000, TEST_HOB_REGION_SIZE,
		CDK2_COREBOOT_TEMP_MAP_LIMIT, &hob_mem_base);
	failures += expect(status == EFI_OUT_OF_RESOURCES,
			   "high aligned RAM range selected HOB memory");

	handoff.memory_ranges[0].base = MAX_UINT64 - 0x7ffULL;
	handoff.memory_ranges[0].size = 0x1000;
	status = cdk2_coreboot_find_hob_memory_base(
		&handoff, 0x00100000, 0x00100000, TEST_HOB_REGION_SIZE,
		CDK2_COREBOOT_TEMP_MAP_LIMIT, &hob_mem_base);
	failures += expect(status == EFI_COMPROMISED_DATA,
			   "wrapping RAM range accepted for HOB memory");

	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 3;
	handoff.memory_ranges[0].base = 0x00100000;
	handoff.memory_ranges[0].size = EFI_PAGE_SIZE;
	handoff.memory_ranges[0].type = CB_MEM_RAM;
	handoff.memory_ranges[1].base = CDK2_COREBOOT_TEMP_MAP_LIMIT - EFI_PAGE_SIZE;
	handoff.memory_ranges[1].size = 3 * EFI_PAGE_SIZE;
	handoff.memory_ranges[1].type = CB_MEM_RAM;
	handoff.memory_ranges[2].base = CDK2_COREBOOT_TEMP_MAP_LIMIT + 3 * EFI_PAGE_SIZE;
	handoff.memory_ranges[2].size = EFI_PAGE_SIZE;
	handoff.memory_ranges[2].type = CB_MEM_RAM;
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "high RAM HOB filtering failed");
	resource_count = 0;
	high_ram_resource_count = 0;
	clipped_ram_resource_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
			resource = (EFI_HOB_RESOURCE_DESCRIPTOR *)(void *)hob;
			if (resource->resource_type == EFI_RESOURCE_SYSTEM_MEMORY) {
				resource_count++;
				if (resource->physical_start >= CDK2_COREBOOT_TEMP_MAP_LIMIT) {
					high_ram_resource_count++;
				}

				if (resource->physical_start ==
				    CDK2_COREBOOT_TEMP_MAP_LIMIT - EFI_PAGE_SIZE) {
					failures += expect(
						resource->resource_length == EFI_PAGE_SIZE,
						"crossing RAM resource was not clipped");
					clipped_ram_resource_count++;
				}
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(resource_count == 2, "unexpected high RAM resource count");
	failures += expect(high_ram_resource_count == 0, "unmapped high RAM was handed to DXE");
	failures += expect(clipped_ram_resource_count == 1,
			   "temp-map crossing RAM was not kept below the map limit");

	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 2;
	handoff.memory_ranges[0].base = 0x00100000;
	handoff.memory_ranges[0].size = 0x7ff00000;
	handoff.memory_ranges[0].type = CB_MEM_RAM;
	handoff.memory_ranges[1].base = 0x80000000;
	handoff.memory_ranges[1].size = 0x01000000;
	handoff.memory_ranges[1].type = CB_MEM_RESERVED;
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS,
			   "contiguous reserved DRAM HOB build failed");
	resource_count = 0;
	resource = NULL;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
			resource_count++;
			if (resource_count == 2) {
				resource = (EFI_HOB_RESOURCE_DESCRIPTOR *)(void *)hob;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(resource_count == 2, "contiguous reserved resource count is wrong");
	failures += expect(resource != NULL &&
				   resource->resource_type == EFI_RESOURCE_MEMORY_RESERVED,
			   "contiguous reserved DRAM became MMIO");

	handoff.pcie_base_address = 0x80000000;
	handoff.pcie_base_size = 0x01000000;
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "ECAM resource HOB build failed");
	resource_count = 0;
	resource = NULL;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
			resource_count++;
			if (resource_count == 2) {
				resource = (EFI_HOB_RESOURCE_DESCRIPTOR *)(void *)hob;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(resource_count == 2, "ECAM resource count is wrong");
	failures += expect(resource != NULL &&
				   resource->resource_type == EFI_RESOURCE_MEMORY_MAPPED_IO,
			   "below-TOLUD ECAM was not MMIO");
	allocation_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
			EFI_HOB_MEMORY_ALLOCATION *allocation;

			allocation = (EFI_HOB_MEMORY_ALLOCATION *)(void *)hob;
			if (allocation->alloc_descriptor.memory_type == efi_reserved_memory_type &&
			    allocation->alloc_descriptor.memory_base_address == 0x80000000 &&
			    allocation->alloc_descriptor.memory_length == 0x01000000) {
				allocation_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(allocation_count == 1, "ECAM allocation HOB missing");

	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 2;
	handoff.memory_ranges[0].base = 0x00100000;
	handoff.memory_ranges[0].size = 0x00400000;
	handoff.memory_ranges[0].type = CB_MEM_RAM;
	handoff.memory_ranges[1].base = 0x00600000;
	handoff.memory_ranges[1].size = 0x00100000;
	handoff.memory_ranges[1].type = CB_MEM_UNUSABLE;
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "unusable memory HOB build failed");
	allocation_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
			EFI_HOB_MEMORY_ALLOCATION *allocation;

			allocation = (EFI_HOB_MEMORY_ALLOCATION *)(void *)hob;
			if (allocation->alloc_descriptor.memory_type == efi_unusable_memory &&
			    allocation->alloc_descriptor.memory_base_address == 0x00600000 &&
			    allocation->alloc_descriptor.memory_length == 0x00100000) {
				allocation_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(allocation_count == 1, "unusable memory allocation HOB missing");

	build_test_acpi_tables(&rsdp, &xsdt, &fadt, &mcfg);
	status = cdk2_coreboot_test_build_acpi_board_info((EFI_PHYSICAL_ADDRESS)(UINTN)&rsdp,
							  &board_info);
	failures += expect(status == EFI_SUCCESS, "valid MCFG ACPI data rejected");
	failures += expect(board_info.pcie_base_address == 0xe0000000ULL,
			   "MCFG base address is wrong");

	rsdp.checksum ^= 1U;
	status = cdk2_coreboot_test_build_acpi_board_info((EFI_PHYSICAL_ADDRESS)(UINTN)&rsdp,
							  &board_info);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad RSDP checksum accepted");

	build_test_acpi_tables(&rsdp, &xsdt, &fadt, &mcfg);
	xsdt.header.checksum ^= 1U;
	status = cdk2_coreboot_test_build_acpi_board_info((EFI_PHYSICAL_ADDRESS)(UINTN)&rsdp,
							  &board_info);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad XSDT checksum accepted");

	build_test_acpi_tables(&rsdp, &xsdt, &fadt, &mcfg);
	xsdt.header.signature = EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE;
	test_update_acpi_table_checksum(&xsdt.header);
	status = cdk2_coreboot_test_build_acpi_board_info((EFI_PHYSICAL_ADDRESS)(UINTN)&rsdp,
							  &board_info);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad XSDT signature accepted");

	build_test_acpi_tables(&rsdp, &xsdt, &fadt, &mcfg);
	fadt.header.checksum ^= 1U;
	status = cdk2_coreboot_test_build_acpi_board_info((EFI_PHYSICAL_ADDRESS)(UINTN)&rsdp,
							  &board_info);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad FADT checksum accepted");

	build_test_acpi_tables(&rsdp, &xsdt, &fadt, &mcfg);
	rsdp.revision = 0;
	rsdp.length = 0;
	rsdp.rsdt_address = 0;
	test_update_rsdp_checksums(&rsdp);
	status = cdk2_coreboot_test_build_acpi_board_info((EFI_PHYSICAL_ADDRESS)(UINTN)&rsdp,
							  &board_info);
	failures += expect(status == EFI_NOT_FOUND, "ACPI 1.0 RSDP followed XSDT pointer");

	build_test_acpi_tables(&rsdp, &xsdt, &fadt, &mcfg);
	mcfg.header.header.length = sizeof(EFI_ACPI_DESCRIPTION_HEADER) + sizeof(mcfg.allocation);
	test_update_acpi_table_checksum(&mcfg.header.header);
	status = cdk2_coreboot_test_build_acpi_board_info((EFI_PHYSICAL_ADDRESS)(UINTN)&rsdp,
							  &board_info);
	failures += expect(status == EFI_COMPROMISED_DATA,
			   "MCFG length before allocation table was accepted");

	memset(tpm_event_log, 0, sizeof(tpm_event_log));
	table_size = build_tpm_spec_event(tpm_event_log);
	table_size = append_tpm_event2(tpm_event_log, table_size, 0, "pcr0-data");
	table_size = append_tpm_event2(tpm_event_log, table_size, 1, "pcr1-data");
	tpm2_table = (struct test_tpm2_table){0};
	tpm2_table.header.header.signature =
		EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE;
	tpm2_table.header.header.revision = EFI_TPM2_ACPI_TABLE_REVISION_5;
	tpm2_table.header.header.length = sizeof(tpm2_table);
	tpm2_table.laml = (UINT32)table_size;
	tpm2_table.lasa = (UINT64)(UINTN)tpm_event_log;
	handoff = (struct cdk2_coreboot_handoff){0};
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures += expect(status == EFI_SUCCESS, "TPM event HOB base construction failed");
	status = cdk2_coreboot_test_append_tpm_event_hobs(hob_info,
							  &tpm2_table.header.header);
	failures += expect(status == EFI_SUCCESS, "TPM event HOB import failed");
	guid_count = 0;
	pcr0_count = 0;
	pcr1_count = 0;
	unexpected_pcr_count = 0;
	hob_cursor = (UINTN)(void *)hob_info;
	while (status == EFI_SUCCESS && hob_cursor < (UINTN)hob_info->efi_end_of_hob_list) {
		hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)hob_cursor;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION) {
			EFI_HOB_GUID_TYPE *guid_hob;
			UINT32 pcr_index;

			guid_hob = (EFI_HOB_GUID_TYPE *)(void *)hob;
			if (memcmp(&guid_hob->name, &tcg_event_guid, sizeof(tcg_event_guid)) == 0) {
				memcpy(&pcr_index, guid_hob + 1, sizeof(pcr_index));
				if (pcr_index == 0) {
					pcr0_count++;
				} else if (pcr_index == 1) {
					pcr1_count++;
				} else {
					unexpected_pcr_count++;
				}

				guid_count++;
			}
		}

		hob_cursor += (hob->hob_length + 7U) & ~(UINTN)7U;
	}

	failures += expect(guid_count == 2, "wrong TPM event HOB count");
	failures += expect(pcr0_count == 1, "PCR0 TPM event was not imported");
	failures += expect(pcr1_count == 1, "PCR1 TPM event was not imported");
	failures += expect(unexpected_pcr_count == 0, "unexpected TPM PCR event was imported");

	handoff = (struct cdk2_coreboot_handoff){0};
	handoff.memory_range_count = 2;
	handoff.memory_ranges[0].base = 0x00200000;
	handoff.memory_ranges[0].size = 0x00400000;
	handoff.memory_ranges[0].type = CB_MEM_RAM;
	handoff.memory_ranges[1].base = 0x00300000;
	handoff.memory_ranges[1].size = 0x00100000;
	handoff.memory_ranges[1].type = CB_MEM_RESERVED;
	status = cdk2_coreboot_build_hobs(&handoff, hob_storage, hob_storage + sizeof(hob_storage),
					  hob_storage, hob_storage + sizeof(hob_storage), FALSE,
					  (void **)&hob_info);
	failures +=
		expect(status == EFI_COMPROMISED_DATA, "overlapping memory ranges accepted");

	if (failures != 0) {
		return 1;
	}

	puts("cdk2 coreboot test: PASS");
	return 0;
}
