/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * coreboot platform adapter for the native cdk2 stage.
 */

#include <library/cdk2_native_services.h>
#include <guid/acpi_board_info.h>
#include <guid/cbmem_table_hob.h>
#include <guid/cfr_setup_menu.h>
#include <guid/firmware_info.h>
#include <guid/graphics_info_hob.h>
#include <guid/serial_port_info.h>
#include <guid/smmstore_info.h>
#include <industry_standard/acpi.h>
#include <industry_standard/mcfg.h>
#include <industry_standard/tpm20.h>
#include <industry_standard/tpm2_acpi.h>
#include <industry_standard/uefi_tcg_platform.h>
#include <guid/tcg_physical_presence.h>
#include <universal_payload/acpi_table.h>
#include <universal_payload/serial_port_info.h>
#include <universal_payload/smbios_table.h>
#include <cdk2/config.h>

#include "coreboot_hobs.h"
#include "fv.h"
#include "pe.h"
#include "symbols.h"

#define CDK2_ACPI_MCFG_ALLOCATION \
	EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE

#define CDK2_COREBOOT_HOB_REGION_SIZE (0x04000000U)
#define CDK2_COREBOOT_DXE_MAX_PAGES   (0x2000U)

#define CDK2_COREBOOT_MAX_TPM2_LOG_SIZE  (1024U * 1024U)
#define CDK2_COREBOOT_MAX_TPM_PCR_INDEX  23U
#define CDK2_COREBOOT_SPEC_ID_EVENT_NAME "Spec ID Event"
#define CDK2_COREBOOT_CFR_MAX_DEPTH      32U
#define CDK2_COREBOOT_CFR_OPTION_FLAGS_MASK                                   \
	(CFR_OPTFLAG_READONLY | CFR_OPTFLAG_INACTIVE | CFR_OPTFLAG_SUPPRESS | \
	 CFR_OPTFLAG_VOLATILE | CFR_OPTFLAG_RUNTIME)

#define CDK2_COREBOOT_8259_COMMAND_REGISTER_MASTER 0x20U
#define CDK2_COREBOOT_8259_MASK_REGISTER_MASTER    0x21U
#define CDK2_COREBOOT_8259_COMMAND_REGISTER_SLAVE  0xA0U
#define CDK2_COREBOOT_8259_MASK_REGISTER_SLAVE     0xA1U
#define CDK2_COREBOOT_8259_EOI                     0x20U
#define CDK2_COREBOOT_IOAPIC_BASE_ADDRESS          0xFEC00000U
#define CDK2_COREBOOT_IOAPIC_VERSION_REGISTER      0x01U
#define CDK2_COREBOOT_IOAPIC_REDIR_TABLE_BASE      0x10U
#define CDK2_COREBOOT_IOAPIC_REDIR_LOW(index) \
	(CDK2_COREBOOT_IOAPIC_REDIR_TABLE_BASE + ((index) * 2U))
#define CDK2_COREBOOT_IOAPIC_REDIR_MASK            BIT16
#define CDK2_COREBOOT_HPET_BASE_ADDRESS            0xFED00000U
#define CDK2_COREBOOT_HPET_CAPABILITIES_OFFSET     0x000U
#define CDK2_COREBOOT_HPET_CONFIGURATION_OFFSET    0x010U
#define CDK2_COREBOOT_HPET_INTERRUPT_STATUS_OFFSET 0x020U
#define CDK2_COREBOOT_HPET_TIMER_BASE_OFFSET       0x100U
#define CDK2_COREBOOT_HPET_TIMER_STRIDE            0x020U
#define CDK2_COREBOOT_HPET_TIMER_CONFIGURATION     0x000U
#define CDK2_COREBOOT_HPET_MAIN_COUNTER_ENABLE     BIT0
#define CDK2_COREBOOT_HPET_LEGACY_ROUTE_ENABLE     BIT1
#define CDK2_COREBOOT_HPET_TIMER_INTERRUPT_ENABLE  BIT2
#define CDK2_COREBOOT_HPET_TIMER_MSI_ENABLE        BIT14
#define CDK2_COREBOOT_UEFI_MXCSR                   0x1f80U
#define CDK2_COREBOOT_SMBIOS_ANCHOR_SIZE           4U
#define CDK2_COREBOOT_ACPI_RSDP_V1_SIZE \
	OFFSET_OF(EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER, length)
#define CDK2_COREBOOT_ACPI_RSDP_MAX_SIZE 4096U

#if defined(__GNUC__)
#define CDK2_COREBOOT_NORETURN __noreturn
#else
#define CDK2_COREBOOT_NORETURN
#endif

static struct cdk2_coreboot_handoff m_coreboot_handoff;
static const UINT8 m_cdk2_smbios2_anchor[] = {'_', 'S', 'M', '_'};
static const UINT8 m_cdk2_smbios3_anchor[] = {'_', 'S', 'M', '3', '_'};

static const EFI_GUID m_cdk2_graphics_info_hob_guid = {
	0x39f62cce,
	0x6825,
	0x4669,
	{0xbb, 0x56, 0x54, 0x1a, 0xba, 0x75, 0x3a, 0x07}
};
static const EFI_GUID m_cdk2_smm_store_info_hob_guid = {
	0xf585ca19,
	0x881b,
	0x44fb,
	{0x3f, 0x3d, 0x81, 0x89, 0x7c, 0x57, 0xbb, 0x01}
};
static const EFI_GUID m_cdk2_firmware_info_hob_guid = {
	0xe0653829,
	0x274e,
	0x4b1e,
	{0x87, 0x2d, 0xa2, 0x20, 0xf5, 0xaf, 0x8f, 0x3d}
};
static const EFI_GUID m_cdk2_tcg_physical_presence_info_hob_guid = {
	0xf367be59,
	0x5891,
	0x40eb,
	{0x21, 0x44, 0xed, 0x2e, 0xac, 0x57, 0xfd, 0x14}
};
static const EFI_GUID m_cdk2_acpi_board_info_hob_guid = {
	0x0ad3d31b,
	0xb3d8,
	0x4506,
	{0xae, 0x71, 0x2e, 0xf1, 0x10, 0x06, 0xd9, 0x0f}
};
static const EFI_GUID m_cdk2_serial_port_info_guid = {
	0xaa7e190d,
	0xbe21,
	0x4409,
	{0x8e, 0x67, 0xa2, 0xcd, 0x0f, 0x61, 0xe1, 0x70}
};
static const EFI_GUID m_cdk2_legacy_serial_port_info_guid = {
	0x6c6872fe,
	0x56a9,
	0x4403,
	{0xbb, 0x98, 0x95, 0x8d, 0x62, 0xde, 0x87, 0xf1}
};
static const EFI_GUID m_cdk2_acpi_table_guid = {
	0x9f9a9506,
	0x5597,
	0x4515,
	{0xba, 0xb6, 0x8b, 0xcd, 0xe7, 0x84, 0xba, 0x87}
};
static const EFI_GUID m_cdk2_smbios_table_guid = {
	0x590a0d26,
	0x06e5,
	0x4d20,
	{0x8a, 0x82, 0x59, 0xea, 0x1b, 0x34, 0x98, 0x2d}
};
static const EFI_GUID m_cdk2_smbios3_table_guid = {
	0x92b7896c,
	0x3362,
	0x46ce,
	{0x99, 0xb3, 0x4f, 0x5e, 0x3c, 0x34, 0xeb, 0x42}
};
static const EFI_GUID m_cdk2_coreboot_table_guid = {
	0x9e0d4b6f,
	0xa8e8,
	0x4d7e,
	{0x9a, 0x2d, 0x31, 0x0d, 0x4c, 0x9a, 0x8f, 0x2b}
};
static const EFI_GUID m_cdk2_cfr_setup_menu_form_guid = {
	0xfbc3b1de,
	0xd17c,
	0x44de,
	{0x98, 0x47, 0x2b, 0xbf, 0x9e, 0xfd, 0xbd, 0x8e}
};
static const EFI_GUID m_cdk2_tcg_event2_entry_hob_guid = {
	0xd26c221e,
	0x2430,
	0x4c8a,
	{0x91, 0x70, 0x3f, 0xcb, 0x45, 0x00, 0x41, 0x3f}
};

#define CDK2_COREBOOT_MAX_ACPI_TABLE_SIZE (1024U * 1024U)

static void cdk2_coreboot_copy_bytes(void *destination, const void *source, UINTN length);
static EFI_STATUS cdk2_coreboot_find_cbmem_entry(
	const struct cdk2_coreboot_handoff *coreboot, UINT32 id, UINT32 minimum_size,
	EFI_PHYSICAL_ADDRESS *base, UINT32 *size);

static UINT16 cdk2_coreboot_read16(const void *source)
{
	UINT16 value;

	cdk2_coreboot_copy_bytes(&value, source, sizeof(value));
	return value;
}

static UINT32 cdk2_coreboot_read32(const void *source)
{
	UINT32 value;

	cdk2_coreboot_copy_bytes(&value, source, sizeof(value));
	return value;
}

static UINT64 cdk2_coreboot_read64(const void *source)
{
	UINT64 value;

	cdk2_coreboot_copy_bytes(&value, source, sizeof(value));
	return value;
}

static UINT32 cdk2_coreboot_acpi_read32(const void *source)
{
	return cdk2_coreboot_read32(source);
}

static UINT64 cdk2_coreboot_acpi_read64(const void *source)
{
	return cdk2_coreboot_read64(source);
}

static BOOLEAN cdk2_coreboot_bytes_equal(const void *left, const void *right, UINTN length)
{
	const UINT8 *left_bytes;
	const UINT8 *right_bytes;
	UINTN index;

	if (left == NULL || right == NULL) {
		return FALSE;
	}

	left_bytes = (const UINT8 *)left;
	right_bytes = (const UINT8 *)right;
	for (index = 0; index < length; index++) {
		if (left_bytes[index] != right_bytes[index]) {
			return FALSE;
		}
	}

	return TRUE;
}

static UINT8 cdk2_coreboot_checksum8(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT8 checksum;
	UINTN index;

	bytes = (const UINT8 *)buffer;
	checksum = 0;
	for (index = 0; index < length; index++) {
		checksum = (UINT8)(checksum + bytes[index]);
	}

	return checksum;
}

static UINT32 cdk2_coreboot_crc32(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT32 crc;
	UINTN index;
	UINTN bit_index;

	if (buffer == NULL) {
		return 0;
	}

	bytes = (const UINT8 *)buffer;
	crc = 0;
	for (index = 0; index < length; index++) {
		crc ^= (UINT32)bytes[index] << 24;
		for (bit_index = 0; bit_index < 8; bit_index++) {
			if ((crc & BIT31) != 0) {
				crc = (crc << 1) ^ 0x04C11DB7U;
			} else {
				crc <<= 1;
			}
		}
	}

	return crc;
}

static BOOLEAN cdk2_coreboot_acpi_field_present(const EFI_ACPI_DESCRIPTION_HEADER *table,
						UINTN offset, UINTN size)
{
	return table != NULL && table->length >= offset && size <= table->length - offset;
}

static EFI_STATUS cdk2_coreboot_acpi_inspect_table(
	EFI_PHYSICAL_ADDRESS address, EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE **fadt,
	EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER **mcfg,
	BOOLEAN *tpm2_present, BOOLEAN *tcpa_present, EFI_ACPI_DESCRIPTION_HEADER **tpm2_table)
{
	EFI_ACPI_DESCRIPTION_HEADER *header;

	if (address == 0 || fadt == NULL || mcfg == NULL || tpm2_present == NULL ||
	    tcpa_present == NULL || tpm2_table == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	header = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)address;
	if (header->length < sizeof(*header) ||
	    header->length > CDK2_COREBOOT_MAX_ACPI_TABLE_SIZE) {
		return EFI_COMPROMISED_DATA;
	}

	if (cdk2_coreboot_checksum8(header, header->length) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	switch (header->signature) {
	case EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE:
		if (!cdk2_coreboot_acpi_field_present(
			    header,
			    OFFSET_OF(EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE, gpe0_blk_len),
			    sizeof(((EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *)0)
					   ->gpe0_blk_len))) {
			return EFI_COMPROMISED_DATA;
		}

		*fadt = (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *)header;
		break;

	case EFI_ACPI_6_6_PCI_EXPRESS_MEMORY_MAPPED_CONFIGURATION_SPACE_BASE_ADDRESS_DESCRIPTION_TABLE_SIGNATURE:
		if (header->length <
			    sizeof(EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER) +
				    sizeof(CDK2_ACPI_MCFG_ALLOCATION) ||
		    ((header->length -
		      sizeof(EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER)) %
		     sizeof(CDK2_ACPI_MCFG_ALLOCATION)) != 0) {
			return EFI_COMPROMISED_DATA;
		}

		*mcfg = (EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *)header;
		break;

	case EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE:
		*tpm2_present = TRUE;
		if (*tpm2_table == NULL) {
			*tpm2_table = header;
		}

		break;

	case EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_ALLIANCE_CAPABILITIES_TABLE_SIGNATURE:
		*tcpa_present = TRUE;
		break;

	default:
		break;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_acpi_inspect_root(
	EFI_PHYSICAL_ADDRESS address, BOOLEAN extended,
	EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE **fadt,
	EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER **mcfg,
	BOOLEAN *tpm2_present, BOOLEAN *tcpa_present, EFI_ACPI_DESCRIPTION_HEADER **tpm2_table)
{
	EFI_ACPI_DESCRIPTION_HEADER *header;
	UINTN entry_count;
	UINTN entry_size;
	UINTN index;
	UINT32 root_signature;
	UINT64 table_address;
	EFI_STATUS status;

	if (address == 0 || fadt == NULL || mcfg == NULL || tpm2_present == NULL ||
	    tcpa_present == NULL || tpm2_table == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	header = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)address;
	entry_size = extended ? sizeof(UINT64) : sizeof(UINT32);
	root_signature = extended ? EFI_ACPI_3_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE :
				    EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_TABLE_SIGNATURE;
	if (header->signature != root_signature || header->length < sizeof(*header) ||
	    header->length > CDK2_COREBOOT_MAX_ACPI_TABLE_SIZE ||
	    ((header->length - sizeof(*header)) % entry_size) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	if (cdk2_coreboot_checksum8(header, header->length) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	entry_count = (header->length - sizeof(*header)) / entry_size;
	for (index = 0; index < entry_count; index++) {
		if (extended) {
			table_address = cdk2_coreboot_acpi_read64((UINT8 *)(header + 1) +
								 index * entry_size);
		} else {
			table_address = cdk2_coreboot_acpi_read32((UINT8 *)(header + 1) +
								 index * entry_size);
		}

		status = cdk2_coreboot_acpi_inspect_table(table_address, fadt, mcfg, tpm2_present,
							  tcpa_present, tpm2_table);
		if (EFI_ERROR(status)) {
			return status;
		}
	}

	return EFI_SUCCESS;
}

static EFI_STATUS
cdk2_coreboot_validate_rsdp(const EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *rsdp,
			    BOOLEAN *extended)
{
	if (rsdp == NULL || extended == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (rsdp->signature != EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE ||
	    cdk2_coreboot_checksum8(rsdp, CDK2_COREBOOT_ACPI_RSDP_V1_SIZE) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	*extended = FALSE;
	if (rsdp->revision == 0) {
		return EFI_SUCCESS;
	}

	if (rsdp->length < sizeof(*rsdp) || rsdp->length > CDK2_COREBOOT_ACPI_RSDP_MAX_SIZE ||
	    cdk2_coreboot_checksum8(rsdp, rsdp->length) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	*extended = TRUE;
	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_build_acpi_board_info(EFI_PHYSICAL_ADDRESS rsdp_address,
						      ACPI_BOARD_INFO *board_info,
						      EFI_PHYSICAL_ADDRESS *rsdp_base,
						      EFI_ACPI_DESCRIPTION_HEADER **tpm2_table)
{
	EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *rsdp;
	EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *fadt;
	EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *mcfg;
	CDK2_ACPI_MCFG_ALLOCATION *mcfg_base;
	UINTN allocation_count;
	BOOLEAN tpm2_present;
	BOOLEAN tcpa_present;
	BOOLEAN extended_rsdp;
	EFI_ACPI_DESCRIPTION_HEADER *local_tpm2_table;
	EFI_STATUS status;

	if (rsdp_address == 0 || board_info == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	rsdp = (EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *)(UINTN)rsdp_address;
	status = cdk2_coreboot_validate_rsdp(rsdp, &extended_rsdp);
	if (EFI_ERROR(status)) {
		return status;
	}

	fadt = NULL;
	mcfg = NULL;
	tpm2_present = FALSE;
	tcpa_present = FALSE;
	local_tpm2_table = NULL;

	if (rsdp->rsdt_address != 0) {
		status = cdk2_coreboot_acpi_inspect_root(rsdp->rsdt_address, FALSE, &fadt, &mcfg,
							 &tpm2_present, &tcpa_present,
							 &local_tpm2_table);
		if (EFI_ERROR(status)) {
			return status;
		}
	}

	if (extended_rsdp && rsdp->xsdt_address != 0) {
		status = cdk2_coreboot_acpi_inspect_root(rsdp->xsdt_address, TRUE, &fadt, &mcfg,
							 &tpm2_present, &tcpa_present,
							 &local_tpm2_table);
		if (EFI_ERROR(status)) {
			return status;
		}
	}

	if (fadt == NULL) {
		return EFI_NOT_FOUND;
	}

	*board_info = (ACPI_BOARD_INFO){0};
	board_info->pm_ctrl_reg_base = fadt->pm1a_cnt_blk;
	board_info->pm_timer_reg_base = fadt->pm_tmr_blk;
	board_info->pm_evt_base = fadt->pm1a_evt_blk;
	board_info->pm_gpe_en_base = fadt->gpe0_blk + fadt->gpe0_blk_len / 2;
	if (cdk2_coreboot_acpi_field_present(
		    &fadt->header,
		    OFFSET_OF(EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE, reset_value),
		    sizeof(fadt->reset_value))) {
		board_info->reset_reg_address = fadt->reset_reg.address;
		board_info->reset_value = fadt->reset_value;
	}

	board_info->tpm20_present = tpm2_present;
	board_info->tpm12_present = tcpa_present;
	if (mcfg != NULL) {
		allocation_count = mcfg->header.length - sizeof(*mcfg);
		allocation_count /= sizeof(CDK2_ACPI_MCFG_ALLOCATION);
		if (allocation_count == 0) {
			return EFI_COMPROMISED_DATA;
		}

		mcfg_base = (CDK2_ACPI_MCFG_ALLOCATION *)(mcfg + 1);
		if (mcfg_base->end_bus_number < mcfg_base->start_bus_number) {
			return EFI_COMPROMISED_DATA;
		}

		board_info->pcie_base_address = mcfg_base->base_address;
		board_info->pcie_base_size =
			(UINT64)(mcfg_base->end_bus_number + 1 - mcfg_base->start_bus_number) * 4096 *
			32 * 8;
	}

	if (rsdp_base != NULL) {
		*rsdp_base = rsdp_address;
	}

	if (tpm2_table != NULL) {
		*tpm2_table = local_tpm2_table;
	}

	return EFI_SUCCESS;
}

static UINTN cdk2_coreboot_string_record_length(const struct cb_string *string)
{
	UINTN length;

	if (string == NULL || string->size < sizeof(*string)) {
		return 0;
	}

	length = string->size - sizeof(*string);
	if (length != 0 && string->string[length - 1] == '\0') {
		length--;
	}

	return length;
}

static EFI_STATUS cdk2_coreboot_append_acpi_table_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
						      EFI_PHYSICAL_ADDRESS rsdp_base)
{
	UNIVERSAL_PAYLOAD_ACPI_TABLE acpi_table;

	if (rsdp_base == 0) {
		return EFI_INVALID_PARAMETER;
	}

	acpi_table = (UNIVERSAL_PAYLOAD_ACPI_TABLE){0};
	acpi_table.header.revision = UNIVERSAL_PAYLOAD_ACPI_TABLE_REVISION;
	acpi_table.header.length = sizeof(acpi_table);
	acpi_table.rsdp = rsdp_base;

	return cdk2_coreboot_append_guid_hob(handoff, &m_cdk2_acpi_table_guid, &acpi_table,
					     sizeof(acpi_table));
}

static UINT16 cdk2_coreboot_tpm_digest_size(TPMI_ALG_HASH hash_alg)
{
	switch (hash_alg) {
	case TPM_ALG_SHA1:
		return SHA1_DIGEST_SIZE;
	case TPM_ALG_SHA256:
		return SHA256_DIGEST_SIZE;
	case TPM_ALG_SHA384:
		return SHA384_DIGEST_SIZE;
	case TPM_ALG_SHA512:
		return SHA512_DIGEST_SIZE;
	case TPM_ALG_SM3_256:
		return SM3_256_DIGEST_SIZE;
	default:
		return 0;
	}
}

static BOOLEAN cdk2_coreboot_get_tpm2_acpi_event_log(const EFI_ACPI_DESCRIPTION_HEADER *table,
						     UINT32 *laml, EFI_PHYSICAL_ADDRESS *lasa)
{
	UINTN log_area_offset;
	UINTN parameters_size;

	if (table == NULL || laml == NULL || lasa == NULL ||
	    table->signature != EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE ||
	    table->revision < EFI_TPM2_ACPI_TABLE_REVISION_4 ||
	    table->length < sizeof(EFI_TPM2_ACPI_TABLE)) {
		return FALSE;
	}

	parameters_size =
		EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_4;
	if (table->revision >= EFI_TPM2_ACPI_TABLE_REVISION_5) {
		parameters_size =
			EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_5;
	}

	log_area_offset = sizeof(EFI_TPM2_ACPI_TABLE) + parameters_size;
	if (table->length < log_area_offset + sizeof(*laml) + sizeof(*lasa)) {
		return FALSE;
	}

	*laml = cdk2_coreboot_read32((const UINT8 *)table + log_area_offset);
	*lasa = cdk2_coreboot_read64((const UINT8 *)table + log_area_offset + sizeof(*laml));
	return *laml != 0 && *lasa != 0 && *laml <= CDK2_COREBOOT_MAX_TPM2_LOG_SIZE;
}

static BOOLEAN cdk2_coreboot_get_tcg_pcr_event2_size(const UINT8 *event, UINTN remaining,
						     UINTN *event_size, UINTN *event_data_offset,
						     UINT32 *event_data_size)
{
	UINT32 count;
	UINT32 pcr_index;
	UINT16 digest_size;
	TPMI_ALG_HASH hash_alg;
	UINTN index;
	UINTN offset;

	if (event == NULL || event_size == NULL || event_data_offset == NULL ||
	    event_data_size == NULL) {
		return FALSE;
	}

	offset = sizeof(TCG_PCRINDEX) + sizeof(TCG_EVENTTYPE);
	if (remaining < offset + sizeof(count) + sizeof(*event_data_size)) {
		return FALSE;
	}

	pcr_index = cdk2_coreboot_read32(event);
	if (pcr_index > CDK2_COREBOOT_MAX_TPM_PCR_INDEX) {
		return FALSE;
	}

	count = cdk2_coreboot_read32(event + offset);
	offset += sizeof(count);
	if (count == 0 || count > HASH_COUNT) {
		return FALSE;
	}

	for (index = 0; index < count; index++) {
		if (remaining < offset + sizeof(hash_alg)) {
			return FALSE;
		}

		hash_alg = cdk2_coreboot_read16(event + offset);
		offset += sizeof(hash_alg);

		digest_size = cdk2_coreboot_tpm_digest_size(hash_alg);
		if (digest_size == 0 || remaining < offset + digest_size) {
			return FALSE;
		}

		offset += digest_size;
	}

	if (remaining < offset + sizeof(*event_data_size)) {
		return FALSE;
	}

	*event_data_size = cdk2_coreboot_read32(event + offset);
	offset += sizeof(*event_data_size);
	if (remaining < offset + *event_data_size) {
		return FALSE;
	}

	*event_data_offset = offset;
	*event_size = offset + *event_data_size;
	return TRUE;
}

static BOOLEAN cdk2_coreboot_is_spec_id_event(const UINT8 *event_data, UINT32 event_size)
{
	if (event_size < sizeof(CDK2_COREBOOT_SPEC_ID_EVENT_NAME) - 1) {
		return FALSE;
	}

	return cdk2_coreboot_bytes_equal(event_data, CDK2_COREBOOT_SPEC_ID_EVENT_NAME,
					 sizeof(CDK2_COREBOOT_SPEC_ID_EVENT_NAME) - 1);
}

static UINTN cdk2_coreboot_get_first_tcg_pcr_event2_offset(const UINT8 *event_log,
							   UINTN event_log_size)
{
	UINT32 event_data_size;
	UINTN event_size_offset;
	UINTN first_event_offset;

	if (event_log == NULL || event_log_size < sizeof(TCG_PCR_EVENT_HDR)) {
		return 0;
	}

	if (cdk2_coreboot_read32(event_log + sizeof(TCG_PCRINDEX)) != EV_NO_ACTION) {
		return 0;
	}

	event_size_offset = sizeof(TCG_PCRINDEX) + sizeof(TCG_EVENTTYPE) + sizeof(TCG_DIGEST);
	event_data_size = cdk2_coreboot_read32(event_log + event_size_offset);
	first_event_offset = sizeof(TCG_PCR_EVENT_HDR) + event_data_size;
	if (event_log_size < first_event_offset ||
	    !cdk2_coreboot_is_spec_id_event(event_log + sizeof(TCG_PCR_EVENT_HDR),
					    event_data_size)) {
		return 0;
	}

	return first_event_offset;
}

static EFI_STATUS cdk2_coreboot_append_tpm_event_hobs(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
						      EFI_ACPI_DESCRIPTION_HEADER *tpm2_table)
{
	UINT8 *event_log;
	UINTN event_data_offset;
	UINT32 event_data_size;
	UINTN event_size;
	UINT32 laml;
	EFI_PHYSICAL_ADDRESS lasa;
	UINT32 event_type;
	UINTN offset;
	EFI_STATUS status;

	if (tpm2_table == NULL) {
		return EFI_SUCCESS;
	}

	if (!cdk2_coreboot_get_tpm2_acpi_event_log(tpm2_table, &laml, &lasa)) {
		return EFI_SUCCESS;
	}

	event_log = (UINT8 *)(UINTN)lasa;
	offset = cdk2_coreboot_get_first_tcg_pcr_event2_offset(event_log, laml);
	while (offset < laml) {
		if (!cdk2_coreboot_get_tcg_pcr_event2_size(event_log + offset, laml - offset,
							   &event_size, &event_data_offset,
							   &event_data_size)) {
			break;
		}

		event_type = cdk2_coreboot_read32(event_log + offset + sizeof(TCG_PCRINDEX));
		if (event_type != EV_NO_ACTION ||
		    !cdk2_coreboot_is_spec_id_event(event_log + offset + event_data_offset,
						    event_data_size)) {
			status = cdk2_coreboot_append_guid_hob(handoff,
							       &m_cdk2_tcg_event2_entry_hob_guid,
							       event_log + offset, event_size);
			if (EFI_ERROR(status)) {
				return status;
			}
		}

		offset += event_size;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_find_acpi_rsdp(const struct cdk2_coreboot_handoff *coreboot,
					       EFI_PHYSICAL_ADDRESS *rsdp_base)
{
	const void *record;
	const struct cb_acpi_rsdp *rsdp_record;
	EFI_STATUS status;

	if (coreboot == NULL || rsdp_base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_find_record(coreboot, CB_TAG_ACPI_RSDP,
					   CDK2_COREBOOT_ACPI_RSDP_MIN_SIZE, &record);
	if (!EFI_ERROR(status)) {
		rsdp_record = (const struct cb_acpi_rsdp *)record;
		*rsdp_base = (EFI_PHYSICAL_ADDRESS)rsdp_record->rsdp_pointer.lo |
			    ((EFI_PHYSICAL_ADDRESS)rsdp_record->rsdp_pointer.hi << 32);
		return (*rsdp_base != 0) ? EFI_SUCCESS : EFI_NOT_FOUND;
	}

	if (status != EFI_NOT_FOUND) {
		return status;
	}

	return cdk2_coreboot_find_cbmem_entry(
		coreboot, CBMEM_ID_ACPI, CDK2_COREBOOT_ACPI_RSDP_V1_SIZE,
		rsdp_base, NULL);
}

static EFI_STATUS cdk2_coreboot_update_acpi_handoff(struct cdk2_coreboot_handoff *coreboot)
{
	ACPI_BOARD_INFO board_info;
	EFI_PHYSICAL_ADDRESS rsdp_base;
	EFI_STATUS status;

	if (coreboot == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_find_acpi_rsdp(coreboot, &rsdp_base);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_build_acpi_board_info(rsdp_base, &board_info, NULL, NULL);
	if (EFI_ERROR(status)) {
		return status;
	}

	coreboot->pcie_base_address = board_info.pcie_base_address;
	coreboot->pcie_base_size = board_info.pcie_base_size;
	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_append_acpi_hobs(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
						 const struct cdk2_coreboot_handoff *coreboot)
{
	ACPI_BOARD_INFO board_info;
	EFI_PHYSICAL_ADDRESS rsdp_base;
	EFI_ACPI_DESCRIPTION_HEADER *tpm2_table;
	EFI_STATUS status;

	status = cdk2_coreboot_find_acpi_rsdp(coreboot, &rsdp_base);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_build_acpi_board_info(rsdp_base, &board_info, &rsdp_base, &tpm2_table);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_append_acpi_table_hob(handoff, rsdp_base);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_append_guid_hob(handoff, &m_cdk2_acpi_board_info_hob_guid, &board_info,
					       sizeof(board_info));
	if (EFI_ERROR(status)) {
		return status;
	}

	return cdk2_coreboot_append_tpm_event_hobs(handoff, tpm2_table);
}

static EFI_STATUS
cdk2_coreboot_append_coreboot_table_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
					const struct cdk2_coreboot_handoff *coreboot)
{
	COREBOOT_TABLE_HOB table_hob;

	if (coreboot == NULL || coreboot->header == NULL || coreboot->table_size > MAX_UINT32) {
		return EFI_INVALID_PARAMETER;
	}

	table_hob = (COREBOOT_TABLE_HOB){0};
	table_hob.address = (UINT64)(UINTN)coreboot->header;
	table_hob.size = (UINT32)coreboot->table_size;

	return cdk2_coreboot_append_guid_hob(handoff, &m_cdk2_coreboot_table_guid, &table_hob,
					     sizeof(table_hob));
}

static EFI_STATUS
cdk2_coreboot_find_legacy_cbmem_table(const struct cbmem_root *root, UINT32 id,
				      UINT32 minimum_size, EFI_PHYSICAL_ADDRESS *base,
				      UINT32 *size)
{
	const struct cbmem_entry *entries;
	const struct imd_entry *imd_entries;
	UINTN header_size;
	UINTN entry_size;
	UINTN max_entries;
	UINTN index;
	BOOLEAN is_imd_entry;
	INTN offset;
	UINTN root_base;
	UINT32 cbmem_size;

	if (root == NULL || base == NULL || root->num_entries == 0 ||
	    root->num_entries > root->max_entries) {
		return EFI_NOT_FOUND;
	}

	entries = root->entries;
	header_size = sizeof(*root);
	entry_size = sizeof(*entries);
	imd_entries = NULL;
	is_imd_entry = FALSE;
	if (entries[0].magic != CBMEM_ENTRY_MAGIC) {
		imd_entries = ((const struct imd_root *)root)->entries;
		header_size = sizeof(struct imd_root);
		entry_size = sizeof(*imd_entries);
		if (imd_entries[0].magic != IMD_ENTRY_MAGIC) {
			return EFI_NOT_FOUND;
		}

		is_imd_entry = TRUE;
	}

	if (header_size > DYN_CBMEM_ALIGN_SIZE) {
		return EFI_COMPROMISED_DATA;
	}

	max_entries = (DYN_CBMEM_ALIGN_SIZE - header_size) / entry_size;
	if (root->num_entries > max_entries) {
		return EFI_COMPROMISED_DATA;
	}

	root_base = (UINTN)root;
	for (index = 0; index < root->num_entries; index++) {
		if (is_imd_entry) {
			if (imd_entries[index].id != id) {
				continue;
			}

			cbmem_size = imd_entries[index].size;
			if (cbmem_size < minimum_size) {
				return EFI_COMPROMISED_DATA;
			}

			offset = (INTN)(INT32)imd_entries[index].start_offset;
			if ((offset < 0 && root_base < (UINTN)-offset) ||
			    (offset > 0 && root_base > MAX_UINTN - (UINTN)offset)) {
				return EFI_COMPROMISED_DATA;
			}

			*base = (EFI_PHYSICAL_ADDRESS)(root_base + offset);
		} else {
			if (entries[index].id != id) {
				continue;
			}

			cbmem_size = entries[index].size;
			if (cbmem_size < minimum_size) {
				return EFI_COMPROMISED_DATA;
			}

			*base = entries[index].start;
		}

		if (*base == 0 || *base > MAX_UINT64 - cbmem_size) {
			return EFI_COMPROMISED_DATA;
		}

		if (size != NULL) {
			*size = cbmem_size;
		}

		return EFI_SUCCESS;
	}

	return EFI_NOT_FOUND;
}

static EFI_STATUS cdk2_coreboot_find_legacy_cbmem_entry(
	const struct cdk2_coreboot_handoff *coreboot, UINT32 id, UINT32 minimum_size,
	EFI_PHYSICAL_ADDRESS *base, UINT32 *size)
{
	const struct cdk2_coreboot_memory_range *range;
	const struct cbmem_root *root;
	UINT64 end;
	UINTN index;
	EFI_STATUS status;

	if (coreboot == NULL || base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	for (index = 0; index < coreboot->memory_range_count; index++) {
		range = &coreboot->memory_ranges[index];
		if (range->type != CB_MEM_TABLE || range->base <= 0x1000 ||
		    range->size < DYN_CBMEM_ALIGN_SIZE ||
		    range->base > MAX_UINT64 - range->size) {
			continue;
		}

		end = range->base + range->size;
		root = (const struct cbmem_root *)(UINTN)(end - DYN_CBMEM_ALIGN_SIZE);
		status = cdk2_coreboot_find_legacy_cbmem_table(root, id, minimum_size, base, size);
		if (status != EFI_NOT_FOUND) {
			return status;
		}
	}

	return EFI_NOT_FOUND;
}

static EFI_STATUS cdk2_coreboot_find_cbmem_entry(const struct cdk2_coreboot_handoff *coreboot,
						 UINT32 id, UINT32 minimum_size,
						 EFI_PHYSICAL_ADDRESS *base, UINT32 *size)
{
	const struct cb_record *record;
	const struct cb_cbmem_entry *entry;
	const UINT8 *cursor;
	UINTN remaining;
	UINTN index;

	if (coreboot == NULL || base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (coreboot->header == NULL) {
		return cdk2_coreboot_find_legacy_cbmem_entry(coreboot, id, minimum_size, base, size);
	}

	if (coreboot->header->header_bytes > coreboot->table_size) {
		return EFI_INVALID_PARAMETER;
	}

	cursor = (const UINT8 *)coreboot->header + coreboot->header->header_bytes;
	remaining = coreboot->table_size - coreboot->header->header_bytes;
	for (index = 0; index < coreboot->record_count; index++) {
		if (remaining < sizeof(struct cb_record)) {
			return EFI_COMPROMISED_DATA;
		}

		record = (const struct cb_record *)(const void *)cursor;
		if (record->size < sizeof(struct cb_record) || record->size > remaining) {
			return EFI_COMPROMISED_DATA;
		}

		if (record->tag == CB_TAG_CBMEM_ENTRY) {
			if (record->size < sizeof(*entry)) {
				return EFI_COMPROMISED_DATA;
			}

			entry = (const struct cb_cbmem_entry *)record;
			if (entry->id == id) {
				*base = (EFI_PHYSICAL_ADDRESS)entry->address.lo |
					((EFI_PHYSICAL_ADDRESS)entry->address.hi << 32);
				if (*base == 0 || entry->entry_size < minimum_size ||
				    *base > MAX_UINT64 - entry->entry_size) {
					return EFI_COMPROMISED_DATA;
				}

				if (size != NULL) {
					*size = entry->entry_size;
				}

				return EFI_SUCCESS;
			}
		}

		cursor += record->size;
		remaining -= record->size;
	}

	return cdk2_coreboot_find_legacy_cbmem_entry(coreboot, id, minimum_size, base, size);
}

static EFI_STATUS cdk2_coreboot_append_smbios_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
						  const struct cdk2_coreboot_handoff *coreboot)
{
	UNIVERSAL_PAYLOAD_SMBIOS_TABLE smbios_table;
	const EFI_GUID *smbios_guid;
	EFI_PHYSICAL_ADDRESS smbios_base;
	UINT32 smbios_size;
	EFI_STATUS status;

	status = cdk2_coreboot_find_cbmem_entry(coreboot, CBMEM_ID_SMBIOS,
						CDK2_COREBOOT_SMBIOS_ANCHOR_SIZE,
						&smbios_base, &smbios_size);
	if (status == EFI_NOT_FOUND) {
		return EFI_SUCCESS;
	}

	if (EFI_ERROR(status)) {
		return status;
	}

	smbios_table = (UNIVERSAL_PAYLOAD_SMBIOS_TABLE){0};
	smbios_table.header.revision = UNIVERSAL_PAYLOAD_SMBIOS_TABLE_REVISION;
	smbios_table.header.length = sizeof(smbios_table);
	smbios_table.sm_bios_entry_point = smbios_base;
	if (smbios_size >= sizeof(m_cdk2_smbios3_anchor) &&
	    cdk2_coreboot_bytes_equal((const void *)(UINTN)smbios_base, m_cdk2_smbios3_anchor,
				      sizeof(m_cdk2_smbios3_anchor))) {
		smbios_guid = &m_cdk2_smbios3_table_guid;
	} else if (cdk2_coreboot_bytes_equal((const void *)(UINTN)smbios_base,
					     m_cdk2_smbios2_anchor,
					     sizeof(m_cdk2_smbios2_anchor))) {
		smbios_guid = &m_cdk2_smbios_table_guid;
	} else {
		return EFI_COMPROMISED_DATA;
	}

	return cdk2_coreboot_append_guid_hob(handoff, smbios_guid, &smbios_table,
					     sizeof(smbios_table));
}

#if CONFIG_CDK2_CAPSULE
static EFI_STATUS
cdk2_coreboot_append_capsule_hobs(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
				  const struct cdk2_coreboot_handoff *coreboot)
{
	const struct cb_record *record;
	const struct cb_range *range;
	const UINT8 *cursor;
	UINTN remaining;
	UINTN index;
	EFI_STATUS status;

	if (coreboot == NULL || coreboot->header == NULL ||
	    coreboot->header->header_bytes > coreboot->table_size) {
		return EFI_INVALID_PARAMETER;
	}

	cursor = (const UINT8 *)coreboot->header + coreboot->header->header_bytes;
	remaining = coreboot->table_size - coreboot->header->header_bytes;
	for (index = 0; index < coreboot->record_count; index++) {
		if (remaining < sizeof(struct cb_record)) {
			return EFI_COMPROMISED_DATA;
		}

		record = (const struct cb_record *)(const void *)cursor;
		if (record->size < sizeof(struct cb_record) || record->size > remaining) {
			return EFI_COMPROMISED_DATA;
		}

		if (record->tag == CB_TAG_CAPSULE) {
			if (record->size < sizeof(*range)) {
				return EFI_COMPROMISED_DATA;
			}

			range = (const struct cb_range *)record;
			if (range->range_start == 0 || range->range_size == 0 ||
			    range->range_start > MAX_UINT64 - range->range_size) {
				return EFI_COMPROMISED_DATA;
			}

			status = cdk2_coreboot_append_capsule_hob(handoff, range->range_start,
								  range->range_size);
			if (EFI_ERROR(status)) {
				return status;
			}
		}

		cursor += record->size;
		remaining -= record->size;
	}

	return EFI_SUCCESS;
}
#endif

static CFR_VARBINARY *cdk2_coreboot_cfr_extract_var_binary(UINT8 *buffer, UINTN *offset,
							   UINTN buffer_size, UINT32 target_tag)
{
	CFR_VARBINARY *var_binary;
	UINTN required_size;

	if (buffer == NULL || offset == NULL || *offset > buffer_size ||
	    buffer_size - *offset < sizeof(*var_binary)) {
		return NULL;
	}

	var_binary = (CFR_VARBINARY *)(buffer + *offset);
	if (var_binary->tag != target_tag) {
		return NULL;
	}

	if (var_binary->size < sizeof(*var_binary) || var_binary->size > buffer_size - *offset ||
	    var_binary->data_length > var_binary->size - sizeof(*var_binary)) {
		return NULL;
	}

	required_size = (sizeof(*var_binary) + var_binary->data_length + 3U) & ~(UINTN)3U;
	if (var_binary->size != required_size) {
		return NULL;
	}

	if (target_tag == CB_TAG_CFR_DEP_VALUES) {
		if ((var_binary->data_length % sizeof(UINT32)) != 0) {
			return NULL;
		}
	} else if (var_binary->data_length == 0 ||
		   var_binary->data[var_binary->data_length - 1] != '\0') {
		return NULL;
	}

	*offset += var_binary->size;
	return var_binary;
}

static EFI_STATUS cdk2_coreboot_cfr_validate_var_binary(const UINT8 *buffer, UINTN *offset,
							UINTN buffer_size, UINT32 tag)
{
	if (cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, offset, buffer_size, tag) ==
	    NULL) {
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_cfr_validate_object(const UINT8 *buffer, UINTN buffer_size,
						    UINTN depth)
{
	const CFR_OPTION_FORM *header;
	const CFR_OPTION_NUMERIC *numeric;
	const CFR_ENUM_VALUE *enum_value;
	const CFR_RUNTIME_APPLY *runtime_apply;
	UINTN offset;
	UINTN enum_offset;
	EFI_STATUS status;

	if (depth > CDK2_COREBOOT_CFR_MAX_DEPTH || buffer_size < sizeof(*header)) {
		return EFI_COMPROMISED_DATA;
	}

	header = (const CFR_OPTION_FORM *)buffer;
	if (header->size < sizeof(*header) || header->size > buffer_size ||
	    (header->flags & ~CDK2_COREBOOT_CFR_OPTION_FLAGS_MASK) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	switch (header->tag) {
	case CB_TAG_CFR_OPTION_FORM:
		offset = sizeof(CFR_OPTION_FORM);
		status = cdk2_coreboot_cfr_validate_var_binary(buffer, &offset, header->size,
							       CB_TAG_CFR_VARCHAR_UI_NAME);
		if (EFI_ERROR(status)) {
			return status;
		}

		cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, &offset, header->size,
						     CB_TAG_CFR_DEP_VALUES);

		while (offset < header->size) {
			status = cdk2_coreboot_cfr_validate_object(
				buffer + offset, header->size - offset, depth + 1);
			if (EFI_ERROR(status)) {
				return status;
			}

			offset += ((const CFR_OPTION_FORM *)(buffer + offset))->size;
		}

		return (offset == header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;

	case CB_TAG_CFR_OPTION_ENUM:
	case CB_TAG_CFR_OPTION_NUMBER:
	case CB_TAG_CFR_OPTION_BOOL:
		if (header->size < sizeof(CFR_OPTION_NUMERIC)) {
			return EFI_COMPROMISED_DATA;
		}

		numeric = (const CFR_OPTION_NUMERIC *)buffer;
		offset = sizeof(CFR_OPTION_NUMERIC);
		status = cdk2_coreboot_cfr_validate_var_binary(buffer, &offset, header->size,
							       CB_TAG_CFR_VARCHAR_OPT_NAME);
		if (EFI_ERROR(status)) {
			return status;
		}

		status = cdk2_coreboot_cfr_validate_var_binary(buffer, &offset, header->size,
							       CB_TAG_CFR_VARCHAR_UI_NAME);
		if (EFI_ERROR(status)) {
			return status;
		}

		cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, &offset, header->size,
						     CB_TAG_CFR_VARCHAR_UI_HELPTEXT);
		cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, &offset, header->size,
						     CB_TAG_CFR_DEP_VALUES);

		if (header->size - offset >= sizeof(CFR_RUNTIME_APPLY)) {
			runtime_apply = (const CFR_RUNTIME_APPLY *)(buffer + offset);
			if (runtime_apply->tag == CB_TAG_CFR_RUNTIME_APPLY) {
				if (runtime_apply->size != sizeof(CFR_RUNTIME_APPLY)) {
					return EFI_COMPROMISED_DATA;
				}

				offset += runtime_apply->size;
			}
		}

		if (numeric->tag != CB_TAG_CFR_OPTION_ENUM) {
			return (offset == header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
		}

		while (offset < header->size) {
			if (header->size - offset < sizeof(CFR_ENUM_VALUE)) {
				return EFI_COMPROMISED_DATA;
			}

			enum_value = (const CFR_ENUM_VALUE *)(buffer + offset);
			if (enum_value->tag != CB_TAG_CFR_ENUM_VALUE ||
			    enum_value->size < sizeof(CFR_ENUM_VALUE) ||
			    enum_value->size > header->size - offset) {
				return EFI_COMPROMISED_DATA;
			}

			enum_offset = sizeof(CFR_ENUM_VALUE);
			status = cdk2_coreboot_cfr_validate_var_binary(
				(const UINT8 *)enum_value, &enum_offset, enum_value->size,
				CB_TAG_CFR_VARCHAR_UI_NAME);
			if (EFI_ERROR(status) || enum_offset != enum_value->size) {
				return EFI_COMPROMISED_DATA;
			}

			offset += enum_value->size;
		}

		return EFI_SUCCESS;

	case CB_TAG_CFR_OPTION_VARCHAR:
		offset = sizeof(CFR_OPTION_VARCHAR);
		status = cdk2_coreboot_cfr_validate_var_binary(buffer, &offset, header->size,
							       CB_TAG_CFR_VARCHAR_DEF_VALUE);
		if (EFI_ERROR(status)) {
			return status;
		}

		status = cdk2_coreboot_cfr_validate_var_binary(buffer, &offset, header->size,
							       CB_TAG_CFR_VARCHAR_OPT_NAME);
		if (EFI_ERROR(status)) {
			return status;
		}

		status = cdk2_coreboot_cfr_validate_var_binary(buffer, &offset, header->size,
							       CB_TAG_CFR_VARCHAR_UI_NAME);
		if (EFI_ERROR(status)) {
			return status;
		}

		cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, &offset, header->size,
						     CB_TAG_CFR_VARCHAR_UI_HELPTEXT);
		cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, &offset, header->size,
						     CB_TAG_CFR_DEP_VALUES);
		return (offset == header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;

	case CB_TAG_CFR_OPTION_COMMENT:
		offset = sizeof(CFR_OPTION_COMMENT);
		status = cdk2_coreboot_cfr_validate_var_binary(buffer, &offset, header->size,
							       CB_TAG_CFR_VARCHAR_UI_NAME);
		if (EFI_ERROR(status)) {
			return status;
		}

		cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, &offset, header->size,
						     CB_TAG_CFR_VARCHAR_UI_HELPTEXT);
		cdk2_coreboot_cfr_extract_var_binary((UINT8 *)buffer, &offset, header->size,
						     CB_TAG_CFR_DEP_VALUES);
		return (offset == header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;

	default:
		return EFI_COMPROMISED_DATA;
	}
}

static EFI_STATUS cdk2_coreboot_cfr_validate_form(const CFR_OPTION_FORM *form, UINTN form_size)
{
	EFI_STATUS status;

	if (form == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_cfr_validate_object((const UINT8 *)form, form_size, 0);
	if (EFI_ERROR(status) || form->tag != CB_TAG_CFR_OPTION_FORM ||
	    form->size != form_size) {
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS cdk2_coreboot_append_cfr_hobs(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
						const struct cdk2_coreboot_handoff *coreboot)
{
	const void *record;
	const struct cb_cfr *root;
	const CFR_OPTION_FORM *form;
	UINTN processed_length;
	EFI_STATUS status;

	status = cdk2_coreboot_find_record(coreboot, CB_TAG_CFR_ROOT, sizeof(*root), &record);
	if (status == EFI_NOT_FOUND) {
		return EFI_SUCCESS;
	}

	if (EFI_ERROR(status)) {
		return status;
	}

	root = (const struct cb_cfr *)record;
	if (root->version != CB_CFR_VERSION || root->size < sizeof(*root) ||
	    cdk2_coreboot_crc32(root + 1, root->size - sizeof(*root)) != root->checksum) {
		return EFI_COMPROMISED_DATA;
	}

	processed_length = sizeof(*root);
	while (processed_length < root->size) {
		if (root->size - processed_length < sizeof(*form)) {
			return EFI_COMPROMISED_DATA;
		}

		form = (const CFR_OPTION_FORM *)((const UINT8 *)root + processed_length);
		if (form->size > root->size - processed_length) {
			return EFI_COMPROMISED_DATA;
		}

		status = cdk2_coreboot_cfr_validate_form(form, form->size);
		if (EFI_ERROR(status)) {
			return EFI_COMPROMISED_DATA;
		}

		status = cdk2_coreboot_append_guid_hob(handoff, &m_cdk2_cfr_setup_menu_form_guid,
						       form, form->size);
		if (EFI_ERROR(status)) {
			return status;
		}

		processed_length += form->size;
	}

	return EFI_SUCCESS;
}

struct cdk2_coreboot_hob_append_state {
	EFI_PHYSICAL_ADDRESS end_of_hob_list;
	EFI_PHYSICAL_ADDRESS free_memory_bottom;
	EFI_HOB_GENERIC_HEADER end_marker;
};

static UINT32 cdk2_coreboot_pixel_mask(UINT8 size, UINT8 position)
{
	if (size == 0 || position >= 32 || size > 32 - position) {
		return 0;
	}

	if (size == 32) {
		return MAX_UINT32;
	}

	return ((1U << size) - 1U) << position;
}

static void cdk2_coreboot_copy_bytes(void *destination, const void *source, UINTN length)
{
	UINT8 *destination_bytes;
	const UINT8 *source_bytes;
	UINTN index;

	destination_bytes = (UINT8 *)destination;
	source_bytes = (const UINT8 *)source;
	for (index = 0; index < length; index++) {
		destination_bytes[index] = source_bytes[index];
	}
}

struct cdk2_native_idt_gate {
	UINT16 offset_low;
	UINT16 selector;
	UINT8 ist;
	UINT8 attributes;
	UINT16 offset_middle;
	UINT32 offset_high;
	UINT32 reserved;
};

struct cdk2_native_idtr {
	UINT16 limit;
	UINTN base;
} __packed;

#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
#if defined(__GNUC__)
static struct cdk2_native_idt_gate m_cdk2_native_idt[256] __aligned(16);
#else
static struct cdk2_native_idt_gate m_cdk2_native_idt[256];
#endif

#endif

static void cdk2_coreboot_io_write8(UINT16 port, UINT8 value)
{
#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
	__asm__ volatile("outb %0, %w1" : : "a"(value), "Nd"(port));
#else
	(void)port;
	(void)value;
#endif
}

static UINT32 cdk2_coreboot_mmio_read32(UINTN address)
{
#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
	UINT32 value;

	__asm__ volatile("movl %1, %0"
			 : "=r"(value)
			 : "m"(*(const UINT32 *)(UINTN)address)
			 : "memory");
	return value;
#else
	(void)address;
	return 0;
#endif
}

static void cdk2_coreboot_mmio_write32(UINTN address, UINT32 value)
{
#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
	__asm__ volatile("movl %1, %0"
			 : "=m"(*(UINT32 *)(UINTN)address)
			 : "r"(value)
			 : "memory");
#else
	(void)address;
	(void)value;
#endif
}

static UINT64 cdk2_coreboot_mmio_read64(UINTN address)
{
#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
	UINT64 value;

	__asm__ volatile("movq %1, %0"
			 : "=r"(value)
			 : "m"(*(const UINT64 *)(UINTN)address)
			 : "memory");
	return value;
#else
	(void)address;
	return 0;
#endif
}

static void cdk2_coreboot_mmio_write64(UINTN address, UINT64 value)
{
#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
	__asm__ volatile("movq %1, %0"
			 : "=m"(*(UINT64 *)(UINTN)address)
			 : "r"(value)
			 : "memory");
#else
	(void)address;
	(void)value;
#endif
}

static UINT32 cdk2_coreboot_io_apic_read(UINT32 reg)
{
	cdk2_coreboot_mmio_write32(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x00U, reg);
	return cdk2_coreboot_mmio_read32(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x10U);
}

static void cdk2_coreboot_io_apic_write(UINT32 reg, UINT32 value)
{
	cdk2_coreboot_mmio_write32(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x00U, reg);
	cdk2_coreboot_mmio_write32(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x10U, value);
}

static void cdk2_coreboot_disable_hpet_interrupts(void)
{
	UINT64 capabilities;
	UINT64 configuration;
	UINT64 timer_configuration;
	UINTN timer_count;
	UINTN timer_index;
	UINTN timer_address;

	capabilities = cdk2_coreboot_mmio_read64(CDK2_COREBOOT_HPET_BASE_ADDRESS +
						 CDK2_COREBOOT_HPET_CAPABILITIES_OFFSET);
	if ((capabilities & 0xffU) == 0 || capabilities == MAX_UINT64) {
		return;
	}

	configuration = cdk2_coreboot_mmio_read64(CDK2_COREBOOT_HPET_BASE_ADDRESS +
						  CDK2_COREBOOT_HPET_CONFIGURATION_OFFSET);
	configuration &= ~(CDK2_COREBOOT_HPET_MAIN_COUNTER_ENABLE |
			   CDK2_COREBOOT_HPET_LEGACY_ROUTE_ENABLE);
	cdk2_coreboot_mmio_write64(CDK2_COREBOOT_HPET_BASE_ADDRESS +
					   CDK2_COREBOOT_HPET_CONFIGURATION_OFFSET,
				   configuration);

	/* HPET interrupt status is write-one-to-clear. */
	cdk2_coreboot_mmio_write64(CDK2_COREBOOT_HPET_BASE_ADDRESS +
					   CDK2_COREBOOT_HPET_INTERRUPT_STATUS_OFFSET,
				   MAX_UINT64);

	timer_count = ((capabilities >> 8) & 0x1fU) + 1U;
	for (timer_index = 0; timer_index < timer_count; timer_index++) {
		timer_address = CDK2_COREBOOT_HPET_BASE_ADDRESS +
			       CDK2_COREBOOT_HPET_TIMER_BASE_OFFSET +
			       timer_index * CDK2_COREBOOT_HPET_TIMER_STRIDE +
			       CDK2_COREBOOT_HPET_TIMER_CONFIGURATION;
		timer_configuration = cdk2_coreboot_mmio_read64(timer_address);
		timer_configuration &= ~(CDK2_COREBOOT_HPET_TIMER_INTERRUPT_ENABLE |
					CDK2_COREBOOT_HPET_TIMER_MSI_ENABLE);
		cdk2_coreboot_mmio_write64(timer_address, timer_configuration);
	}
}

static void cdk2_coreboot_mask_io_apic_interrupts(void)
{
	UINT32 io_apic_version;
	UINT32 redirection_count;
	UINT32 index;
	UINT32 redirection_low;

	io_apic_version = cdk2_coreboot_io_apic_read(CDK2_COREBOOT_IOAPIC_VERSION_REGISTER);
	if (io_apic_version == 0 || io_apic_version == MAX_UINT32) {
		return;
	}

	redirection_count = ((io_apic_version >> 16) & 0xffU) + 1U;
	if (redirection_count > 0x100U) {
		redirection_count = 0x100U;
	}

	for (index = 0; index < redirection_count; index++) {
		redirection_low =
			cdk2_coreboot_io_apic_read(CDK2_COREBOOT_IOAPIC_REDIR_LOW(index));
		cdk2_coreboot_io_apic_write(CDK2_COREBOOT_IOAPIC_REDIR_LOW(index),
					    redirection_low | CDK2_COREBOOT_IOAPIC_REDIR_MASK);
	}
}

static EFI_STATUS cdk2_coreboot_validate_framebuffer_geometry(
	const struct cb_framebuffer *framebuffer)
{
	UINT64 minimum_line_bits;
	UINT64 minimum_line_bytes;
	UINT64 stride_bits;

	if (framebuffer == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (framebuffer->bits_per_pixel == 0 || framebuffer->bits_per_pixel > 32 ||
	    framebuffer->x_resolution == 0 || framebuffer->y_resolution == 0 ||
	    framebuffer->bytes_per_line == 0 ||
	    framebuffer->bytes_per_line > MAX_UINT32 / framebuffer->y_resolution ||
	    framebuffer->bytes_per_line > MAX_UINT32 / 8U) {
		return EFI_COMPROMISED_DATA;
	}

	minimum_line_bits = (UINT64)framebuffer->x_resolution * framebuffer->bits_per_pixel;
	minimum_line_bytes = (minimum_line_bits + 7U) / 8U;
	if (minimum_line_bytes > framebuffer->bytes_per_line) {
		return EFI_COMPROMISED_DATA;
	}

	stride_bits = (UINT64)framebuffer->bytes_per_line * 8U;
	if ((stride_bits % framebuffer->bits_per_pixel) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI cdk2_coreboot_build_platform_hobs(struct cdk2_native_context *context,
							   void **handoff)
{
	UINT8 physical_address_bits;
	UINT32 maximum_function;
	UINT32 eax;
	EFI_STATUS status;
	const void *record;
	const struct cb_serial *serial;
	const struct cb_framebuffer *framebuffer;
	const struct cb_smmstorev2 *smm_store;
	const struct lb_efi_fw_info *firmware;
	const struct cb_tpm_physical_presence *tpm_ppi;
	const struct cb_string *version;
	const struct cb_string *extra_version;
	UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO serial_info;
	SERIAL_PORT_INFO legacy_serial_info;
	EFI_PEI_GRAPHICS_INFO_HOB graphics_info;
	EFI_HOB_HANDOFF_INFO_TABLE *hob;
	SMMSTORE_INFO smm_store_info;
	FIRMWARE_INFO firmware_info;
	TCG_PHYSICAL_PRESENCE_INFO tpm_ppi_info;
	UINT32 red_mask;
	UINT32 green_mask;
	UINT32 blue_mask;
	UINT32 reserved_mask;
	UINTN length;
	UINTN version_length;

	if (context == NULL || handoff == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_coreboot_update_acpi_handoff(&m_coreboot_handoff);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_build_hobs(&m_coreboot_handoff, context->hob_memory_bottom,
					  context->hob_memory_top,
					  context->hob_free_memory_bottom,
					  context->hob_free_memory_top,
					  CONFIG_CDK2_CAPSULE != 0, (void **)&hob);
	if (EFI_ERROR(status)) {
		return status;
	}

	*handoff = hob;

	status = cdk2_coreboot_append_memory_allocation_hob(
		hob, context->payload_base, context->payload_size, efi_boot_services_data);
	if (EFI_ERROR(status)) {
		return status;
	}

	physical_address_bits = 36;
#if defined(__x86_64__)
	__asm__ volatile("cpuid" : "=a"(eax) : "a"(0x80000000U) : "rbx", "rcx", "rdx");
	maximum_function = eax;
	if (maximum_function >= 0x80000008U) {
		__asm__ volatile("cpuid" : "=a"(eax) : "a"(0x80000008U) : "rbx", "rcx", "rdx");
		physical_address_bits = (UINT8)(eax & 0xffU);
	}
#endif

	status = cdk2_coreboot_append_cpu_hob(hob, physical_address_bits, 16);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_append_coreboot_table_hob(hob, &m_coreboot_handoff);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_append_acpi_hobs(hob, &m_coreboot_handoff);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_append_smbios_hob(hob, &m_coreboot_handoff);
	if (EFI_ERROR(status)) {
		return status;
	}

	/*
	 * CFR backs the optional setup UI. Match the legacy ParseMiscInfo() path by
	 * continuing when the data is absent, unsupported, or malformed.
	 */
	(void)cdk2_coreboot_append_cfr_hobs(hob, &m_coreboot_handoff);

#if CONFIG_CDK2_CAPSULE
	status = cdk2_coreboot_append_capsule_hobs(hob, &m_coreboot_handoff);
	if (EFI_ERROR(status)) {
		return status;
	}
#endif

	status = cdk2_coreboot_find_record(&m_coreboot_handoff, CB_TAG_SERIAL,
					   CDK2_COREBOOT_SERIAL_MIN_SIZE, &record);
	if (!EFI_ERROR(status)) {
		serial = (const struct cb_serial *)record;
		serial_info = (UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO){0};
		serial_info.header.revision = UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_REVISION;
		serial_info.header.length = sizeof(serial_info);
		serial_info.use_mmio = (serial->type == CB_SERIAL_TYPE_IO_MAPPED) ? FALSE : TRUE;
		serial_info.register_stride = (UINT8)serial->regwidth;
		serial_info.baud_rate = serial->baud;
		serial_info.register_base = serial->baseaddr;
		status = cdk2_coreboot_append_guid_hob(hob, &m_cdk2_serial_port_info_guid,
						       &serial_info, sizeof(serial_info));
		if (EFI_ERROR(status)) {
			return status;
		}

		if (serial->size >=
			    CDK2_COREBOOT_RECORD_FIELD_END(struct cb_serial, input_hertz) &&
		    serial->input_hertz != 0) {
			legacy_serial_info = (SERIAL_PORT_INFO){0};
			legacy_serial_info.revision = 1;
			legacy_serial_info.type = serial->type;
			legacy_serial_info.base_addr = serial->baseaddr;
			legacy_serial_info.baud = serial->baud;
			legacy_serial_info.reg_width = serial->regwidth;
			legacy_serial_info.input_hertz = serial->input_hertz;
			if (serial->size >=
			    CDK2_COREBOOT_RECORD_FIELD_END(struct cb_serial, uart_pci_addr)) {
				legacy_serial_info.uart_pci_addr = serial->uart_pci_addr;
			}

			status = cdk2_coreboot_append_guid_hob(hob,
							       &m_cdk2_legacy_serial_port_info_guid,
							       &legacy_serial_info,
							       sizeof(legacy_serial_info));
			if (EFI_ERROR(status)) {
				return status;
			}
		}
	} else if (status != EFI_NOT_FOUND) {
		return status;
	}

	status = cdk2_coreboot_find_record(&m_coreboot_handoff, CB_TAG_FRAMEBUFFER,
						   CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE, &record);
	if (!EFI_ERROR(status)) {
		framebuffer = (const struct cb_framebuffer *)record;
		status = cdk2_coreboot_validate_framebuffer_geometry(framebuffer);
		if (EFI_ERROR(status)) {
			return status;
		}

		red_mask = cdk2_coreboot_pixel_mask(framebuffer->red_mask_size,
						   framebuffer->red_mask_pos);
		green_mask = cdk2_coreboot_pixel_mask(framebuffer->green_mask_size,
						     framebuffer->green_mask_pos);
		blue_mask = cdk2_coreboot_pixel_mask(framebuffer->blue_mask_size,
						    framebuffer->blue_mask_pos);
		reserved_mask = cdk2_coreboot_pixel_mask(framebuffer->reserved_mask_size,
							framebuffer->reserved_mask_pos);
		if ((framebuffer->red_mask_size != 0 && red_mask == 0) ||
		    (framebuffer->green_mask_size != 0 && green_mask == 0) ||
		    (framebuffer->blue_mask_size != 0 && blue_mask == 0) ||
		    (framebuffer->reserved_mask_size != 0 && reserved_mask == 0)) {
			return EFI_COMPROMISED_DATA;
		}

		graphics_info = (EFI_PEI_GRAPHICS_INFO_HOB){0};
		graphics_info.frame_buffer_base = framebuffer->physical_address;
		graphics_info.frame_buffer_size =
			(UINT64)framebuffer->bytes_per_line * framebuffer->y_resolution;
		graphics_info.graphics_mode.version = 0;
		graphics_info.graphics_mode.horizontal_resolution = framebuffer->x_resolution;
		graphics_info.graphics_mode.vertical_resolution = framebuffer->y_resolution;
		graphics_info.graphics_mode.pixels_per_scan_line =
			(framebuffer->bytes_per_line * 8U) / framebuffer->bits_per_pixel;
		graphics_info.graphics_mode.pixel_information.red_mask = red_mask;
		graphics_info.graphics_mode.pixel_information.green_mask = green_mask;
		graphics_info.graphics_mode.pixel_information.blue_mask = blue_mask;
		graphics_info.graphics_mode.pixel_information.reserved_mask = reserved_mask;
		graphics_info.graphics_mode.pixel_format = pixel_bit_mask;
		if (framebuffer->bits_per_pixel == 32 && framebuffer->red_mask_size == 8 &&
		    framebuffer->green_mask_size == 8 && framebuffer->blue_mask_size == 8 &&
		    framebuffer->reserved_mask_size == 8 && framebuffer->red_mask_pos == 0 &&
		    framebuffer->green_mask_pos == 8 && framebuffer->blue_mask_pos == 16) {
			graphics_info.graphics_mode.pixel_format =
				pixel_red_green_blue_reserved8_bit_per_color;
		} else if (framebuffer->bits_per_pixel == 32 &&
			   framebuffer->red_mask_size == 8 &&
			   framebuffer->green_mask_size == 8 &&
			   framebuffer->blue_mask_size == 8 &&
			   framebuffer->reserved_mask_size == 8 &&
			   framebuffer->blue_mask_pos == 0 &&
			   framebuffer->green_mask_pos == 8 &&
			   framebuffer->red_mask_pos == 16) {
			graphics_info.graphics_mode.pixel_format =
				pixel_blue_green_red_reserved8_bit_per_color;
		}

		status = cdk2_coreboot_append_guid_hob(hob, &m_cdk2_graphics_info_hob_guid,
						       &graphics_info, sizeof(graphics_info));
		if (EFI_ERROR(status)) {
			return status;
		}
	} else if (status != EFI_NOT_FOUND) {
		return status;
	}

	status = cdk2_coreboot_find_record(&m_coreboot_handoff, CB_TAG_SMMSTOREV2,
					   CDK2_COREBOOT_SMMSTOREV2_MIN_SIZE, &record);
	if (!EFI_ERROR(status)) {
		smm_store = (const struct cb_smmstorev2 *)record;
		smm_store_info = (SMMSTORE_INFO){0};
		smm_store_info.com_buffer = smm_store->com_buffer;
		smm_store_info.com_buffer_size = smm_store->com_buffer_size;
		smm_store_info.num_blocks = smm_store->num_blocks;
		smm_store_info.block_size = smm_store->block_size;
		smm_store_info.mmio_address = smm_store->mmap_addr;
		smm_store_info.apm_cmd = smm_store->apm_cmd;
		status = cdk2_coreboot_append_guid_hob(hob, &m_cdk2_smm_store_info_hob_guid,
						       &smm_store_info, sizeof(smm_store_info));
		if (EFI_ERROR(status)) {
			return status;
		}
	} else if (status != EFI_NOT_FOUND) {
		return status;
	}

	status = cdk2_coreboot_find_record(&m_coreboot_handoff, CB_TAG_FW_INFO,
					   CDK2_COREBOOT_FW_INFO_MIN_SIZE, &record);
	if (!EFI_ERROR(status)) {
		firmware = (const struct lb_efi_fw_info *)record;
		firmware_info = (FIRMWARE_INFO){0};
		version_length = 0;
		cdk2_coreboot_copy_bytes(&firmware_info.type, firmware->guid,
					 sizeof(firmware_info.type));
		firmware_info.version = firmware->version;
		firmware_info.lowest_supported_version = firmware->lowest_supported_version;
		firmware_info.image_size = firmware->fw_size;

		status = cdk2_coreboot_find_record(&m_coreboot_handoff, CB_TAG_VERSION,
						   sizeof(struct cb_record) + 1,
						   (const void **)&version);
		if (!EFI_ERROR(status)) {
			length = cdk2_coreboot_string_record_length(version);
			if (length >= sizeof(firmware_info.version_str)) {
				length = sizeof(firmware_info.version_str) - 1;
			}

			cdk2_coreboot_copy_bytes(firmware_info.version_str, version->string,
						 length);
			version_length = length;
		} else if (status != EFI_NOT_FOUND) {
			return status;
		}

		status = cdk2_coreboot_find_record(&m_coreboot_handoff, CB_TAG_EXTRA_VERSION,
						   sizeof(struct cb_record) + 1,
						   (const void **)&extra_version);
		if (!EFI_ERROR(status)) {
			length = cdk2_coreboot_string_record_length(extra_version);
			if (length > sizeof(firmware_info.version_str) - 1 - version_length) {
				length = sizeof(firmware_info.version_str) - 1 - version_length;
			}

			cdk2_coreboot_copy_bytes(&firmware_info.version_str[version_length],
						 extra_version->string, length);
			version_length += length;
		} else if (status != EFI_NOT_FOUND) {
			return status;
		}

		firmware_info.version_str[version_length] = '\0';

		status = cdk2_coreboot_append_guid_hob(hob, &m_cdk2_firmware_info_hob_guid,
						       &firmware_info, sizeof(firmware_info));
		if (EFI_ERROR(status)) {
			return status;
		}
	} else if (status != EFI_NOT_FOUND) {
		return status;
	}

	status = cdk2_coreboot_find_record(&m_coreboot_handoff, CB_TAG_TPM_PPI_HANDOFF,
					   CDK2_COREBOOT_TPM_PPI_MIN_SIZE, &record);
	if (!EFI_ERROR(status)) {
		tpm_ppi = (const struct cb_tpm_physical_presence *)record;
		tpm_ppi_info = (TCG_PHYSICAL_PRESENCE_INFO){0};
		tpm_ppi_info.ppi_address = tpm_ppi->ppi_address;
		if (tpm_ppi->tpm_version == LB_TPM_VERSION_TPM_VERSION_1_2) {
			tpm_ppi_info.tpm_version = UEFIPAYLOAD_TPM_VERSION_1_2;
		} else if (tpm_ppi->tpm_version == LB_TPM_VERSION_TPM_VERSION_2) {
			tpm_ppi_info.tpm_version = UEFIPAYLOAD_TPM_VERSION_2;
		}

		if ((tpm_ppi->ppi_version >> 4) == 1 && (tpm_ppi->ppi_version & 0x0f) >= 3) {
			tpm_ppi_info.ppi_version = UEFIPAYLOAD_TPM_PPI_VERSION_1_30;
		}

		status = cdk2_coreboot_append_guid_hob(hob,
						       &m_cdk2_tcg_physical_presence_info_hob_guid,
						       &tpm_ppi_info, sizeof(tpm_ppi_info));
		if (EFI_ERROR(status)) {
			return status;
		}
	} else if (status != EFI_NOT_FOUND) {
		return status;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI cdk2_coreboot_find_hob_memory(struct cdk2_native_context *context,
						       UINTN *hob_mem_base)
{
	if (context == NULL || hob_mem_base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	/* entry32.S maps 0..128 GiB while this stage builds HOBs and loads DXE. */
	return cdk2_coreboot_find_hob_memory_base(&m_coreboot_handoff, context->payload_base,
						  context->payload_size,
						  context->hob_region_size,
						  CDK2_COREBOOT_TEMP_MAP_LIMIT, hob_mem_base);
}

static EFI_STATUS EFIAPI
cdk2_coreboot_initialize_floating_point(struct cdk2_native_context *context)
{
#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
	UINTN cr4;
	UINTN handler;
	UINTN index;
	const UINT32 mxcsr = CDK2_COREBOOT_UEFI_MXCSR;
	struct cdk2_native_idtr idtr;
#endif

	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

#if defined(__x86_64__) && !defined(CDK2_COREBOOT_BACKEND_TEST)
	__asm__ volatile("fninit");
	__asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
	cr4 |= BIT9;
	__asm__ volatile("mov %0, %%cr4" : : "r"(cr4) : "memory");
	__asm__ volatile("ldmxcsr %0" : : "m"(mxcsr) : "memory");

	handler = (UINTN)cdk2_native_exception_dead_loop;
	for (index = 0; index < ARRAY_SIZE(m_cdk2_native_idt); index++) {
		m_cdk2_native_idt[index].offset_low = (UINT16)handler;
		m_cdk2_native_idt[index].selector = 0x18;
		m_cdk2_native_idt[index].ist = 0;
		m_cdk2_native_idt[index].attributes = 0x8e;
		m_cdk2_native_idt[index].offset_middle = (UINT16)(handler >> 16);
		m_cdk2_native_idt[index].offset_high = (UINT32)(handler >> 32);
		m_cdk2_native_idt[index].reserved = 0;
	}

	idtr.limit = sizeof(m_cdk2_native_idt) - 1;
	idtr.base = (UINTN)m_cdk2_native_idt;
	__asm__ volatile("lidt %0" : : "m"(idtr));
#endif
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
cdk2_coreboot_mask_legacy_interrupts(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	cdk2_coreboot_disable_hpet_interrupts();
	cdk2_coreboot_mask_io_apic_interrupts();
	cdk2_coreboot_io_write8(CDK2_COREBOOT_8259_MASK_REGISTER_MASTER, 0xFF);
	cdk2_coreboot_io_write8(CDK2_COREBOOT_8259_MASK_REGISTER_SLAVE, 0xFF);
	cdk2_coreboot_io_write8(CDK2_COREBOOT_8259_COMMAND_REGISTER_SLAVE,
				CDK2_COREBOOT_8259_EOI);
	cdk2_coreboot_io_write8(CDK2_COREBOOT_8259_COMMAND_REGISTER_MASTER,
				CDK2_COREBOOT_8259_EOI);
	return EFI_SUCCESS;
}

static EFI_STATUS
cdk2_coreboot_save_hob_append_state(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
				    struct cdk2_coreboot_hob_append_state *state)
{
	EFI_HOB_GENERIC_HEADER *end;

	if (handoff == NULL || state == NULL || handoff->efi_end_of_hob_list == 0) {
		return EFI_INVALID_PARAMETER;
	}

	if (handoff->efi_end_of_hob_list > (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - sizeof(*end))) {
		return EFI_COMPROMISED_DATA;
	}

	end = (EFI_HOB_GENERIC_HEADER *)(UINTN)handoff->efi_end_of_hob_list;
	if (end->hob_type != EFI_HOB_TYPE_END_OF_HOB_LIST || end->hob_length != sizeof(*end)) {
		return EFI_COMPROMISED_DATA;
	}

	state->end_of_hob_list = handoff->efi_end_of_hob_list;
	state->free_memory_bottom = handoff->efi_free_memory_bottom;
	state->end_marker = *end;
	return EFI_SUCCESS;
}

static void
cdk2_coreboot_restore_hob_append_state(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
				       const struct cdk2_coreboot_hob_append_state *state)
{
	if (handoff == NULL || state == NULL || state->end_of_hob_list == 0) {
		return;
	}

	handoff->efi_end_of_hob_list = state->end_of_hob_list;
	handoff->efi_free_memory_bottom = state->free_memory_bottom;
	*(EFI_HOB_GENERIC_HEADER *)(UINTN)state->end_of_hob_list = state->end_marker;
}

static EFI_STATUS cdk2_coreboot_append_loaded_dxe_core_hobs(
	EFI_HOB_HANDOFF_INFO_TABLE *handoff, EFI_PHYSICAL_ADDRESS fv_base, UINTN fv_size,
	const EFI_GUID *module_name, EFI_PHYSICAL_ADDRESS image_base, UINTN image_size,
	EFI_PHYSICAL_ADDRESS entry_point)
{
	struct cdk2_coreboot_hob_append_state append_state;
	EFI_STATUS status;

	status = cdk2_coreboot_save_hob_append_state(handoff, &append_state);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_append_fv_hob(handoff, fv_base, fv_size);
	if (EFI_ERROR(status)) {
		goto failed;
	}

	status = cdk2_coreboot_append_memory_allocation_hob(handoff, image_base, image_size,
							    efi_boot_services_code);
	if (EFI_ERROR(status)) {
		goto failed;
	}

	status = cdk2_coreboot_append_module_hob(handoff, module_name, image_base, image_size,
						 entry_point);
	if (EFI_ERROR(status)) {
		goto failed;
	}

	return EFI_SUCCESS;

failed:
	cdk2_coreboot_restore_hob_append_state(handoff, &append_state);
	return status;
}

static EFI_STATUS EFIAPI cdk2_coreboot_load_dxe_core(struct cdk2_native_context *context,
						     EFI_PHYSICAL_ADDRESS *entry_point,
						     EFI_PHYSICAL_ADDRESS *image_base,
						     UINTN *image_size)
{
	struct cdk2_native_dxe_core dxe_core;
	EFI_HOB_HANDOFF_INFO_TABLE *handoff;
	EFI_PHYSICAL_ADDRESS destination;
	EFI_PHYSICAL_ADDRESS saved_allocation_bottom;
	EFI_PHYSICAL_ADDRESS saved_allocation_top;
	EFI_PHYSICAL_ADDRESS saved_free_memory_top;
	UINTN fv_start;
	UINTN fv_end;
	UINTN fv_size;
	UINTN available_pages;
	UINTN pages;
	UINTN loaded_image_size;
	EFI_STATUS status;

	fv_start = (UINTN)__cdk2_fv_start;
	fv_end = (UINTN)__cdk2_fv_end;
	if (context == NULL || entry_point == NULL || image_base == NULL ||
	    image_size == NULL || context->hob_list == NULL || fv_start == 0 ||
	    fv_end <= fv_start) {
		return EFI_NOT_FOUND;
	}

	handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)context->hob_list;
	fv_size = fv_end - fv_start;
	status = cdk2_native_find_dxe_core((const void *)fv_start, fv_size, &dxe_core);
	if (EFI_ERROR(status)) {
		return status;
	}

	if (context->allocation_top < context->allocation_bottom) {
		return EFI_COMPROMISED_DATA;
	}

	available_pages = (context->allocation_top - context->allocation_bottom) / EFI_PAGE_SIZE;
	pages = (available_pages < CDK2_COREBOOT_DXE_MAX_PAGES) ? available_pages :
								 CDK2_COREBOOT_DXE_MAX_PAGES;
	if (pages == 0) {
		return EFI_OUT_OF_RESOURCES;
	}

	saved_allocation_bottom = context->allocation_bottom;
	saved_allocation_top = context->allocation_top;
	saved_free_memory_top = handoff->efi_free_memory_top;
	status = cdk2_native_allocate_pages(context, pages, &destination);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_load_pe32_plus(dxe_core.pe32_image, dxe_core.pe32_size, destination,
					    pages * EFI_PAGE_SIZE, image_base, image_size,
					    entry_point);
	if (EFI_ERROR(status)) {
		goto failed;
	}

	loaded_image_size = EFI_SIZE_TO_PAGES(*image_size) * EFI_PAGE_SIZE;
	status = cdk2_coreboot_append_loaded_dxe_core_hobs(
		handoff, (EFI_PHYSICAL_ADDRESS)(UINTN)__cdk2_fv_start, fv_size,
		&dxe_core.dxe_core_file->name, *image_base, loaded_image_size, *entry_point);
	if (EFI_ERROR(status)) {
		goto failed;
	}

	return EFI_SUCCESS;

failed:
	context->allocation_bottom = saved_allocation_bottom;
	context->allocation_top = saved_allocation_top;
	handoff->efi_free_memory_top = saved_free_memory_top;
	*entry_point = 0;
	*image_base = 0;
	*image_size = 0;
	return status;
}

static void CDK2_COREBOOT_NORETURN cdk2_coreboot_jump_to_dxe_core(
	EFI_PHYSICAL_ADDRESS entry_point, void *hob_list, void *stack_top)
{
#if defined(__x86_64__)
	__asm__ volatile(
		"cli\n\t"
		"mov %[stack], %%rsp\n\t"
		"xor %%rbp, %%rbp\n\t"
		"mov %[hob], %%rcx\n\t"
		"xor %%rdx, %%rdx\n\t"
		"xor %%r8, %%r8\n\t"
		"xor %%r9, %%r9\n\t"
		"jmp *%[entry]\n\t"
		:
		: [stack] "r"(stack_top), [hob] "c"(hob_list),
		  [entry] "a"((UINTN)entry_point)
		: "rdx", "r8", "r9", "memory");
#endif
	__builtin_unreachable();
}

static EFI_STATUS EFIAPI cdk2_coreboot_transfer(struct cdk2_native_context *context)
{
	EFI_HOB_HANDOFF_INFO_TABLE *handoff;
	EFI_PHYSICAL_ADDRESS saved_allocation_bottom;
	EFI_PHYSICAL_ADDRESS saved_allocation_top;
	EFI_PHYSICAL_ADDRESS saved_free_memory_top;
	EFI_PHYSICAL_ADDRESS stack_base;
	UINTN stack_pages;
	EFI_STATUS status;

	if (context == NULL || context->hob_list == NULL || context->image_entry_point == 0) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_native_handoff(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)context->hob_list;
	saved_allocation_bottom = context->allocation_bottom;
	saved_allocation_top = context->allocation_top;
	saved_free_memory_top = handoff->efi_free_memory_top;
	stack_pages = 0x20;
	status = cdk2_native_allocate_pages(context, stack_pages, &stack_base);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_append_stack_hob((EFI_HOB_HANDOFF_INFO_TABLE *)context->hob_list,
						stack_base, stack_pages * EFI_PAGE_SIZE);
	if (EFI_ERROR(status)) {
		context->allocation_bottom = saved_allocation_bottom;
		context->allocation_top = saved_allocation_top;
		handoff->efi_free_memory_top = saved_free_memory_top;
		return status;
	}

	cdk2_coreboot_jump_to_dxe_core(
		context->image_entry_point, context->hob_list,
		(void *)(UINTN)(stack_base + stack_pages * EFI_PAGE_SIZE - 0x28));
	return EFI_DEVICE_ERROR;
}

#if defined(CDK2_COREBOOT_BACKEND_TEST)
struct cdk2_coreboot_test_cbmem_result
EFIAPI
cdk2_coreboot_test_find_cbmem_entry(const struct cdk2_coreboot_handoff *coreboot, UINT32 id,
				    UINT32 minimum_size)
{
	struct cdk2_coreboot_test_cbmem_result result;

	result = (struct cdk2_coreboot_test_cbmem_result){0};
	result.status = cdk2_coreboot_find_cbmem_entry(coreboot, id, minimum_size, &result.base,
						      &result.size);
	return result;
}

struct cdk2_coreboot_test_cbmem_result
EFIAPI
cdk2_coreboot_test_find_acpi_rsdp(const struct cdk2_coreboot_handoff *coreboot)
{
	struct cdk2_coreboot_test_cbmem_result result;

	result = (struct cdk2_coreboot_test_cbmem_result){0};
	result.status = cdk2_coreboot_find_acpi_rsdp(coreboot, &result.base);
	return result;
}

EFI_STATUS
EFIAPI
cdk2_coreboot_test_build_acpi_board_info(EFI_PHYSICAL_ADDRESS rsdp_address, void *board_info)
{
	return cdk2_coreboot_build_acpi_board_info(
		rsdp_address, (ACPI_BOARD_INFO *)board_info, NULL, NULL);
}

EFI_STATUS
EFIAPI
cdk2_coreboot_test_validate_framebuffer(const struct cb_framebuffer *framebuffer)
{
	return cdk2_coreboot_validate_framebuffer_geometry(framebuffer);
}

EFI_STATUS
EFIAPI
cdk2_coreboot_test_append_tpm_event_hobs(void *handoff,
					 EFI_ACPI_DESCRIPTION_HEADER *tpm2_table)
{
	return cdk2_coreboot_append_tpm_event_hobs(
		(EFI_HOB_HANDOFF_INFO_TABLE *)handoff, tpm2_table);
}

EFI_STATUS
EFIAPI
cdk2_coreboot_test_append_smbios_hob(void *handoff,
				     const struct cdk2_coreboot_handoff *coreboot)
{
	return cdk2_coreboot_append_smbios_hob((EFI_HOB_HANDOFF_INFO_TABLE *)handoff,
					       coreboot);
}

EFI_STATUS
EFIAPI
cdk2_coreboot_test_transfer(struct cdk2_native_context *context)
{
	return cdk2_coreboot_transfer(context);
}

EFI_STATUS
EFIAPI
cdk2_coreboot_test_append_loaded_dxe_core_hobs(void *handoff,
					       EFI_PHYSICAL_ADDRESS fv_base, UINTN fv_size,
					       const void *module_name,
					       EFI_PHYSICAL_ADDRESS image_base,
					       UINTN image_size,
					       EFI_PHYSICAL_ADDRESS entry_point)
{
	return cdk2_coreboot_append_loaded_dxe_core_hobs(
		(EFI_HOB_HANDOFF_INFO_TABLE *)handoff, fv_base, fv_size,
		(const EFI_GUID *)module_name, image_base, image_size, entry_point);
}
#endif

EFI_STATUS
EFIAPI
cdk2_platform_initialize_native_context(struct cdk2_native_context *context,
					UINTN bootloader_parameter)
{
	struct cdk2_coreboot_handoff handoff;
	EFI_STATUS status;
	UINTN image_start;
	UINTN image_end;

	image_start = (UINTN)__cdk2_image_start;
	image_end = (UINTN)__cdk2_image_end;
	if (context == NULL || image_end <= image_start) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_native_initialize_stage_context(context, bootloader_parameter);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_coreboot_parse(bootloader_parameter, &handoff);
	if (EFI_ERROR(status)) {
		return status;
	}

	m_coreboot_handoff = handoff;
	context->payload_base = (EFI_PHYSICAL_ADDRESS)image_start;
	context->payload_size = image_end - image_start;
	context->hob_region_size = CDK2_COREBOOT_HOB_REGION_SIZE;
	context->ops.build_platform_hobs = cdk2_coreboot_build_platform_hobs;
	context->ops.find_hob_memory = cdk2_coreboot_find_hob_memory;
	context->ops.initialize_floating_point = cdk2_coreboot_initialize_floating_point;
	context->ops.mask_legacy_interrupts = cdk2_coreboot_mask_legacy_interrupts;
	context->ops.load_dxe_core = cdk2_coreboot_load_dxe_core;
	context->ops.transfer = cdk2_coreboot_transfer;
	return EFI_SUCCESS;
}
