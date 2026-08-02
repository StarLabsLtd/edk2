/** @file

  Freestanding coreboot table validation for the native cdk2 stage.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_NATIVE_COREBOOT_H_
#define CDK2_NATIVE_COREBOOT_H_

#include <Uefi.h>
#include <Coreboot.h>

#define CDK2_COREBOOT_MAX_TABLE_BYTES    (1024U * 1024U)
#define CDK2_COREBOOT_MAX_RECORDS        256U
#define CDK2_COREBOOT_MAX_MEMORY_RANGES  128U
#define CDK2_COREBOOT_MAX_FORWARD_DEPTH  4U

#define CDK2_COREBOOT_RECORD_FIELD_END(Type, Field) \
  ((UINT32)(OFFSET_OF (Type, Field) + sizeof (((Type *)0)->Field)))

#define CDK2_COREBOOT_SERIAL_MIN_SIZE \
  CDK2_COREBOOT_RECORD_FIELD_END (struct cb_serial, regwidth)
#define CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE \
  CDK2_COREBOOT_RECORD_FIELD_END (struct cb_framebuffer, reserved_mask_size)
#define CDK2_COREBOOT_SMMSTOREV2_MIN_SIZE \
  CDK2_COREBOOT_RECORD_FIELD_END (struct cb_smmstorev2, apm_cmd)
#define CDK2_COREBOOT_FW_INFO_MIN_SIZE \
  CDK2_COREBOOT_RECORD_FIELD_END (struct lb_efi_fw_info, fw_size)
#define CDK2_COREBOOT_TPM_PPI_MIN_SIZE \
  CDK2_COREBOOT_RECORD_FIELD_END (struct cb_tpm_physical_presence, ppi_version)
#define CDK2_COREBOOT_ACPI_RSDP_MIN_SIZE \
  CDK2_COREBOOT_RECORD_FIELD_END (struct cb_acpi_rsdp, rsdp_pointer)
#define CDK2_COREBOOT_PAYLOAD_RESOURCE_HANDOFF_MIN_SIZE \
  CDK2_COREBOOT_RECORD_FIELD_END (struct cb_payload_resource_handoff, lifetime_flags)
#define CDK2_COREBOOT_PAYLOAD_RESOURCE_SECTION_MIN_SIZE \
  (sizeof (struct cb_payload_resource_section))
#define CDK2_COREBOOT_PRH_FRAMEBUFFER_MIN_SIZE \
  (sizeof (struct cb_prh_framebuffer_entry))

#define CDK2_COREBOOT_PAYLOAD_RESOURCE_MAX_SECTIONS  64U

typedef struct {
  EFI_PHYSICAL_ADDRESS  Base;
  UINT64                Size;
  UINT32                Type;
} CDK2_COREBOOT_MEMORY_RANGE;

typedef struct {
  CONST struct cb_header       *Header;
  UINTN                         TableSize;
  UINT32                        RecordCount;
  UINT32                        MemoryRangeCount;
  UINT32                        UsableRamCount;
  EFI_PHYSICAL_ADDRESS          LargestUsableRamBase;
  UINT64                        LargestUsableRamSize;
  UINT64                        ForwardAddress;
  EFI_STATUS                    PayloadResourceHandoffStatus;
  CONST struct cb_payload_resource_handoff *PayloadResourceHandoff;
  CDK2_COREBOOT_MEMORY_RANGE    MemoryRanges[CDK2_COREBOOT_MAX_MEMORY_RANGES];
} CDK2_COREBOOT_HANDOFF;

UINT16
Cdk2CorebootChecksum16 (
  IN CONST VOID  *Buffer,
  IN UINTN        Length
  );

UINT32
Cdk2CorebootCalculateCrc32 (
  IN CONST VOID  *Buffer,
  IN UINTN        Length
  );

EFI_STATUS
Cdk2CorebootParseTable (
  IN  CONST VOID             *Table,
  IN  UINTN                   TableSize,
  OUT CDK2_COREBOOT_HANDOFF  *Handoff
  );

EFI_STATUS
Cdk2CorebootParse (
  IN  UINTN                   BootloaderParameter,
  OUT CDK2_COREBOOT_HANDOFF  *Handoff
  );

EFI_STATUS
Cdk2CorebootFindRecord (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Handoff,
  IN  UINT32                        Tag,
  IN  UINT32                        MinimumSize,
  OUT CONST VOID                  **Record
  );

EFI_STATUS
Cdk2CorebootFindPayloadResourceSection (
  IN  CONST CDK2_COREBOOT_HANDOFF            *Handoff,
  IN  UINT16                                  Type,
  OUT CONST struct cb_payload_resource_section **Section
  );

#endif
