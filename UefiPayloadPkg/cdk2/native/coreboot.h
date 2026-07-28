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
  CDK2_COREBOOT_MEMORY_RANGE    MemoryRanges[CDK2_COREBOOT_MAX_MEMORY_RANGES];
} CDK2_COREBOOT_HANDOFF;

UINT16
Cdk2CorebootChecksum16 (
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

#endif
