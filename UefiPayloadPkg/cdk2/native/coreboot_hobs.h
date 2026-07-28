/** @file

  Freestanding HOB construction from a validated coreboot handoff.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_NATIVE_COREBOOT_HOBS_H_
#define CDK2_NATIVE_COREBOOT_HOBS_H_

#include <Uefi.h>
#include <Pi/PiBootMode.h>
#include <Pi/PiHob.h>

#include "coreboot.h"

EFI_STATUS
Cdk2CorebootBuildHobs (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Coreboot,
  IN  VOID                          *EfiMemoryBottom,
  IN  VOID                          *EfiMemoryTop,
  IN  VOID                          *EfiFreeMemoryBottom,
  IN  VOID                          *EfiFreeMemoryTop,
  OUT EFI_HOB_HANDOFF_INFO_TABLE   **Handoff
  );

EFI_STATUS
Cdk2CorebootAppendFvHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         BaseAddress,
  IN     UINT64                       Length
  );

EFI_STATUS
Cdk2CorebootAppendGuidHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     CONST EFI_GUID              *Guid,
  IN     CONST VOID                   *Data,
  IN     UINTN                        DataLength
  );

EFI_STATUS
Cdk2CorebootAppendMemoryAllocationHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         BaseAddress,
  IN     UINT64                       Length,
  IN     EFI_MEMORY_TYPE              MemoryType
  );

EFI_STATUS
Cdk2CorebootAppendCpuHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     UINT8                        SizeOfMemorySpace,
  IN     UINT8                        SizeOfIoSpace
  );

EFI_STATUS
Cdk2CorebootAppendModuleHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     CONST EFI_GUID                *ModuleName,
  IN     EFI_PHYSICAL_ADDRESS          BaseAddress,
  IN     UINT64                        Length,
  IN     EFI_PHYSICAL_ADDRESS          EntryPoint
  );

#endif
