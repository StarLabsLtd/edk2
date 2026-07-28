/** @file

  Freestanding HOB construction from a validated coreboot handoff.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "coreboot_hobs.h"

#include <Guid/MemoryAllocationHob.h>

#define CDK2_COREBOOT_HOB_RESOURCE_ATTRIBUTES  \
  (EFI_RESOURCE_ATTRIBUTE_PRESENT |            \
   EFI_RESOURCE_ATTRIBUTE_INITIALIZED |        \
   EFI_RESOURCE_ATTRIBUTE_TESTED |             \
   EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |        \
   EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |  \
   EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE | \
   EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE)

STATIC
UINTN
Cdk2CorebootAlignUp8 (
  IN UINTN  Value
  )
{
  return (Value + 7U) & ~(UINTN)7U;
}

STATIC
BOOLEAN
Cdk2CorebootRangeValid (
  IN UINTN  Bottom,
  IN UINTN  Top
  )
{
  return Bottom <= Top;
}

STATIC
VOID *
Cdk2CorebootAppendHob (
  IN OUT UINTN                 *Cursor,
  IN     UINTN                  Limit,
  IN     UINT16                 Type,
  IN     UINTN                  Length
  )
{
  EFI_HOB_GENERIC_HEADER  *Hob;
  UINTN                    AlignedLength;

  if (Cursor == NULL || Length < sizeof (EFI_HOB_GENERIC_HEADER) ||
      Length > MAX_UINT16)
  {
    return NULL;
  }

  AlignedLength = Cdk2CorebootAlignUp8 (Length);
  if (*Cursor > Limit || AlignedLength > Limit - *Cursor) {
    return NULL;
  }

  Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)*Cursor;
  for (UINTN Index = 0; Index < AlignedLength; Index++) {
    ((UINT8 *)(VOID *)Hob)[Index] = 0;
  }

  Hob->HobType   = Type;
  Hob->HobLength = (UINT16)Length;
  *Cursor       += AlignedLength;
  return Hob;
}

STATIC
UINT32
Cdk2CorebootFindTolud (
  IN CONST CDK2_COREBOOT_HANDOFF  *Coreboot
  )
{
  UINT32  Tolud;
  UINTN   Index;
  UINT64  End;

  Tolud = 0;
  for (Index = 0; Index < Coreboot->MemoryRangeCount; Index++) {
    if ((Coreboot->MemoryRanges[Index].Type != CB_MEM_RAM) &&
        (Coreboot->MemoryRanges[Index].Type != CB_MEM_ACPI) &&
        (Coreboot->MemoryRanges[Index].Type != CB_MEM_NVS))
    {
      continue;
    }

    End = Coreboot->MemoryRanges[Index].Base + Coreboot->MemoryRanges[Index].Size;
    if (End <= 0x100000000ULL && End > Tolud) {
      Tolud = (UINT32)End;
    }
  }

  return Tolud;
}

STATIC
EFI_RESOURCE_TYPE
Cdk2CorebootResourceType (
  IN CONST CDK2_COREBOOT_MEMORY_RANGE  *Range,
  IN UINT32                              Tolud
  )
{
  if ((Range->Type == CB_MEM_RAM) ||
      (Range->Type == CB_MEM_ACPI) ||
      (Range->Type == CB_MEM_NVS))
  {
    return EFI_RESOURCE_SYSTEM_MEMORY;
  }

  if (Range->Base < Tolud) {
    return EFI_RESOURCE_MEMORY_RESERVED;
  }

  if (Range->Base < 0x100000000ULL) {
    return EFI_RESOURCE_MEMORY_MAPPED_IO;
  }

  return EFI_RESOURCE_MEMORY_RESERVED;
}

STATIC
EFI_MEMORY_TYPE
Cdk2CorebootAllocationType (
  IN UINT32  Type
  )
{
  if (Type == CB_MEM_ACPI) {
    return EfiACPIReclaimMemory;
  }

  if (Type == CB_MEM_NVS) {
    return EfiACPIMemoryNVS;
  }

  return EfiReservedMemoryType;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendBeforeEnd (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     UINT16                        Type,
  IN     UINTN                         Length,
  OUT    VOID                        **NewHob
  )
{
  EFI_HOB_GENERIC_HEADER  *End;
  UINTN                    Cursor;
  UINTN                    Limit;
  UINTN                    FirstLength;
  UINTN                    EndLength;

  if (Handoff == NULL || NewHob == NULL || Handoff->EfiEndOfHobList == 0) {
    return EFI_INVALID_PARAMETER;
  }

  End         = (EFI_HOB_GENERIC_HEADER *)(UINTN)Handoff->EfiEndOfHobList;
  Cursor      = (UINTN)End;
  Limit       = (UINTN)Handoff->EfiFreeMemoryTop;
  if (Cursor > Limit) {
    return EFI_COMPROMISED_DATA;
  }

  FirstLength = Cdk2CorebootAlignUp8 (Length);
  EndLength   = Cdk2CorebootAlignUp8 (sizeof (*End));
  if (FirstLength > Limit - Cursor || EndLength > Limit - Cursor - FirstLength) {
    return EFI_OUT_OF_RESOURCES;
  }

  *NewHob = Cdk2CorebootAppendHob (&Cursor, Limit, Type, Length);
  if (*NewHob == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  End = (EFI_HOB_GENERIC_HEADER *)Cdk2CorebootAppendHob (
                                                   &Cursor,
                                                   Limit,
                                                   EFI_HOB_TYPE_END_OF_HOB_LIST,
                                                   sizeof (*End)
                                                   );
  if (End == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Handoff->EfiEndOfHobList    = (EFI_PHYSICAL_ADDRESS)(UINTN)End;
  Handoff->EfiFreeMemoryBottom = Cursor;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendResource (
  IN OUT UINTN                              *Cursor,
  IN     UINTN                               Limit,
  IN     CONST CDK2_COREBOOT_MEMORY_RANGE  *Range,
  IN     UINT32                              Tolud
  )
{
  EFI_HOB_RESOURCE_DESCRIPTOR  *Resource;

  Resource = (EFI_HOB_RESOURCE_DESCRIPTOR *)Cdk2CorebootAppendHob (
                                                   Cursor,
                                                   Limit,
                                                   EFI_HOB_TYPE_RESOURCE_DESCRIPTOR,
                                                   sizeof (*Resource)
                                                   );
  if (Resource == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Resource->ResourceType      = Cdk2CorebootResourceType (Range, Tolud);
  Resource->ResourceAttribute = CDK2_COREBOOT_HOB_RESOURCE_ATTRIBUTES;
  Resource->PhysicalStart     = Range->Base;
  Resource->ResourceLength    = Range->Size;
  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootAppendFvHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         BaseAddress,
  IN     UINT64                       Length
  )
{
  EFI_HOB_FIRMWARE_VOLUME  *Fv;
  EFI_STATUS                 Status;

  Status = Cdk2CorebootAppendBeforeEnd (
             Handoff,
             EFI_HOB_TYPE_FV,
             sizeof (*Fv),
             (VOID **)&Fv
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Fv->BaseAddress = BaseAddress;
  Fv->Length      = Length;
  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootAppendGuidHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     CONST EFI_GUID              *Guid,
  IN     CONST VOID                   *Data,
  IN     UINTN                        DataLength
  )
{
  EFI_HOB_GUID_TYPE  *GuidHob;
  EFI_STATUS           Status;
  UINT8               *Destination;
  CONST UINT8         *Source;
  UINTN                Index;

  if (Handoff == NULL || Guid == NULL || (Data == NULL && DataLength != 0) ||
      DataLength > MAX_UINT16 - sizeof (*GuidHob))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2CorebootAppendBeforeEnd (
             Handoff,
             EFI_HOB_TYPE_GUID_EXTENSION,
             sizeof (*GuidHob) + DataLength,
             (VOID **)&GuidHob
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  GuidHob->Name = *Guid;
  Destination  = (UINT8 *)(VOID *)(GuidHob + 1);
  Source       = (CONST UINT8 *)Data;
  for (Index = 0; Index < DataLength; Index++) {
    Destination[Index] = Source[Index];
  }

  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootAppendMemoryAllocationHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         BaseAddress,
  IN     UINT64                       Length,
  IN     EFI_MEMORY_TYPE              MemoryType
  )
{
  EFI_HOB_MEMORY_ALLOCATION  *Allocation;
  EFI_STATUS                  Status;

  if (Length == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2CorebootAppendBeforeEnd (
             Handoff,
             EFI_HOB_TYPE_MEMORY_ALLOCATION,
             sizeof (*Allocation),
             (VOID **)&Allocation
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Allocation->AllocDescriptor.MemoryBaseAddress = BaseAddress;
  Allocation->AllocDescriptor.MemoryLength      = Length;
  Allocation->AllocDescriptor.MemoryType        = MemoryType;
  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootAppendCpuHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     UINT8                        SizeOfMemorySpace,
  IN     UINT8                        SizeOfIoSpace
  )
{
  EFI_HOB_CPU  *Cpu;
  EFI_STATUS    Status;

  Status = Cdk2CorebootAppendBeforeEnd (
             Handoff,
             EFI_HOB_TYPE_CPU,
             sizeof (*Cpu),
             (VOID **)&Cpu
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Cpu->SizeOfMemorySpace = SizeOfMemorySpace;
  Cpu->SizeOfIoSpace     = SizeOfIoSpace;
  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootAppendModuleHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     CONST EFI_GUID                *ModuleName,
  IN     EFI_PHYSICAL_ADDRESS          BaseAddress,
  IN     UINT64                        Length,
  IN     EFI_PHYSICAL_ADDRESS          EntryPoint
  )
{
  EFI_HOB_MEMORY_ALLOCATION_MODULE  *Module;
  EFI_GUID                            AllocationGuid;
  EFI_STATUS                          Status;
  UINT8                               *Destination;
  CONST UINT8                         *Source;
  UINTN                                Index;

  if (ModuleName == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  AllocationGuid = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_MODULE_GUID;
  Status = Cdk2CorebootAppendBeforeEnd (
             Handoff,
             EFI_HOB_TYPE_MEMORY_ALLOCATION,
             sizeof (*Module),
             (VOID **)&Module
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Module->MemoryAllocationHeader.Name              = AllocationGuid;
  Module->MemoryAllocationHeader.MemoryBaseAddress = BaseAddress;
  Module->MemoryAllocationHeader.MemoryLength      = Length;
  Module->MemoryAllocationHeader.MemoryType        = EfiBootServicesCode;
  Source = (CONST UINT8 *)ModuleName;
  Destination = (UINT8 *)&Module->ModuleName;
  for (Index = 0; Index < sizeof (EFI_GUID); Index++) {
    Destination[Index] = Source[Index];
  }

  Module->EntryPoint = EntryPoint;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendAllocation (
  IN OUT UINTN                              *Cursor,
  IN     UINTN                               Limit,
  IN     CONST CDK2_COREBOOT_MEMORY_RANGE  *Range
  )
{
  EFI_HOB_MEMORY_ALLOCATION  *Allocation;

  if ((Range->Type != CB_MEM_ACPI) && (Range->Type != CB_MEM_NVS)) {
    return EFI_SUCCESS;
  }

  Allocation = (EFI_HOB_MEMORY_ALLOCATION *)Cdk2CorebootAppendHob (
                                                          Cursor,
                                                          Limit,
                                                          EFI_HOB_TYPE_MEMORY_ALLOCATION,
                                                          sizeof (*Allocation)
                                                          );
  if (Allocation == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Allocation->AllocDescriptor.MemoryBaseAddress = Range->Base;
  Allocation->AllocDescriptor.MemoryLength      = Range->Size;
  Allocation->AllocDescriptor.MemoryType        = Cdk2CorebootAllocationType (Range->Type);
  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootBuildHobs (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Coreboot,
  IN  VOID                          *EfiMemoryBottom,
  IN  VOID                          *EfiMemoryTop,
  IN  VOID                          *EfiFreeMemoryBottom,
  IN  VOID                          *EfiFreeMemoryTop,
  OUT EFI_HOB_HANDOFF_INFO_TABLE   **Handoff
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *HobInfo;
  EFI_HOB_GENERIC_HEADER      *End;
  UINTN                        MemoryBottom;
  UINTN                        MemoryTop;
  UINTN                        FreeMemoryBottom;
  UINTN                        FreeMemoryTop;
  UINTN                        Cursor;
  UINT32                       Tolud;
  UINTN                        Index;
  EFI_STATUS                   Status;

  if (Coreboot == NULL || Handoff == NULL ||
      EfiMemoryBottom == NULL || EfiMemoryTop == NULL ||
      EfiFreeMemoryBottom == NULL || EfiFreeMemoryTop == NULL)
  {
    return EFI_INVALID_PARAMETER;
  }

  MemoryBottom     = (UINTN)EfiMemoryBottom;
  MemoryTop        = (UINTN)EfiMemoryTop;
  FreeMemoryBottom = (UINTN)EfiFreeMemoryBottom;
  FreeMemoryTop    = (UINTN)EfiFreeMemoryTop;
  if (!Cdk2CorebootRangeValid (MemoryBottom, MemoryTop) ||
      !Cdk2CorebootRangeValid (FreeMemoryBottom, FreeMemoryTop) ||
      FreeMemoryBottom < MemoryBottom || FreeMemoryTop > MemoryTop)
  {
    return EFI_INVALID_PARAMETER;
  }

  Cursor = Cdk2CorebootAlignUp8 (FreeMemoryBottom);
  if (Cursor > FreeMemoryTop) {
    return EFI_OUT_OF_RESOURCES;
  }

  HobInfo = (EFI_HOB_HANDOFF_INFO_TABLE *)Cdk2CorebootAppendHob (
                                                     &Cursor,
                                                     FreeMemoryTop,
                                                     EFI_HOB_TYPE_HANDOFF,
                                                     sizeof (*HobInfo)
                                                     );
  if (HobInfo == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  HobInfo->Version              = EFI_HOB_HANDOFF_TABLE_VERSION;
  HobInfo->BootMode             = BOOT_WITH_FULL_CONFIGURATION;
  HobInfo->EfiMemoryBottom      = MemoryBottom;
  HobInfo->EfiMemoryTop         = MemoryTop;
  HobInfo->EfiFreeMemoryTop     = FreeMemoryTop;
  HobInfo->EfiFreeMemoryBottom  = Cursor;
  Tolud                        = Cdk2CorebootFindTolud (Coreboot);

  for (Index = 0; Index < Coreboot->MemoryRangeCount; Index++) {
    Status = Cdk2CorebootAppendResource (
               &Cursor,
               FreeMemoryTop,
               &Coreboot->MemoryRanges[Index],
               Tolud
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = Cdk2CorebootAppendAllocation (
               &Cursor,
               FreeMemoryTop,
               &Coreboot->MemoryRanges[Index]
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  End = (EFI_HOB_GENERIC_HEADER *)Cdk2CorebootAppendHob (
                                           &Cursor,
                                           FreeMemoryTop,
                                           EFI_HOB_TYPE_END_OF_HOB_LIST,
                                           sizeof (*End)
                                           );
  if (End == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  HobInfo->EfiEndOfHobList = (EFI_PHYSICAL_ADDRESS)(UINTN)End;
  HobInfo->EfiFreeMemoryBottom = Cursor;
  *Handoff = HobInfo;
  return EFI_SUCCESS;
}
