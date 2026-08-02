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

#define CDK2_COREBOOT_1MB_MASK  0xfffffULL

STATIC CONST EFI_GUID  mCdk2PayloadResourceHandoffHobGuid =
  { 0xc263a6a9, 0x6938, 0x495e, { 0x95, 0xb6, 0x6a, 0x1a, 0x0b, 0x6b, 0xa8, 0x8e } };

STATIC
BOOLEAN
Cdk2CorebootAlignUp8 (
  IN  UINTN  Value,
  OUT UINTN  *AlignedValue
  )
{
  if (AlignedValue == NULL || Value > MAX_UINTN - 7U) {
    return FALSE;
  }

  *AlignedValue = (Value + 7U) & ~(UINTN)7U;
  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootAlignUp1Mb (
  IN  UINT64  Value,
  OUT UINT64  *AlignedValue
  )
{
  if (AlignedValue == NULL || Value > MAX_UINT64 - CDK2_COREBOOT_1MB_MASK) {
    return FALSE;
  }

  *AlignedValue = (Value + CDK2_COREBOOT_1MB_MASK) & ~CDK2_COREBOOT_1MB_MASK;
  return TRUE;
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
BOOLEAN
Cdk2CorebootMemoryRangeEnd (
  IN  CONST CDK2_COREBOOT_MEMORY_RANGE  *Range,
  OUT UINT64                            *End
  )
{
  if (Range == NULL || End == NULL || Range->Size == 0 ||
      Range->Base > MAX_UINT64 - Range->Size)
  {
    return FALSE;
  }

  *End = Range->Base + Range->Size;
  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootUintnRangeFits (
  IN UINT64  Base,
  IN UINT64  Length
  )
{
  if (Base > MAX_UINTN) {
    return FALSE;
  }

  return Length <= (UINT64)(MAX_UINTN - (UINTN)Base);
}

STATIC
BOOLEAN
Cdk2CorebootDescriptorRangeValid (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length
  )
{
  return (Length != 0) && (BaseAddress <= MAX_UINT64 - Length);
}

EFI_STATUS
Cdk2CorebootFindHobMemoryBase (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Coreboot,
  IN  EFI_PHYSICAL_ADDRESS          PayloadBase,
  IN  UINTN                         PayloadSize,
  IN  UINTN                         HobRegionSize,
  IN  UINT64                        TemporaryMapLimit,
  OUT UINTN                        *HobMemBase
  )
{
  CONST CDK2_COREBOOT_MEMORY_RANGE  *Range;
  UINT64                             PayloadEnd;
  UINT64                             Base;
  UINT64                             End;
  UINTN                              Index;

  if (Coreboot == NULL || HobMemBase == NULL ||
      PayloadSize == 0 || HobRegionSize == 0 || TemporaryMapLimit == 0 ||
      PayloadBase > MAX_UINT64 - PayloadSize)
  {
    return EFI_INVALID_PARAMETER;
  }

  if (Coreboot->MemoryRangeCount > ARRAY_SIZE (Coreboot->MemoryRanges)) {
    return EFI_COMPROMISED_DATA;
  }

  PayloadEnd = PayloadBase + PayloadSize;
  for (Index = 0; Index < Coreboot->MemoryRangeCount; Index++) {
    Range = &Coreboot->MemoryRanges[Index];
    if (Range->Type != CB_MEM_RAM) {
      continue;
    }

    if (!Cdk2CorebootMemoryRangeEnd (Range, &End)) {
      return EFI_COMPROMISED_DATA;
    }

    if (Range->Base >= TemporaryMapLimit) {
      continue;
    }

    if (!Cdk2CorebootAlignUp1Mb (Range->Base, &Base)) {
      continue;
    }

    if (Base >= TemporaryMapLimit) {
      continue;
    }

    if (End > TemporaryMapLimit) {
      End = TemporaryMapLimit;
    }

    if ((Base < PayloadEnd) && (PayloadBase < End)) {
      if (!Cdk2CorebootAlignUp1Mb (PayloadEnd, &Base)) {
        continue;
      }
    }

    if ((End > Base) && (End - Base >= HobRegionSize) &&
        Cdk2CorebootUintnRangeFits (Base, HobRegionSize))
    {
      *HobMemBase = (UINTN)Base;
      return EFI_SUCCESS;
    }
  }

  return EFI_OUT_OF_RESOURCES;
}

STATIC
EFI_STATUS
Cdk2CorebootValidateMemoryRanges (
  IN CONST CDK2_COREBOOT_HANDOFF  *Coreboot
  )
{
  UINTN   Index;
  UINTN   OtherIndex;
  UINT64  End;
  UINT64  OtherEnd;

  if (Coreboot->MemoryRangeCount > ARRAY_SIZE (Coreboot->MemoryRanges)) {
    return EFI_COMPROMISED_DATA;
  }

  for (Index = 0; Index < Coreboot->MemoryRangeCount; Index++) {
    if (!Cdk2CorebootMemoryRangeEnd (&Coreboot->MemoryRanges[Index], &End)) {
      return EFI_COMPROMISED_DATA;
    }

    for (OtherIndex = Index + 1; OtherIndex < Coreboot->MemoryRangeCount; OtherIndex++) {
      if (!Cdk2CorebootMemoryRangeEnd (&Coreboot->MemoryRanges[OtherIndex], &OtherEnd)) {
        return EFI_COMPROMISED_DATA;
      }

      if ((Coreboot->MemoryRanges[Index].Base < OtherEnd) &&
          (Coreboot->MemoryRanges[OtherIndex].Base < End))
      {
        return EFI_COMPROMISED_DATA;
      }
    }
  }

  return EFI_SUCCESS;
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

  if (!Cdk2CorebootAlignUp8 (Length, &AlignedLength)) {
    return NULL;
  }

  if (AlignedLength > MAX_UINT16) {
    return NULL;
  }

  if (*Cursor > Limit || AlignedLength > Limit - *Cursor) {
    return NULL;
  }

  Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)*Cursor;
  for (UINTN Index = 0; Index < AlignedLength; Index++) {
    ((UINT8 *)(VOID *)Hob)[Index] = 0;
  }

  Hob->HobType   = Type;
  Hob->HobLength = (UINT16)AlignedLength;
  *Cursor       += AlignedLength;
  return Hob;
}

STATIC
UINT64
Cdk2CorebootFindTolud (
  IN CONST CDK2_COREBOOT_HANDOFF  *Coreboot
  )
{
  UINT64  Tolud;
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

    if (!Cdk2CorebootMemoryRangeEnd (&Coreboot->MemoryRanges[Index], &End)) {
      continue;
    }

    if (End <= 0x100000000ULL && End > Tolud) {
      Tolud = End;
    }
  }

  return Tolud;
}

STATIC
EFI_RESOURCE_TYPE
Cdk2CorebootResourceType (
  IN CONST CDK2_COREBOOT_MEMORY_RANGE  *Range,
  IN UINT64                              Tolud
  )
{
  if (Range->Type == CB_MEM_TABLE) {
    return EFI_RESOURCE_MEMORY_RESERVED;
  }

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
Cdk2CorebootValidateAppendHandoff (
  IN  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  OUT EFI_HOB_GENERIC_HEADER      **End
  )
{
  EFI_HOB_GENERIC_HEADER  *Hob;
  EFI_PHYSICAL_ADDRESS     ExpectedFreeMemoryBottom;
  UINTN                    EndAddress;
  UINTN                    HobAddress;
  UINTN                    HobLength;

  if (Handoff == NULL || End == NULL || Handoff->EfiEndOfHobList == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Handoff->Header.HobType != EFI_HOB_TYPE_HANDOFF ||
      Handoff->Header.HobLength != sizeof (*Handoff) ||
      Handoff->EfiMemoryBottom > Handoff->EfiMemoryTop ||
      Handoff->EfiFreeMemoryBottom > Handoff->EfiFreeMemoryTop ||
      Handoff->EfiFreeMemoryBottom < Handoff->EfiMemoryBottom ||
      Handoff->EfiFreeMemoryTop > Handoff->EfiMemoryTop ||
      Handoff->EfiEndOfHobList > (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - sizeof (**End)))
  {
    return EFI_COMPROMISED_DATA;
  }

  ExpectedFreeMemoryBottom = Handoff->EfiEndOfHobList + sizeof (**End);
  if (Handoff->EfiFreeMemoryBottom != ExpectedFreeMemoryBottom ||
      ExpectedFreeMemoryBottom > Handoff->EfiFreeMemoryTop)
  {
    return EFI_COMPROMISED_DATA;
  }

  EndAddress = (UINTN)Handoff->EfiEndOfHobList;
  Hob        = (EFI_HOB_GENERIC_HEADER *)(VOID *)Handoff;
  while ((UINTN)Hob < EndAddress) {
    HobAddress = (UINTN)Hob;
    if (EndAddress - HobAddress < sizeof (*Hob)) {
      return EFI_COMPROMISED_DATA;
    }

    HobLength = Hob->HobLength;
    if (HobLength < sizeof (*Hob) ||
        HobLength > EndAddress - HobAddress ||
        (HobLength & 7U) != 0 ||
        Hob->HobType == EFI_HOB_TYPE_END_OF_HOB_LIST)
    {
      return EFI_COMPROMISED_DATA;
    }

    Hob = (EFI_HOB_GENERIC_HEADER *)(VOID *)((UINT8 *)(VOID *)Hob + HobLength);
  }

  if ((UINTN)Hob != EndAddress) {
    return EFI_COMPROMISED_DATA;
  }

  *End = (EFI_HOB_GENERIC_HEADER *)(UINTN)Handoff->EfiEndOfHobList;
  if ((*End)->HobType != EFI_HOB_TYPE_END_OF_HOB_LIST ||
      (*End)->HobLength != sizeof (**End))
  {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
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
  EFI_STATUS               Status;

  if (NewHob == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2CorebootValidateAppendHandoff (Handoff, &End);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Cursor      = (UINTN)End;
  Limit       = (UINTN)Handoff->EfiFreeMemoryTop;
  if (Cursor > Limit) {
    return EFI_COMPROMISED_DATA;
  }

  if (!Cdk2CorebootAlignUp8 (Length, &FirstLength) ||
      !Cdk2CorebootAlignUp8 (sizeof (*End), &EndLength))
  {
    return EFI_OUT_OF_RESOURCES;
  }

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
  IN     UINT64                              Tolud
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

  if (!Cdk2CorebootDescriptorRangeValid (BaseAddress, Length)) {
    return EFI_INVALID_PARAMETER;
  }

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
Cdk2CorebootAppendCapsuleHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         BaseAddress,
  IN     UINT64                       Length
  )
{
  EFI_HOB_UEFI_CAPSULE  *Capsule;
  EFI_STATUS             Status;

  if (!Cdk2CorebootDescriptorRangeValid (BaseAddress, Length)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2CorebootAppendBeforeEnd (
             Handoff,
             EFI_HOB_TYPE_UEFI_CAPSULE,
             sizeof (*Capsule),
             (VOID **)&Capsule
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Capsule->BaseAddress = BaseAddress;
  Capsule->Length      = Length;
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

  if (!Cdk2CorebootDescriptorRangeValid (BaseAddress, Length)) {
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
Cdk2CorebootAppendStackHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         BaseAddress,
  IN     UINT64                       Length
  )
{
  EFI_HOB_MEMORY_ALLOCATION_STACK  *Stack;
  EFI_GUID                         AllocationGuid;
  EFI_STATUS                       Status;

  if (!Cdk2CorebootDescriptorRangeValid (BaseAddress, Length) ||
      ((BaseAddress & EFI_PAGE_MASK) != 0) ||
      ((Length & EFI_PAGE_MASK) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  AllocationGuid = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_STACK_GUID;
  Status = Cdk2CorebootAppendBeforeEnd (
             Handoff,
             EFI_HOB_TYPE_MEMORY_ALLOCATION,
             sizeof (*Stack),
             (VOID **)&Stack
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Stack->AllocDescriptor.Name              = AllocationGuid;
  Stack->AllocDescriptor.MemoryBaseAddress = BaseAddress;
  Stack->AllocDescriptor.MemoryLength      = Length;
  Stack->AllocDescriptor.MemoryType        = EfiBootServicesData;
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

  if (ModuleName == NULL ||
      !Cdk2CorebootDescriptorRangeValid (BaseAddress, Length))
  {
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

STATIC
EFI_STATUS
Cdk2CorebootAppendPayloadResourceHandoffHob (
  IN OUT UINTN                         *Cursor,
  IN     UINTN                          Limit,
  IN     CONST CDK2_COREBOOT_HANDOFF   *Coreboot
  )
{
  EFI_HOB_GUID_TYPE                       *GuidHob;
  CONST struct cb_payload_resource_handoff *PayloadResource;
  UINTN                                    Length;
  UINTN                                    Index;
  UINT8                                   *Destination;
  CONST UINT8                             *Source;

  if (Coreboot->PayloadResourceHandoffStatus != EFI_SUCCESS ||
      Coreboot->PayloadResourceHandoff == NULL)
  {
    return EFI_SUCCESS;
  }

  PayloadResource = Coreboot->PayloadResourceHandoff;
  if (PayloadResource->size > MAX_UINT16 - sizeof (*GuidHob)) {
    return EFI_SUCCESS;
  }

  Length = sizeof (*GuidHob) + PayloadResource->size;
  GuidHob = (EFI_HOB_GUID_TYPE *)Cdk2CorebootAppendHob (
                                  Cursor,
                                  Limit,
                                  EFI_HOB_TYPE_GUID_EXTENSION,
                                  Length
                                  );
  if (GuidHob == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  GuidHob->Name = mCdk2PayloadResourceHandoffHobGuid;
  Destination   = (UINT8 *)(VOID *)(GuidHob + 1);
  Source        = (CONST UINT8 *)PayloadResource;
  for (Index = 0; Index < PayloadResource->size; Index++) {
    Destination[Index] = Source[Index];
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootResolveBootMode (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Coreboot,
  IN  BOOLEAN                      CapsuleSupportEnabled,
  OUT EFI_BOOT_MODE                *BootMode
  )
{
  EFI_STATUS                 Status;
  CONST VOID                 *Record;
  CONST struct lb_boot_mode  *CorebootBootMode;
  CONST struct cb_boot_info  *BootInfo;

  if (Coreboot == NULL || BootMode == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *BootMode = BOOT_WITH_FULL_CONFIGURATION;
  if (Coreboot->Header == NULL && Coreboot->RecordCount == 0) {
    return EFI_SUCCESS;
  }

  if (CapsuleSupportEnabled) {
    Status = Cdk2CorebootFindRecord (
               Coreboot,
               CB_TAG_CAPSULE,
               sizeof (struct cb_range),
               &Record
               );
    if (!EFI_ERROR (Status)) {
      *BootMode = BOOT_ON_FLASH_UPDATE;
      return EFI_SUCCESS;
    }

    if (Status != EFI_NOT_FOUND) {
      return Status;
    }

    Status = Cdk2CorebootFindRecord (
               Coreboot,
               CB_TAG_BOOT_INFO,
               sizeof (*BootInfo),
               &Record
               );
    if (!EFI_ERROR (Status)) {
      BootInfo = (CONST struct cb_boot_info *)Record;
      if (BootInfo->is_disk_capsules_boot != 0) {
        *BootMode = BOOT_ON_FLASH_UPDATE;
        return EFI_SUCCESS;
      }
    } else if (Status != EFI_NOT_FOUND) {
      return Status;
    }
  }

  Status = Cdk2CorebootFindRecord (
             Coreboot,
             CB_TAG_BOOT_MODE,
             sizeof (*CorebootBootMode),
             &Record
             );
  if (Status == EFI_NOT_FOUND) {
    return EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  CorebootBootMode = (CONST struct lb_boot_mode *)Record;
  if (CorebootBootMode->boot_mode == LB_BOOT_MODE_FLASH_UPDATE) {
    *BootMode = BOOT_ON_FLASH_UPDATE;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootBuildHobs (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Coreboot,
  IN  VOID                          *EfiMemoryBottom,
  IN  VOID                          *EfiMemoryTop,
  IN  VOID                          *EfiFreeMemoryBottom,
  IN  VOID                          *EfiFreeMemoryTop,
  IN  BOOLEAN                        CapsuleSupportEnabled,
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
  UINT64                       Tolud;
  UINTN                        Index;
  EFI_BOOT_MODE                BootMode;
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

  if (!Cdk2CorebootAlignUp8 (FreeMemoryBottom, &Cursor)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Cursor > FreeMemoryTop) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = Cdk2CorebootValidateMemoryRanges (Coreboot);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootResolveBootMode (Coreboot, CapsuleSupportEnabled, &BootMode);
  if (EFI_ERROR (Status)) {
    return Status;
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
  HobInfo->BootMode             = BootMode;
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

  Status = Cdk2CorebootAppendPayloadResourceHandoffHob (
             &Cursor,
             FreeMemoryTop,
             Coreboot
             );
  if (EFI_ERROR (Status)) {
    return Status;
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
