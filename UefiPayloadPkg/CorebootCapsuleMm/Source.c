/** @file
  Admit source buffers only within coreboot's protected RAM map.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <PiMm.h>
#include "Source.h"
#include <Guid/CorebootCapsuleRam.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/StandaloneMmMemLib.h>

BOOLEAN
CapsuleSourceInit(CAPSULE_SOURCE *Source, EFI_PHYSICAL_ADDRESS Address, UINTN Size)
{
  EFI_PEI_HOB_POINTERS Hob;

  Source->Address = 0;
  Source->Size = 0;
  if (!Size || Address < 0x100000 || Address > MAX_UINT32 ||
      Size - 1 > MAX_UINT32 - Address || !MmIsBufferOutsideMmValid(Address, Size)) {
    return FALSE;
  }
  Hob.Raw = GetFirstHob(EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    if (CompareGuid(&Hob.ResourceDescriptor->Owner, &gCorebootCapsuleRamGuid) &&
        Hob.ResourceDescriptor->ResourceType == EFI_RESOURCE_SYSTEM_MEMORY &&
        Address >= Hob.ResourceDescriptor->PhysicalStart &&
        Address - Hob.ResourceDescriptor->PhysicalStart < Hob.ResourceDescriptor->ResourceLength &&
        Size <= Hob.ResourceDescriptor->ResourceLength -
                (Address - Hob.ResourceDescriptor->PhysicalStart)) {
      Source->Address = Address;
      Source->Size = Size;
      return TRUE;
    }
    Hob.Raw = GET_NEXT_HOB(Hob);
    Hob.Raw = GetNextHob(EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }
  return FALSE;
}

BOOLEAN
CapsuleSourceRead(VOID *Context, UINTN Offset, VOID *Buffer, UINTN Size)
{
  CAPSULE_SOURCE *Source = Context;

  if (!Source || !Source->Size || !Buffer || Offset > Source->Size ||
      Size > Source->Size - Offset) {
    return FALSE;
  }
  CopyMem(Buffer, (VOID *)(UINTN)(Source->Address + Offset), Size);
  return TRUE;
}
