/** @file

Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Guid/MmProfileData.h>

#include "BlSmmCpuPayloadMm.h"

/**
  Return if the Address is the NonMmram logging Address.

  @param[in] Address the address to be checked

  @return TRUE  The address is the NonMmram logging Address.
  @return FALSE The address is not the NonMmram logging Address.
**/
BOOLEAN
IsNonMmramLoggingAddress (
  IN UINT64  Address
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    if ((Address >= Hob.ResourceDescriptor->PhysicalStart) && (Address < Hob.ResourceDescriptor->PhysicalStart + Hob.ResourceDescriptor->ResourceLength)) {
      if ((Hob.ResourceDescriptor->ResourceAttribute & MM_RESOURCE_ATTRIBUTE_LOGGING) != 0) {
        return TRUE;
      }

      return FALSE;
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  return FALSE;
}

/**
  Return if the Address is forbidden as SMM communication buffer.

  @param[in] Address the address to be checked

  @return TRUE  The address is forbidden as SMM communication buffer.
  @return FALSE The address is allowed as SMM communication buffer.
**/
BOOLEAN
IsSmmCommBufferForbiddenAddress (
  IN UINT64  Address
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    if ((Address >= Hob.ResourceDescriptor->PhysicalStart) && (Address < Hob.ResourceDescriptor->PhysicalStart + Hob.ResourceDescriptor->ResourceLength)) {
      return FALSE;
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  return TRUE;
}

/**
  Build Memory Region from ResourceDescriptor HOBs by excluding Logging attribute range.

  @param[out]     MemoryRegion            Returned Non-Mmram Memory regions.
  @param[out]     MemoryRegionCount       A pointer to the number of Memory regions.
**/
VOID
BuildMemoryMapFromResDescHobs (
  OUT MM_CPU_MEMORY_REGION  **MemoryRegion,
  OUT UINTN                 *MemoryRegionCount
  )
{
  EFI_PEI_HOB_POINTERS  Hob;
  UINTN                 Count;
  UINTN                 Index;
  EFI_PHYSICAL_ADDRESS  MaxPhysicalAddress;
  EFI_PHYSICAL_ADDRESS  ResourceHobEnd;

  ASSERT (MemoryRegion != NULL && MemoryRegionCount != NULL);

  *MemoryRegion      = NULL;
  *MemoryRegionCount = 0;
  MaxPhysicalAddress = LShiftU64 (1, mPhysicalAddressBits);

  //
  // Get the count.
  //
  Count   = 0;
  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    if ((Hob.ResourceDescriptor->ResourceAttribute & MM_RESOURCE_ATTRIBUTE_LOGGING) == 0) {
      ResourceHobEnd = Hob.ResourceDescriptor->PhysicalStart + Hob.ResourceDescriptor->ResourceLength;

      ASSERT (ResourceHobEnd <= MaxPhysicalAddress);
      if (ResourceHobEnd > MaxPhysicalAddress) {
        CpuDeadLoop ();
      }

      //
      // Resource HOBs describe all accessible non-smram regions.
      // Logging attribute range is treated as not present. Not-present ranges are not included in this memory map.
      //
      Count++;
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  *MemoryRegionCount = Count;

  *MemoryRegion = (MM_CPU_MEMORY_REGION *)AllocateZeroPool (sizeof (MM_CPU_MEMORY_REGION) * Count);
  ASSERT (*MemoryRegion != NULL);

  Index   = 0;
  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob.Raw != NULL) {
    if ((Hob.ResourceDescriptor->ResourceAttribute & MM_RESOURCE_ATTRIBUTE_LOGGING) == 0) {
      ASSERT (Index < Count);
      (*MemoryRegion)[Index].Base      = Hob.ResourceDescriptor->PhysicalStart;
      (*MemoryRegion)[Index].Length    = Hob.ResourceDescriptor->ResourceLength;
      (*MemoryRegion)[Index].Attribute = EFI_MEMORY_XP;
      if (Hob.ResourceDescriptor->ResourceAttribute == EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTED) {
        (*MemoryRegion)[Index].Attribute |= EFI_MEMORY_RO;
      }

      Index++;
    }

    Hob.Raw = GET_NEXT_HOB (Hob);
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob.Raw);
  }

  return;
}

/**
  Build extended protection MemoryRegion.

  The caller is responsible for freeing MemoryRegion via FreePool().

  @param[out]     MemoryRegion         Returned Non-Mmram Memory regions.
  @param[out]     MemoryRegionCount    A pointer to the number of Memory regions.
**/
VOID
CreateExtendedProtectionRange (
  OUT MM_CPU_MEMORY_REGION  **MemoryRegion,
  OUT UINTN                 *MemoryRegionCount
  )
{
  BuildMemoryMapFromResDescHobs (MemoryRegion, MemoryRegionCount);
}

/**
  Create the Non-Mmram Memory Region within the ResourceDescriptor HOBs
  without Logging attribute.

  The caller is responsible for freeing MemoryRegion via FreePool().

  @param[in]      PhysicalAddressBits  The bits of physical address to map.
  @param[out]     MemoryRegion         Returned Non-Mmram Memory regions.
  @param[out]     MemoryRegionCount    A pointer to the number of Memory regions.
**/
VOID
CreateNonMmramMemMap (
  IN  UINT8                 PhysicalAddressBits,
  OUT MM_CPU_MEMORY_REGION  **MemoryRegion,
  OUT UINTN                 *MemoryRegionCount
  )
{
  BuildMemoryMapFromResDescHobs (MemoryRegion, MemoryRegionCount);
}
