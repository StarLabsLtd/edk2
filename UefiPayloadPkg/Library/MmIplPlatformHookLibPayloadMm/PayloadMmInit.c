/** @file
  This library allows platforms to customise SMM/MM loading.
  It shall be called in the payload MM IPL.

  Copyright (c) 2025, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmIplPlatformHookLib.h>
#include <Library/PayloadMmHelperLib.h>
#include <Library/PcdLib.h>
#include <Library/PeCoffLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MemoryAttribute.h>
#include <Protocol/MmAccess.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include "PayloadMmCmdInterface.h"

/**
  Allocate memory below 4G memory address.

  This function allocates memory below 4G memory address.

  @param  MemoryType   Memory type of memory to allocate.
  @param  Pages        The number of 4 KB pages to allocate.

  @return Allocated address for output.

**/
VOID *
AllocatePagesBelow4G (
  IN EFI_MEMORY_TYPE  MemoryType,
  IN UINTN            Pages
  )
{
  EFI_PHYSICAL_ADDRESS  Address;
  EFI_STATUS            Status;

  Address = 0xFFFFFFFF;

  Status = gBS->AllocatePages (
                  AllocateMaxAddress,
                  MemoryType,
                  Pages,
                  &Address
                  );
  ASSERT_EFI_ERROR (Status);

  return (VOID *)(UINTN)Address;
}

/**
  Performs platform specific tasks to alter how SMM/MM is loaded. This can be used to support MM.

  This function performs platform specific tasks to alter how SMM/MM is loaded.

  @retval EFI_SUCCESS       The platform hook completes successfully.
  @retval Other values      The paltform hook cannot complete due to some error.

**/
EFI_STATUS
EFIAPI
PlatformHookBeforeMmLoad (
  IN PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  UINTN  PageCount;

  //
  // Relocate it to match where it's going to,
  // but load it to a temporary buffer we'll provide to the coreboot driver.
  //
  ImageContext->DestinationAddress = ImageContext->ImageAddress;

  DEBUG ((DEBUG_INFO, "Payload MM loading MM Core at SMRAM address %x\n", (UINTN)ImageContext->DestinationAddress));

  PageCount = EFI_SIZE_TO_PAGES (ImageContext->ImageSize + ImageContext->SectionAlignment);
  ImageContext->ImageAddress = (PHYSICAL_ADDRESS)AllocatePagesBelow4G (EfiReservedMemoryType, PageCount);

  return EFI_SUCCESS;
}

/**
  Configure the mappings of MMRAM in the early page table.

  This function maps/unmaps the relevant regions of MMRAM in the DXE page table.
  It must be called to unmap MMRAM when done! MMRAM is locked, but this makes faults easier to debug.

  @param  SetUnset     Whether to map/unmap the relevant memory.

  @retval EFI_SUCCESS  The operation completed successfully.
  @retval Others       An error was encounterd.

**/
EFI_STATUS
PlatformMapMmEnvironment (
  IN BOOLEAN  SetUnset
  )
{
  EFI_MM_ACCESS_PROTOCOL         *MmAccess;
  EFI_STATUS                     Status;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL  *MemoryAttributeProtocol;
  EFI_MMRAM_DESCRIPTOR           *MmramDescriptor;
  UINTN                          MmramDescriptorTotalSize;
  EFI_PHYSICAL_ADDRESS           PayloadMmramAddress;
  UINTN                          MmramSize;
  UINTN                          Index;
  EFI_PHYSICAL_ADDRESS           BootloaderMmramAddress;

  Status = gBS->LocateProtocol (&gEfiMmAccessProtocolGuid, NULL, (VOID **)&MmAccess);
  ASSERT_EFI_ERROR (Status);

  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&MemoryAttributeProtocol);
  ASSERT_EFI_ERROR (Status);

  //
  // Retrieve MMRAM descriptors.
  //
  MmramDescriptor = NULL;
  MmramDescriptorTotalSize = 0;
  Status = MmAccess->GetCapabilities (MmAccess, &MmramDescriptorTotalSize, MmramDescriptor);
  ASSERT (Status == EFI_BUFFER_TOO_SMALL);

  MmramDescriptor = AllocatePool (MmramDescriptorTotalSize);
  Status = MmAccess->GetCapabilities (MmAccess, &MmramDescriptorTotalSize, MmramDescriptor);
  ASSERT_EFI_ERROR (Status);

  //
  // Discover MMRAM address and size.
  //
  PayloadMmramAddress = MAX_ADDRESS;
  MmramSize = 0;
  for (Index = 0; Index < MmramDescriptorTotalSize / sizeof (EFI_MMRAM_DESCRIPTOR); Index++) {
    // Assume contiguous MMRAM, it's what we provide in coreboot.
    if (MmramDescriptor[Index].PhysicalStart < PayloadMmramAddress) {
      PayloadMmramAddress = MmramDescriptor[Index].PhysicalStart;
    }

    MmramSize += MmramDescriptor[Index].PhysicalSize;
  }

  FreePool (MmramDescriptor);

  BootloaderMmramAddress = PayloadMmramAddress + MmramSize;
  if (SetUnset) {
    //
    // Mark our MMRAM as RWX. It's blunt, but sufficient, and our CPU driver will do better.
    //
    DEBUG ((DEBUG_INFO, "Mapping our MMRAM as RWX (address 0x%x, length 0x%x)\n", PayloadMmramAddress, MmramSize));

    Status = MemoryAttributeProtocol->ClearMemoryAttributes (
                                        MemoryAttributeProtocol,
                                        PayloadMmramAddress,
                                        MmramSize,
                                        EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_XP
                                        );
    ASSERT_EFI_ERROR (Status);

    //
    // Mark bootloader's MMRAM as RO. This is necessary to use its GDT.
    //
    DEBUG ((DEBUG_INFO, "Mapping bootloader's MMRAM as RO (address 0x%x, length 0x%x)\n", BootloaderMmramAddress, MmramSize));

    Status = MemoryAttributeProtocol->ClearMemoryAttributes (
                                        MemoryAttributeProtocol,
                                        BootloaderMmramAddress,
                                        MmramSize,
                                        EFI_MEMORY_RP
                                        );
    ASSERT_EFI_ERROR (Status);

    Status = MemoryAttributeProtocol->SetMemoryAttributes (
                                        MemoryAttributeProtocol,
                                        BootloaderMmramAddress,
                                        MmramSize,
                                        EFI_MEMORY_RO | EFI_MEMORY_XP
                                        );
    ASSERT_EFI_ERROR (Status);
  } else {
    DEBUG ((DEBUG_INFO, "Unmapping all MMRAM (address 0x%x, length 0x%x)\n", PayloadMmramAddress, MmramSize * 2));

    Status = MemoryAttributeProtocol->SetMemoryAttributes (
                                        MemoryAttributeProtocol,
                                        PayloadMmramAddress,
                                        MmramSize * 2,
                                        EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_XP
                                        );
    ASSERT_EFI_ERROR (Status);
  }

  return EFI_SUCCESS;
}

/**
  Allows platforms to override how SMM/MM is called, rather than calling the entrypoint.

  This function allows platforms to override how SMM/MM is called.

  @retval EFI_SUCCESS       The platform hook completes successfully.
  @retval Other values      The paltform hook cannot complete due to some error.

**/
EFI_STATUS
EFIAPI
PlatformHookCallMmCore (
  IN     PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  IN     VOID                          *Context,
  IN OUT EFI_STATUS                    *PiSmmCoreStatus
  )
{
  UINTN                         PageCount;
  PAYLOAD_MM_LOAD_CONTEXT       PayloadMmLoadContext;
  PAYLOAD_MM_EDK2_PRIVATE_DATA  PrivateData;
  UINTN                         StackSize;
  EFI_STATUS                    Status;

  PageCount = EFI_SIZE_TO_PAGES (ImageContext->ImageSize + ImageContext->SectionAlignment);

  PayloadMmLoadContext.HeaderSize                = sizeof (PAYLOAD_MM_LOAD_CONTEXT);
  PayloadMmLoadContext.HeaderRevision            = PLD_MM_CORE_LOAD_CONTEXT_REVISION;
  PayloadMmLoadContext.MmCoreSourceAddress       = ImageContext->ImageAddress;
  PayloadMmLoadContext.MmCoreDestinationAddress  = ImageContext->DestinationAddress;
  PayloadMmLoadContext.MmCoreSize                = EFI_PAGES_TO_SIZE (PageCount);
  PayloadMmLoadContext.MmEntryPointOffset        = ImageContext->EntryPoint - ImageContext->DestinationAddress;
  PayloadMmLoadContext.MmEntryPointArg1          = (UINT64)(UINTN)Context;
  PayloadMmLoadContext.ImplementationPrivateData = (UINT64)(UINTN)&PrivateData;

  //
  // Prepare data required by the EDK2 implementation specifically;
  // in other words, spec-extension data.
  //
  StackSize = PcdGet32 (PcdCpuSmmStackSize);
  PrivateData.StackPointers = AllocatePool (sizeof (UINT32)); // Really, need per-CPU stack.

  PrivateData.StackPointers[0]  = (UINT32)(UINTN)AllocatePagesBelow4G (EfiReservedMemoryType, EFI_SIZE_TO_PAGES (StackSize)) + StackSize;
  PrivateData.PageTable         = (UINT32)AsmReadCr3 ();

  CheckFeatureSupported (&PrivateData);

  DEBUG ((DEBUG_INFO, "Payload MM calling MM Core through bootloader SMI\n"));

  Status = PlatformMapMmEnvironment (TRUE);
  ASSERT_EFI_ERROR (Status);

  *PiSmmCoreStatus = PayloadMmCmdLoadAndCallCore (&PayloadMmLoadContext);
  ASSERT_EFI_ERROR (*PiSmmCoreStatus);

  Status = PlatformMapMmEnvironment (FALSE);
  ASSERT_EFI_ERROR (Status);

  //
  // Reclaim the DXE memory we allocated for the MM core as part of the private data.
  //
  FreePages ((VOID *)(UINTN)(PrivateData.StackPointers[0] - StackSize), EFI_SIZE_TO_PAGES (StackSize));
  FreePool (PrivateData.StackPointers);

  FreePages ((VOID *)ImageContext->ImageAddress, PageCount);

  return EFI_SUCCESS;
}
