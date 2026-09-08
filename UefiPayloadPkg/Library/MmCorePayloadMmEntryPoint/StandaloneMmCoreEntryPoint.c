/** @file
  Entry point to the Standalone Mm Core.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <StandaloneMm.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include <Guid/SmmS3CommunicationInfoGuid.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CpuExceptionHandlerLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MmCorePayloadMmEntryPoint.h>

//
// Cache copy of HobList pointer.
//
VOID  *gHobList = NULL;

//
// Variables used by initialisation IDTR.
//
STATIC EFI_MM_SYSTEM_TABLE  *mMmst;
STATIC IA32_DESCRIPTOR      MmEntryPointIdtr;

/**
  Allocate pages for code.

  @param[in]  Pages Number of pages to be allocated.

  @return Allocated memory.

**/
VOID *
AllocateCodePages (
  IN UINTN  Pages
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Memory;

  if (Pages == 0) {
    return NULL;
  }

  Status = mMmst->MmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, Pages, &Memory);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return (VOID *)(UINTN)Memory;
}

/**
  Initialize IDT to setup exception handlers for SMM.

  @param[in]  ImageHandle   The firmware allocated handle for the EFI image.
  @param[in]  MmSystemTable A pointer to the MM System Table.

  @retval EFI_SUCCESS   The constructor always returns EFI_SUCCESS.

**/
EFI_STATUS
EFIAPI
PayloadMmEntryPointLibConstructor (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  EFI_STATUS  Status;
  BOOLEAN     InterruptState;

  mMmst = MmSystemTable;

  //
  // There are 32 (not 255) entries in it since only processor
  // generated exceptions will be handled.
  //
  MmEntryPointIdtr.Limit = (sizeof (IA32_IDT_GATE_DESCRIPTOR) * 32) - 1;

  //
  // Allocate page aligned IDT, because it might be set as read only.
  //
  MmEntryPointIdtr.Base = (UINTN)AllocateCodePages (EFI_SIZE_TO_PAGES (MmEntryPointIdtr.Limit + 1));
  if (MmEntryPointIdtr.Base == 0) {
    // Constructors have no error return path through the generated MM core entry.
    CpuDeadLoop ();
  }
  ZeroMem ((VOID *)MmEntryPointIdtr.Base, MmEntryPointIdtr.Limit + 1);

  //
  // Disable Interrupts
  //
  InterruptState = SaveAndDisableInterrupts ();

  //
  // Load SMM temporary IDT table
  //
  AsmWriteIdtr (&MmEntryPointIdtr);

  //
  // Setup SMM default exception handlers, SMM IDT table
  // will be updated and saved in MmEntryPointIdtr
  //
  Status = InitializeCpuExceptionHandlers (NULL);
  if (EFI_ERROR (Status)) {
    CpuDeadLoop ();
  }

  //
  // Restore CPU interrupts
  //
  SetInterruptState (InterruptState);

  return EFI_SUCCESS;
}

/**
  The entry point of PE/COFF Image for the STANDALONE MM Core.

  This function is the entry point for the STANDALONE MM Core. This function is required to call
  ProcessModuleEntryPointList() and ProcessModuleEntryPointList() is never expected to return.
  The STANDALONE MM Core is responsible for calling ProcessLibraryConstructorList() as soon as the EFI
  System Table and the image handle for the STANDALONE MM Core itself have been established.
  If ProcessModuleEntryPointList() returns, then ASSERT() and halt the system.

  @param  HobStart  Pointer to the beginning of the HOB List passed in from the PEI Phase.

**/
UINT8
EFIAPI
CEntryPoint (
  IN PAYLOAD_MM_CORE_CALL_CONTEXT  *PayloadMmCallContext
  )
{
  EFI_HOB_GUID_TYPE       *Hob;
  PLD_S3_COMMUNICATION    *Communication;
  PAYLOAD_MM_SHARED_INFO  *Info;

  if ((PayloadMmCallContext == NULL) || (PayloadMmCallContext->MmEntryPointArg1 == 0)) {
    return PAYLOAD_MM_RET_FAILURE;
  }

  //
  // Cache a pointer to the HobList
  //
  gHobList = (VOID *)PayloadMmCallContext->MmEntryPointArg1;

  //
  // Call the Standalone MM Core entry point
  //
  ProcessModuleEntryPointList (gHobList);

  // Keep the bootstrap IDT allocated: failed CPU dispatch may still be using it.
  Hob = GetFirstGuidHob (&gS3CommunicationGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) < sizeof (*Communication))) {
    return PAYLOAD_MM_RET_FAILURE;
  }

  Communication = GET_GUID_HOB_DATA (Hob);
  if ((Communication->CommBuffer.PhysicalStart == 0) ||
      (Communication->CommBuffer.PhysicalSize < sizeof (*Info)))
  {
    return PAYLOAD_MM_RET_FAILURE;
  }

  Info = (VOID *)(UINTN)Communication->CommBuffer.PhysicalStart;
  if ((Info->HeaderMagic != PLD_MM_STRUCT_MAGIC) ||
      (Info->SharedInfoSize != sizeof (*Info)) ||
      (Info->HeaderRevision != PLD_MM_SHARED_STRUCT_REVISION) ||
      (Info->Reserved != 0) || (Info->MmEntryPointAddress == 0))
  {
    return PAYLOAD_MM_RET_FAILURE;
  }

  return PAYLOAD_MM_RET_SUCCESS;
}
