/** @file
Agent Module to load other modules to deploy MM Entry Vector for X86 CPU.

Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>

#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PerformanceLib.h>

#include <Protocol/MpService.h>
#include <Protocol/SmmMemoryAttribute.h>

#include <Guid/PiSmmMemoryAttributesTable.h>

#include "BlSmmCpuPayloadMm.h"

//
// TRUE to indicate it's the MM_STANDALONE MM CPU driver.
// FALSE to indicate it's the DXE_SMM_DRIVER SMM CPU driver.
//
const BOOLEAN  mIsStandaloneMm = TRUE;

//
// RemainingTasks Done flag
//
BOOLEAN  mRemainingTasksDone = FALSE;

/**
  Perform the remaining tasks.

**/
VOID
PerformRemainingTasks (
  VOID
  )
{
  EDKII_PI_SMM_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable;

  if (!mRemainingTasksDone) {
    PERF_FUNCTION_BEGIN ();

    //
    // gEdkiiPiSmmMemoryAttributesTableGuid should have been published after SmmCore dispatched all MM drivers (MmDriverDispatchHandler).
    // Note: gEdkiiPiSmmMemoryAttributesTableGuid is not always installed since it depends on
    //       the memory protection attribute setting in MM Core.
    //
    SmmGetSystemConfigurationTable (&gEdkiiPiSmmMemoryAttributesTableGuid, (VOID **)&MemoryAttributesTable);

    //
    // Set critical region attribute in page table according to the MemoryAttributesTable
    //
    if (MemoryAttributesTable != NULL) {
      SetMemMapAttributes (MemoryAttributesTable);
    }

    //
    // Set page table itself to be read-only
    //
    SetPageTableAttributes ();

    //
    // Mark RemainingTasksDone flag to TRUE
    //
    mRemainingTasksDone = TRUE;

    PERF_FUNCTION_END ();
  }
}

/**
  Get the maximum number of logical processors supported by the system.

  @retval The maximum number of logical processors supported by the system
          is indicated by the return value.
**/
UINTN
GetSupportedMaxLogicalProcessorNumber (
  VOID
  )
{
  ASSERT (FALSE);

  return 0;
}

/**
  Extract NumberOfCpus, MaxNumberOfCpus and EFI_PROCESSOR_INFORMATION.

  @param[out] NumberOfCpus           Pointer to NumberOfCpus.
  @param[out] MaxNumberOfCpus        Pointer to MaxNumberOfCpus.

  @retval ProcessorInfo              Pointer to EFI_PROCESSOR_INFORMATION buffer.
**/
EFI_PROCESSOR_INFORMATION *
GetMpInformationFromMpServices (
  OUT UINTN  *NumberOfCpus,
  OUT UINTN  *MaxNumberOfCpus
  )
{
  ASSERT (FALSE);

  return NULL;
}

/**
  The module Entry Point of the CPU StandaloneMm driver.

  @param  ImageHandle    The firmware allocated handle for the EFI image.
  @param  SystemTable    A pointer to the MM System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
BlSmmCpuStandaloneMmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = BlSmmCpuPayloadMmEntry ();
  ASSERT_EFI_ERROR (Status);

  //
  // Install the SMM Configuration Protocol onto a new handle on the handle database.
  // The entire SMM Configuration Protocol is allocated from SMRAM, so only a pointer
  // to an SMRAM address will be present in the handle database
  //
  Status = gMmst->MmInstallProtocolInterface (
                    &gPayloadMmCpuPrivateData->SmmCpuHandle,
                    &gEfiSmmConfigurationProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &gPayloadMmCpuPrivateData->SmmConfiguration
                    );
  ASSERT_EFI_ERROR (Status);

  return Status;
}
