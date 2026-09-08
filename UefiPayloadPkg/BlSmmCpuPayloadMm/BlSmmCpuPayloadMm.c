/** @file
  This module forms the interface between bootloader SMM and payload MM.
  It also supplements a payload MM core with the CPU protocols.

  Copyright (c) 2023, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CpuExceptionHandlerLib.h>
#include <Library/CpuLib.h>
#include <Library/DebugAgentLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PayloadMmHelperLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PerformanceLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/SynchronizationLib.h>

#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmConfiguration.h>

#include <Guid/MpInformation2.h>
#include <Guid/SmramMemoryReserve.h>

#include "BlSmmCpuPayloadMm.h"

//
// SMM CPU Private Data structure that contains SMM Configuration Protocol
// along its supporting fields.
//
PAYLOAD_MM_CPU_PRIVATE_DATA  mPayloadMmCpuPrivateData = {
  PAYLOAD_MM_CPU_PRIVATE_DATA_SIGNATURE,        // Signature
  NULL,                                         // SmmCpuHandle
  {
    NULL,                                       // PayloadMmPrivateData.StackPointers
    0,                                          // PayloadMmPrivateData.PageTable
    FALSE,                                      // PayloadMmPrivateData.Intel5LevelPagingNeeded
    TRUE,                                       // PayloadMmPrivateData.XdSupported
    TRUE                                        // PayloadMmPrivateData.MsrIa32MiscEnableSupported
  },
  {
    SmmStartupThisAp,                           // SmmCoreEntryContext.SmmStartupThisAp
    0,                                          // SmmCoreEntryContext.CurrentlyExecutingCpu
    0,                                          // SmmCoreEntryContext.NumberOfCpus
    NULL,                                       // SmmCoreEntryContext.CpuSaveStateSize
    NULL                                        // SmmCoreEntryContext.CpuSaveState
  },
  NULL,                                         // SmmCoreEntry
  {
    { 0    }
  },                                            // SmmReservedSmramRegion
  {
    mPayloadMmCpuPrivateData.SmmReservedSmramRegion, // SmmConfiguration.SmramReservedRegions
    RegisterPayloadMmEntry                           // SmmConfiguration.RegisterSmmEntry
  },
  NULL,                                         // Pointer to ProcessorInfo array
  NULL,                                         // pointer to Ap Wrapper Func array
  { NULL, NULL },                               // List_Entry for Tokens.
  NULL                                          // Pointer to first free token in list.
};

UINT32  mSmrrBase, mSmrrSize;

//
// Global pointer used to access mPayloadMmCpuPrivateData from outside and inside SMM
//
PAYLOAD_MM_CPU_PRIVATE_DATA  *gPayloadMmCpuPrivateData = &mPayloadMmCpuPrivateData;

X86_ASSEMBLY_PATCH_LABEL  gPatchEdk2PayloadMmPrivateData;

///
/// Handle for the SMM CPU Protocol
///
EFI_HANDLE  mMmCpuHandle = NULL;

///
/// SMM Memory Attribute Protocol instance
///
EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL  mSmmMemoryAttribute = {
  EdkiiSmmGetMemoryAttributes,
  EdkiiSmmSetMemoryAttributes,
  EdkiiSmmClearMemoryAttributes
};

//
// SMM stack information
//
UINTN  mSmmStackArrayBase;
UINTN  mSmmStackSize;

UINTN  mMaxNumberOfCpus = 0;
UINTN  mNumberOfCpus    = 0;

//
// Global used to cache SMM Debug Agent Supported ot not
//
BOOLEAN  mSmmDebugAgentSupport = FALSE;

//
// Global copy of the PcdPteMemoryEncryptionAddressOrMask
//
UINT64  mAddressEncMask = 0;

//
// Saved SMM ranges information
//
EFI_SMRAM_DESCRIPTOR  *mSmmCpuSmramRanges;
UINTN                 mSmmCpuSmramRangeCount;

UINT8  mPhysicalAddressBits;

/**
  Initialize IDT to setup exception handlers for SMM.

**/
EFI_STATUS
InitializeSmmIdt (
  VOID
  )
{
  EFI_STATUS       Status;
  BOOLEAN          InterruptState;
  IA32_DESCRIPTOR  DxeIdtr;

  //
  // There are 32 (not 255) entries in it since only processor
  // generated exceptions will be handled.
  //
  gSmiHandlerIdtr.Limit = (sizeof (IA32_IDT_GATE_DESCRIPTOR) * 32) - 1;

  //
  // Allocate page aligned IDT, because it might be set as read only.
  //
  gSmiHandlerIdtr.Base = (UINTN)AllocateCodePages (EFI_SIZE_TO_PAGES (gSmiHandlerIdtr.Limit + 1));
  if (gSmiHandlerIdtr.Base == 0) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem ((VOID *)gSmiHandlerIdtr.Base, gSmiHandlerIdtr.Limit + 1);

  //
  // Disable Interrupt and save DXE IDT table
  //
  InterruptState = SaveAndDisableInterrupts ();
  if (!mIsStandaloneMm) {
    AsmReadIdtr (&DxeIdtr);
  }

  //
  // Load SMM temporary IDT table
  //
  AsmWriteIdtr (&gSmiHandlerIdtr);

  //
  // Setup SMM default exception handlers, SMM IDT table
  // will be updated and saved in gSmiHandlerIdtr
  //
  Status = InitializeCpuExceptionHandlers (NULL);

  //
  // Restore DXE IDT table and CPU interrupt
  //
  if (!mIsStandaloneMm) {
    AsmWriteIdtr ((IA32_DESCRIPTOR *)&DxeIdtr);
  }

  SetInterruptState (InterruptState);
  return Status;
}

/**
  Search module name by input IP address and output it.

  @param CallerIpAddress   Caller instruction pointer.

**/
VOID
DumpModuleInfoByIp (
  IN  UINTN  CallerIpAddress
  )
{
  UINTN  Pe32Data;
  VOID   *PdbPointer;

  //
  // Find Image Base
  //
  Pe32Data = PeCoffSearchImageBase (CallerIpAddress);
  if (Pe32Data != 0) {
    DEBUG ((DEBUG_ERROR, "It is invoked from the instruction before IP(0x%p)", (VOID *)CallerIpAddress));
    PdbPointer = PeCoffLoaderGetPdbPointer ((VOID *)Pe32Data);
    if (PdbPointer != NULL) {
      DEBUG ((DEBUG_ERROR, " in module (%a)\n", PdbPointer));
    }
  }
}

/**
  Function to compare 2 MP_INFORMATION2_HOB_DATA pointer based on ProcessorIndex.

  @param[in] Buffer1            pointer to MP_INFORMATION2_HOB_DATA poiner to compare
  @param[in] Buffer2            pointer to second MP_INFORMATION2_HOB_DATA pointer to compare

  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2
**/
INTN
EFIAPI
MpInformation2HobCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if ((*(MP_INFORMATION2_HOB_DATA **)Buffer1)->ProcessorIndex > (*(MP_INFORMATION2_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return 1;
  } else if ((*(MP_INFORMATION2_HOB_DATA **)Buffer1)->ProcessorIndex < (*(MP_INFORMATION2_HOB_DATA **)Buffer2)->ProcessorIndex) {
    return -1;
  }

  return 0;
}

/**
  Extract NumberOfCpus, MaxNumberOfCpus and EFI_PROCESSOR_INFORMATION for all CPU from MpInformation2 HOB.

  @param[out] NumberOfCpus           Pointer to NumberOfCpus.
  @param[out] MaxNumberOfCpus        Pointer to MaxNumberOfCpus.

  @retval ProcessorInfo              Pointer to EFI_PROCESSOR_INFORMATION buffer.
**/
EFI_PROCESSOR_INFORMATION *
GetMpInformation (
  OUT UINTN  *NumberOfCpus,
  OUT UINTN  *MaxNumberOfCpus
  )
{
  EFI_HOB_GUID_TYPE          *GuidHob;
  EFI_HOB_GUID_TYPE          *FirstMpInfo2Hob;
  MP_INFORMATION2_HOB_DATA   *MpInformation2HobData;
  UINTN                      HobCount;
  UINTN                      HobIndex;
  MP_INFORMATION2_HOB_DATA   **MpInfo2Hobs;
  UINTN                      SortBuffer;
  UINTN                      ProcessorIndex;
  UINT64                     PrevProcessorIndex;
  MP_INFORMATION2_ENTRY      *MpInformation2Entry;
  EFI_PROCESSOR_INFORMATION  *ProcessorInfo;

  GuidHob               = NULL;
  MpInformation2HobData = NULL;
  FirstMpInfo2Hob       = NULL;
  MpInfo2Hobs           = NULL;
  HobIndex              = 0;
  HobCount              = 0;

  FirstMpInfo2Hob = GetFirstGuidHob (&gMpInformation2HobGuid);

  if (mIsStandaloneMm) {
    ASSERT (FirstMpInfo2Hob != NULL);
  } else {
    if (FirstMpInfo2Hob == NULL) {
      DEBUG ((DEBUG_INFO, "%a: [INFO] gMpInformation2HobGuid HOB not found.\n", __func__));
      return GetMpInformationFromMpServices (NumberOfCpus, MaxNumberOfCpus);
    }
  }

  GuidHob = FirstMpInfo2Hob;
  while (GuidHob != NULL) {
    MpInformation2HobData = GET_GUID_HOB_DATA (GuidHob);

    //
    // This is the last MpInformationHob in the HOB list.
    //
    if (MpInformation2HobData->NumberOfProcessors == 0) {
      ASSERT (HobCount != 0);
      break;
    }

    HobCount++;
    *NumberOfCpus += MpInformation2HobData->NumberOfProcessors;
    GuidHob        = GetNextGuidHob (&gMpInformation2HobGuid, GET_NEXT_HOB (GuidHob));
  }

  *MaxNumberOfCpus = *NumberOfCpus;

  if (!mIsStandaloneMm) {
    ASSERT (*NumberOfCpus <= GetSupportedMaxLogicalProcessorNumber ());
  }

  MpInfo2Hobs = AllocatePool (sizeof (MP_INFORMATION2_HOB_DATA *) * HobCount);
  ASSERT (MpInfo2Hobs != NULL);
  if (MpInfo2Hobs == NULL) {
    return NULL;
  }

  //
  // Record each MpInformation2Hob pointer in the MpInfo2Hobs.
  // The FirstMpInfo2Hob is to speed up this while-loop without
  // needing to look for MpInfo2Hob from beginning.
  //
  GuidHob = FirstMpInfo2Hob;
  while (HobIndex < HobCount) {
    MpInfo2Hobs[HobIndex++] = GET_GUID_HOB_DATA (GuidHob);
    GuidHob                 = GetNextGuidHob (&gMpInformation2HobGuid, GET_NEXT_HOB (GuidHob));
  }

  ProcessorInfo = (EFI_PROCESSOR_INFORMATION *)AllocatePool (sizeof (EFI_PROCESSOR_INFORMATION) * (*MaxNumberOfCpus));
  ASSERT (ProcessorInfo != NULL);
  if (ProcessorInfo == NULL) {
    FreePool (MpInfo2Hobs);
    return NULL;
  }

  QuickSort (MpInfo2Hobs, HobCount, sizeof (MP_INFORMATION2_HOB_DATA *), (BASE_SORT_COMPARE)MpInformation2HobCompare, &SortBuffer);
  PrevProcessorIndex = 0;
  for (HobIndex = 0; HobIndex < HobCount; HobIndex++) {
    //
    // Make sure no overlap and no gap in the CPU range covered by each HOB
    //
    ASSERT (MpInfo2Hobs[HobIndex]->ProcessorIndex == PrevProcessorIndex);

    //
    // Cache each EFI_PROCESSOR_INFORMATION in order.
    //
    for (ProcessorIndex = 0; ProcessorIndex < MpInfo2Hobs[HobIndex]->NumberOfProcessors; ProcessorIndex++) {
      MpInformation2Entry = GET_MP_INFORMATION_ENTRY (MpInfo2Hobs[HobIndex], ProcessorIndex);
      CopyMem (
        &ProcessorInfo[PrevProcessorIndex + ProcessorIndex],
        &MpInformation2Entry->ProcessorInfo,
        sizeof (EFI_PROCESSOR_INFORMATION)
        );
    }

    PrevProcessorIndex += MpInfo2Hobs[HobIndex]->NumberOfProcessors;
  }

  FreePool (MpInfo2Hobs);
  return ProcessorInfo;
}

/**
  Main entry for runtime payload MM support.
  TODO: Implement parts of `SmiRendezvous()`. For instance, save/restore CR2 and debug registers. Also FLAGS?

  @retval EFI_SUCCESS  The common entry point executed successfully.
  @retval other        Some error occurred when executing this entry point.

**/
EFI_STATUS
BlSmmCpuPayloadMmEntry (
  VOID
  )
{
  EFI_STATUS  Status;

  PERF_FUNCTION_BEGIN ();

  // The initial backend does not support recovery through the debug trap handler.
  if (HEAP_GUARD_NONSTOP_MODE || NULL_DETECTION_NONSTOP_MODE) {
    return EFI_UNSUPPORTED;
  }

  //
  // Initialize address fixup
  //
  PayloadMmTransferExecFixupAddress ();

  //
  // Initialize Debug Agent to support source level debug in SMM code
  //
  InitializeDebugAgent (DEBUG_AGENT_INIT_SMM, &mSmmDebugAgentSupport, NULL);

  //
  // Report the start of payload CPU MM initialization.
  //
  REPORT_STATUS_CODE (
    EFI_PROGRESS_CODE,
    EFI_COMPUTING_UNIT_HOST_PROCESSOR | EFI_CU_HP_PC_SMM_INIT
    );

  //
  // Find out SMRR Base and SMRR Size
  //
  Status = FindSmramInfo (&mSmrrBase, &mSmrrSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Coreboot serializes SMI handling. MM exposes one logical execution context,
  // not physical CPU save states or AP startup services.
  //
  mNumberOfCpus    = 1;
  mMaxNumberOfCpus = 1;

  gPayloadMmCpuPrivateData->SmmCoreEntryContext.NumberOfCpus = mMaxNumberOfCpus;

  CheckFeatureSupported (&gPayloadMmCpuPrivateData->PayloadMmPrivateData);

  gPayloadMmCpuPrivateData->SmmCoreEntryContext.CpuSaveStateSize = AllocateZeroPool (sizeof (UINTN) * gPayloadMmCpuPrivateData->SmmCoreEntryContext.NumberOfCpus);
  if (gPayloadMmCpuPrivateData->SmmCoreEntryContext.CpuSaveStateSize == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  gPayloadMmCpuPrivateData->SmmCoreEntryContext.CpuSaveState = AllocateZeroPool (sizeof (VOID *));
  if (gPayloadMmCpuPrivateData->SmmCoreEntryContext.CpuSaveState == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Allocate SMI stacks for all processors.
  //
  mSmmStackSize = PcdGet32 (PcdCpuSmmStackSize);
  if (FeaturePcdGet (PcdCpuSmmStackGuard)) {
    //
    // SMM Stack Guard Enabled
    //   2 more pages is allocated for each processor, one is guard page and the other is known good stack.
    //
    // +--------------------------------------------------+-----+--------------------------------------------------+
    // | Known Good Stack | Guard Page |     SMM Stack    | ... | Known Good Stack | Guard Page |     SMM Stack    |
    // +--------------------------------------------------+-----+--------------------------------------------------+
    // |        4K        |    4K       PcdCpuSmmStackSize|     |        4K        |    4K       PcdCpuSmmStackSize|
    // |<---------------- mSmmStackSize ----------------->|     |<---------------- mSmmStackSize ----------------->|
    // |                                                  |     |                                                  |
    // |<------------------ Processor 0 ----------------->|     |<------------------ Processor n ----------------->|
    //
    mSmmStackSize += EFI_PAGES_TO_SIZE (2);
  }

  gPayloadMmCpuPrivateData->PayloadMmPrivateData.StackPointers = AllocatePool (sizeof (UINT32));
  if (gPayloadMmCpuPrivateData->PayloadMmPrivateData.StackPointers == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  mSmmStackArrayBase = (UINTN)AllocatePages (EFI_SIZE_TO_PAGES (mSmmStackSize));
  if ((mSmmStackArrayBase == 0) || (mSmmStackArrayBase > MAX_UINT32) ||
      (mSmmStackSize > MAX_UINT32 - mSmmStackArrayBase))
  {
    return EFI_OUT_OF_RESOURCES;
  }

  DEBUG ((DEBUG_INFO, "mSmmStackArrayBase       - 0x%x\n", mSmmStackArrayBase));
  DEBUG ((DEBUG_INFO, "mSmmStackSize            - 0x%x\n", mSmmStackSize));
  DEBUG ((DEBUG_INFO, "PcdCpuSmmStackGuard      - 0x%x\n", FeaturePcdGet (PcdCpuSmmStackGuard)));

  //
  // Initialize IDT
  //
  Status = InitializeSmmIdt ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Initialize payload MM calling
  //
  if (InitializeMpServiceData (mSmmStackArrayBase, mSmmStackSize) == 0) {
    return EFI_OUT_OF_RESOURCES;
  }

  PatchInstructionX86 (gPatchEdk2PayloadMmPrivateData, (UINT32)(UINTN)&gPayloadMmCpuPrivateData->PayloadMmPrivateData, 4);

  DEBUG ((DEBUG_INFO, "mXdSupported - 0x%x\n", gPayloadMmCpuPrivateData->PayloadMmPrivateData.XdSupported));

  //
  // Fill in SMM Reserved Regions
  //
  gPayloadMmCpuPrivateData->SmmReservedSmramRegion[0].SmramReservedStart = 0;
  gPayloadMmCpuPrivateData->SmmReservedSmramRegion[0].SmramReservedSize  = 0;

  //
  // TODO: CPU save state modification.
  //

  //
  // Install the SMM Memory Attribute Protocol into SMM protocol database
  //
  Status = gMmst->MmInstallProtocolInterface (
                    &mMmCpuHandle,
                    &gEdkiiSmmMemoryAttributeProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mSmmMemoryAttribute
                    );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // TODO: MP support, requires convoluted mode switching.
  // Will not support SMM CPU Services, these perform BSP/AP management.
  //

  //
  // Initialize SMM Profile feature
  //
  InitSmmProfile ();

  DEBUG ((DEBUG_INFO, "SMM CPU Module exit from SMRAM with EFI_SUCCESS\n"));

  PERF_FUNCTION_END ();
  return EFI_SUCCESS;
}

/**
  Function to compare 2 EFI_SMRAM_DESCRIPTOR based on CpuStart.

  @param[in] Buffer1            pointer to Device Path poiner to compare
  @param[in] Buffer2            pointer to second DevicePath pointer to compare

  @retval 0                     Buffer1 equal to Buffer2
  @retval <0                    Buffer1 is less than Buffer2
  @retval >0                    Buffer1 is greater than Buffer2

**/
INTN
EFIAPI
CpuSmramRangeCompare (
  IN  CONST VOID  *Buffer1,
  IN  CONST VOID  *Buffer2
  )
{
  if (((EFI_SMRAM_DESCRIPTOR *)Buffer1)->CpuStart > ((EFI_SMRAM_DESCRIPTOR *)Buffer2)->CpuStart) {
    return 1;
  } else if (((EFI_SMRAM_DESCRIPTOR *)Buffer1)->CpuStart < ((EFI_SMRAM_DESCRIPTOR *)Buffer2)->CpuStart) {
    return -1;
  }

  return 0;
}

/**
  Find out SMRAM information including SMRR base and SMRR size.

  @param          SmrrBase          SMRR base
  @param          SmrrSize          SMRR size

**/
EFI_STATUS
FindSmramInfo (
  OUT UINT32  *SmrrBase,
  OUT UINT32  *SmrrSize
  )
{
  VOID                            *GuidHob;
  EFI_SMRAM_HOB_DESCRIPTOR_BLOCK  *DescriptorBlock;
  EFI_SMRAM_DESCRIPTOR            *CurrentSmramRange;
  UINTN                           Index;
  UINT64                          MaxSize;
  BOOLEAN                         Found;
  EFI_SMRAM_DESCRIPTOR            SmramDescriptor;
  UINTN                           HobSize;

  if ((SmrrBase == NULL) || (SmrrSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Get SMRAM information
  //
  GuidHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
  if (GuidHob == NULL) {
    return EFI_NOT_FOUND;
  }

  HobSize = GET_GUID_HOB_DATA_SIZE (GuidHob);
  if (HobSize < OFFSET_OF (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, Descriptor)) {
    return EFI_INVALID_PARAMETER;
  }

  DescriptorBlock = (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK *)GET_GUID_HOB_DATA (GuidHob);
  if ((DescriptorBlock->NumberOfSmmReservedRegions == 0) ||
      (DescriptorBlock->NumberOfSmmReservedRegions >
       (HobSize - OFFSET_OF (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, Descriptor)) / sizeof (SmramDescriptor)))
  {
    return EFI_INVALID_PARAMETER;
  }

  mSmmCpuSmramRangeCount = DescriptorBlock->NumberOfSmmReservedRegions;
  mSmmCpuSmramRanges     = DescriptorBlock->Descriptor;

  //
  // Sort the mSmmCpuSmramRanges
  //
  QuickSort (mSmmCpuSmramRanges, mSmmCpuSmramRangeCount, sizeof (EFI_SMRAM_DESCRIPTOR), (BASE_SORT_COMPARE)CpuSmramRangeCompare, &SmramDescriptor);

  for (Index = 0; Index < mSmmCpuSmramRangeCount; Index++) {
    CurrentSmramRange = &mSmmCpuSmramRanges[Index];
    if ((CurrentSmramRange->CpuStart != CurrentSmramRange->PhysicalStart) ||
        (CurrentSmramRange->CpuStart > MAX_UINT32) ||
        (CurrentSmramRange->PhysicalSize == 0) ||
        (CurrentSmramRange->PhysicalSize - 1 > MAX_UINT32 - CurrentSmramRange->CpuStart) ||
        (((CurrentSmramRange->CpuStart | CurrentSmramRange->PhysicalSize) & EFI_PAGE_MASK) != 0) ||
        ((Index != 0) && (CurrentSmramRange->CpuStart <
                          mSmmCpuSmramRanges[Index - 1].CpuStart + mSmmCpuSmramRanges[Index - 1].PhysicalSize)))
    {
      return EFI_INVALID_PARAMETER;
    }
  }

  //
  // Find the largest SMRAM range between 1MB and 4GB that is at least 256K - 4K in size
  //
  CurrentSmramRange = NULL;
  for (Index = 0, MaxSize = SIZE_256KB - EFI_PAGE_SIZE; Index < mSmmCpuSmramRangeCount; Index++) {
    //
    // Skip any SMRAM region that is already allocated, needs testing, or needs ECC initialization
    //
    if ((mSmmCpuSmramRanges[Index].RegionState & (EFI_ALLOCATED | EFI_NEEDS_TESTING | EFI_NEEDS_ECC_INITIALIZATION)) != 0) {
      continue;
    }

    if (mSmmCpuSmramRanges[Index].CpuStart >= BASE_1MB) {
      if ((mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize) <= SMRR_MAX_ADDRESS) {
        if (mSmmCpuSmramRanges[Index].PhysicalSize >= MaxSize) {
          MaxSize           = mSmmCpuSmramRanges[Index].PhysicalSize;
          CurrentSmramRange = &mSmmCpuSmramRanges[Index];
        }
      }
    }
  }

  if (CurrentSmramRange == NULL) {
    return EFI_NOT_FOUND;
  }

  if (CurrentSmramRange->PhysicalSize > MAX_UINT32) {
    return EFI_INVALID_PARAMETER;
  }

  *SmrrBase = (UINT32)CurrentSmramRange->CpuStart;
  *SmrrSize = (UINT32)CurrentSmramRange->PhysicalSize;

  do {
    Found = FALSE;
    for (Index = 0; Index < mSmmCpuSmramRangeCount; Index++) {
      if ((mSmmCpuSmramRanges[Index].CpuStart < *SmrrBase) &&
          (*SmrrBase == (mSmmCpuSmramRanges[Index].CpuStart + mSmmCpuSmramRanges[Index].PhysicalSize)))
      {
        if (mSmmCpuSmramRanges[Index].PhysicalSize > MAX_UINT32 - *SmrrSize) {
          return EFI_INVALID_PARAMETER;
        }

        *SmrrBase = (UINT32)mSmmCpuSmramRanges[Index].CpuStart;
        *SmrrSize = (UINT32)(*SmrrSize + mSmmCpuSmramRanges[Index].PhysicalSize);
        Found     = TRUE;
      } else if ((((UINT64)*SmrrBase + *SmrrSize) == mSmmCpuSmramRanges[Index].CpuStart) && (mSmmCpuSmramRanges[Index].PhysicalSize > 0)) {
        if (mSmmCpuSmramRanges[Index].PhysicalSize > MAX_UINT32 - *SmrrSize) {
          return EFI_INVALID_PARAMETER;
        }

        *SmrrSize = (UINT32)(*SmrrSize + mSmmCpuSmramRanges[Index].PhysicalSize);
        Found     = TRUE;
      }
    }
  } while (Found);

  DEBUG ((DEBUG_INFO, "%a: SMRR Base = 0x%x, SMRR Size = 0x%x\n", __func__, *SmrrBase, *SmrrSize));
  return EFI_SUCCESS;
}

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

  Status = gMmst->MmAllocatePages (AllocateAnyPages, EfiRuntimeServicesCode, Pages, &Memory);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  return (VOID *)(UINTN)Memory;
}
