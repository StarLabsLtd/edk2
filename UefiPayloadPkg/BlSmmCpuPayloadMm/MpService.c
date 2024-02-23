/** @file
SMM MP service implementation

Copyright (c) 2009 - 2024, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>
Copyright (c) 2024, 9elements GmbH. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>

#include <Protocol/SmmConfiguration.h>

#include <Guid/PayloadMmInterfaceInfoGuid.h>

#include <Register/Intel/Cpuid.h>

#include "BlSmmCpuPayloadMm.h"

//
// Slots for all MTRR( FIXED MTRR + VARIABLE MTRR + MTRR_LIB_IA32_MTRR_DEF_TYPE)
//
UINT64                       gPhyMask;
SPIN_LOCK                    *mPFLock = NULL;
MM_COMPLETION                mSmmStartupThisApToken;

/**
  Allocate buffer for the SPIN_LOCK and PROCEDURE_TOKEN.

  @return First token of the token buffer.
**/
LIST_ENTRY *
AllocateTokenBuffer (
  VOID
  )
{
  UINTN            SpinLockSize;
  UINT32           TokenCountPerChunk;
  UINTN            Index;
  SPIN_LOCK        *SpinLock;
  UINT8            *SpinLockBuffer;
  PROCEDURE_TOKEN  *ProcTokens;

  SpinLockSize = GetSpinLockProperties ();

  TokenCountPerChunk = FixedPcdGet32 (PcdCpuSmmMpTokenCountPerChunk);
  ASSERT (TokenCountPerChunk != 0);
  if (TokenCountPerChunk == 0) {
    DEBUG ((DEBUG_ERROR, "PcdCpuSmmMpTokenCountPerChunk should not be Zero!\n"));
    CpuDeadLoop ();
  }

  DEBUG ((DEBUG_INFO, "CpuSmm: SpinLock Size = 0x%x, PcdCpuSmmMpTokenCountPerChunk = 0x%x\n", SpinLockSize, TokenCountPerChunk));

  //
  // Separate the Spin_lock and Proc_token because the alignment requires by Spin_Lock.
  //
  SpinLockBuffer = AllocatePool (SpinLockSize * TokenCountPerChunk);
  if (SpinLockBuffer == NULL) {
    ASSERT (SpinLockBuffer != NULL);
    return NULL;
  }

  ProcTokens = AllocatePool (sizeof (PROCEDURE_TOKEN) * TokenCountPerChunk);
  if (ProcTokens == NULL) {
    ASSERT (ProcTokens != NULL);
    FreePool (SpinLockBuffer);
    return NULL;
  }

  for (Index = 0; Index < TokenCountPerChunk; Index++) {
    SpinLock = (SPIN_LOCK *)(SpinLockBuffer + SpinLockSize * Index);
    InitializeSpinLock (SpinLock);

    ProcTokens[Index].Signature      = PROCEDURE_TOKEN_SIGNATURE;
    ProcTokens[Index].SpinLock       = SpinLock;
    ProcTokens[Index].RunningApCount = 0;

    InsertTailList (&gPayloadMmCpuPrivateData->TokenList, &ProcTokens[Index].Link);
  }

  return &ProcTokens[0].Link;
}

/**
  Schedule a procedure to run on the specified CPU.

  @param[in]       Procedure                The address of the procedure to run
  @param[in]       CpuIndex                 Target CPU Index
  @param[in,out]   ProcArguments            The parameter to pass to the procedure
  @param[in]       Token                    This is an optional parameter that allows the caller to execute the
                                            procedure in a blocking or non-blocking fashion. If it is NULL the
                                            call is blocking, and the call will not return until the AP has
                                            completed the procedure. If the token is not NULL, the call will
                                            return immediately. The caller can check whether the procedure has
                                            completed with CheckOnProcedure or WaitForProcedure.
  @param[in]       TimeoutInMicroseconds    Indicates the time limit in microseconds for the APs to finish
                                            execution of Procedure, either for blocking or non-blocking mode.
                                            Zero means infinity. If the timeout expires before all APs return
                                            from Procedure, then Procedure on the failed APs is terminated. If
                                            the timeout expires in blocking mode, the call returns EFI_TIMEOUT.
                                            If the timeout expires in non-blocking mode, the timeout determined
                                            can be through CheckOnProcedure or WaitForProcedure.
                                            Note that timeout support is optional. Whether an implementation
                                            supports this feature can be determined via the Attributes data
                                            member.
  @param[in,out]   CpuStatus                This optional pointer may be used to get the status code returned
                                            by Procedure when it completes execution on the target AP, or with
                                            EFI_TIMEOUT if the Procedure fails to complete within the optional
                                            timeout. The implementation will update this variable with
                                            EFI_NOT_READY prior to starting Procedure on the target AP.

  @retval EFI_INVALID_PARAMETER    CpuNumber not valid
  @retval EFI_INVALID_PARAMETER    CpuNumber specifying BSP
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber did not enter SMM
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber is busy
  @retval EFI_SUCCESS              The procedure has been successfully scheduled

**/
EFI_STATUS
InternalSmmStartupThisAp (
  IN      EFI_AP_PROCEDURE2  Procedure,
  IN      UINTN              CpuIndex,
  IN OUT  VOID               *ProcArguments OPTIONAL,
  IN      MM_COMPLETION      *Token,
  IN      UINTN              TimeoutInMicroseconds,
  IN OUT  EFI_STATUS         *CpuStatus
  )
{
  DEBUG ((DEBUG_ERROR, "ATTN: MP services aren't implemented yet!\n"));
  return EFI_UNSUPPORTED;
}

/**
  Worker function to execute a caller provided function on all enabled APs.

  @param[in]     Procedure               A pointer to the function to be run on
                                         enabled APs of the system.
  @param[in]     TimeoutInMicroseconds   Indicates the time limit in microseconds for
                                         APs to return from Procedure, either for
                                         blocking or non-blocking mode.
  @param[in,out] ProcedureArguments      The parameter passed into Procedure for
                                         all APs.
  @param[in,out] Token                   This is an optional parameter that allows the caller to execute the
                                         procedure in a blocking or non-blocking fashion. If it is NULL the
                                         call is blocking, and the call will not return until the AP has
                                         completed the procedure. If the token is not NULL, the call will
                                         return immediately. The caller can check whether the procedure has
                                         completed with CheckOnProcedure or WaitForProcedure.
  @param[in,out] CPUStatus               This optional pointer may be used to get the status code returned
                                         by Procedure when it completes execution on the target AP, or with
                                         EFI_TIMEOUT if the Procedure fails to complete within the optional
                                         timeout. The implementation will update this variable with
                                         EFI_NOT_READY prior to starting Procedure on the target AP.


  @retval EFI_SUCCESS             In blocking mode, all APs have finished before
                                  the timeout expired.
  @retval EFI_SUCCESS             In non-blocking mode, function has been dispatched
                                  to all enabled APs.
  @retval others                  Failed to Startup all APs.

**/
EFI_STATUS
InternalSmmStartupAllAPs (
  IN       EFI_AP_PROCEDURE2  Procedure,
  IN       UINTN              TimeoutInMicroseconds,
  IN OUT   VOID               *ProcedureArguments OPTIONAL,
  IN OUT   MM_COMPLETION      *Token,
  IN OUT   EFI_STATUS         *CPUStatus
  )
{
  DEBUG ((DEBUG_ERROR, "ATTN: MP services aren't implemented yet!\n"));
  return EFI_UNSUPPORTED;
}

/**
  ISO C99 6.5.2.2 "Function calls", paragraph 9:
  If the function is defined with a type that is not compatible with
  the type (of the expression) pointed to by the expression that
  denotes the called function, the behavior is undefined.

  So add below wrapper function to convert between EFI_AP_PROCEDURE
  and EFI_AP_PROCEDURE2.

  Wrapper for Procedures.

  @param[in]  Buffer              Pointer to PROCEDURE_WRAPPER buffer.

**/
EFI_STATUS
EFIAPI
ProcedureWrapper (
  IN     VOID  *Buffer
  )
{
  PROCEDURE_WRAPPER  *Wrapper;

  Wrapper = Buffer;
  Wrapper->Procedure (Wrapper->ProcedureArgument);

  return EFI_SUCCESS;
}

/**
  Schedule a procedure to run on the specified CPU.

  @param  Procedure                The address of the procedure to run
  @param  CpuIndex                 Target CPU Index
  @param  ProcArguments            The parameter to pass to the procedure

  @retval EFI_INVALID_PARAMETER    CpuNumber not valid
  @retval EFI_INVALID_PARAMETER    CpuNumber specifying BSP
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber did not enter SMM
  @retval EFI_INVALID_PARAMETER    The AP specified by CpuNumber is busy
  @retval EFI_SUCCESS              The procedure has been successfully scheduled

**/
EFI_STATUS
EFIAPI
SmmStartupThisAp (
  IN      EFI_AP_PROCEDURE  Procedure,
  IN      UINTN             CpuIndex,
  IN OUT  VOID              *ProcArguments OPTIONAL
  )
{
  gPayloadMmCpuPrivateData->ApWrapperFunc[CpuIndex].Procedure         = Procedure;
  gPayloadMmCpuPrivateData->ApWrapperFunc[CpuIndex].ProcedureArgument = ProcArguments;

  //
  // Use wrapper function to convert EFI_AP_PROCEDURE to EFI_AP_PROCEDURE2.
  //
  return InternalSmmStartupThisAp (
           ProcedureWrapper,
           CpuIndex,
           &gPayloadMmCpuPrivateData->ApWrapperFunc[CpuIndex],
           FeaturePcdGet (PcdCpuSmmBlockStartupThisAp) ? NULL : &mSmmStartupThisApToken,
           0,
           NULL
           );
}

/**
  C function for SMI entry, each processor comes here upon SMI trigger.

  @param    CpuIndex              CPU Index

**/
VOID
EFIAPI
SmiRendezvous (
  IN  VOID  *PayloadMmEntryContext
  )
{
  // This simplifies the deduplication of assembly code.
  AsmWriteIdtr (&gSmiHandlerIdtr);

  //
  // CPU save states aren't supported in payload MM yet,
  // so there's nothing to copy.
  //

  //
  // Invoke SMM Foundation EntryPoint with the processor information context.
  //
  gPayloadMmCpuPrivateData->SmmCoreEntry (&gPayloadMmCpuPrivateData->SmmCoreEntryContext);

  //
  // Perform the remaining tasks
  //
  PerformRemainingTasks ();
}

/**
  Allocate buffer for SpinLock and Wrapper function buffer.

**/
VOID
InitializeDataForMmMp (
  VOID
  )
{
  gPayloadMmCpuPrivateData->ApWrapperFunc = AllocatePool (sizeof (PROCEDURE_WRAPPER) * gPayloadMmCpuPrivateData->SmmCoreEntryContext.NumberOfCpus);
  ASSERT (gPayloadMmCpuPrivateData->ApWrapperFunc != NULL);

  InitializeListHead (&gPayloadMmCpuPrivateData->TokenList);

  gPayloadMmCpuPrivateData->FirstFreeToken = AllocateTokenBuffer ();
}

/**
  Initialize global data for MP synchronization.

  @param Stacks             Base address of SMI stack buffer for all processors.
  @param StackSize          Stack size for each processor in SMM.

**/
UINT32
InitializeMpServiceData (
  IN UINTN  Stacks,
  IN UINTN  StackSize
  )
{
  UINT32                          MaxExtendedFunction;
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX  VirPhyAddressSize;
  UINTN                           Index;

  mPFLock = AllocatePool (sizeof (SPIN_LOCK));

  //
  // Initialize physical address mask
  // NOTE: Physical memory above virtual address limit is not supported !!!
  //
  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunction, NULL, NULL, NULL);
  if (MaxExtendedFunction >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  gPhyMask = LShiftU64 (1, VirPhyAddressSize.Bits.PhysicalAddressBits) - 1;
  //
  // Clear the low 12 bits
  //
  gPhyMask &= 0xfffffffffffff000ULL;

  //
  // Patch values in MMI handler
  //
  for (Index = 0; Index < 1 /* mMaxNumberOfCpus */; Index++) {
    gPayloadMmCpuPrivateData->PayloadMmPrivateData.StackPointers[Index] = (UINT32)(Stacks + StackSize * (Index + 1));
  }
  gPayloadMmCpuPrivateData->PayloadMmPrivateData.PageTable = SmmInitPageTable ();

  InitGdt (gPayloadMmCpuPrivateData->PayloadMmPrivateData.PageTable);

  return gPayloadMmCpuPrivateData->PayloadMmPrivateData.PageTable;
}

/**
  Private copies of assembly function prototypes.

**/

VOID
CallMmCore (
  VOID  *PayloadMmEntryContext
  );

VOID
ModeSwitchCallMmCore (
  VOID  *PayloadMmEntryContext
  );

/**
  Register payload MMI entrypoint with bootloader SMM.

  @param[in] MmEntryPoint      MM Foundation entry point.

  @retval PayloadMmEntryPoint  Bootloader-specific transfer execution function.

**/
STATIC
EFI_PHYSICAL_ADDRESS
EFIAPI
PayloadMmCpuRegisterEntryPoint (
  IN EFI_SMM_ENTRY_POINT  MmEntryPoint
  )
{
  EFI_HOB_GUID_TYPE          *GuidHob;
  PAYLOAD_MM_INTERFACE_INFO  *PayloadMmInterfaceInfo;

  //
  // Collect interface data.
  //
  GuidHob = GetFirstGuidHob (&gPayloadMmInterfaceInfoGuid);
  ASSERT (GuidHob != NULL);

  PayloadMmInterfaceInfo = GET_GUID_HOB_DATA (GuidHob);

  if (PayloadMmInterfaceInfo->BootloaderSmmIs64Bit) {
    return (UINTN)CallMmCore;
  } else {
    return (UINTN)ModeSwitchCallMmCore;
  }
}

/**
  Register the MM Foundation entry point.

  This function registers the MM Foundation entry point with the processor code. This entry point
  will be invoked by the SMM Processor entry code.

  @param[in] This                The EFI_MM_CONFIGURATION_PROTOCOL instance.
  @param[in] MmEntryPoint        MM Foundation entry point.

  @retval EFI_SUCCESS            Success to register MM Entry Point.
  @retval EFI_INVALID_PARAMETER  MmEntryPoint is NULL.

**/
EFI_STATUS
EFIAPI
RegisterPayloadMmEntry (
  IN CONST EFI_SMM_CONFIGURATION_PROTOCOL  *This,
  IN EFI_SMM_ENTRY_POINT                   MmEntryPoint
  )
{
  EFI_PHYSICAL_ADDRESS  PayloadMmEntryPoint;
  EFI_STATUS            Status;

  PayloadMmEntryPoint = PayloadMmCpuRegisterEntryPoint (MmEntryPoint);
  ASSERT (PayloadMmEntryPoint != 0);

  Status = SaveMmInfoForS3 (PayloadMmEntryPoint);
  ASSERT_EFI_ERROR (Status);

  //
  // Record SMM Foundation EntryPoint, later invoke it on SMI entry vector.
  //
  gPayloadMmCpuPrivateData->SmmCoreEntry = MmEntryPoint;

  return Status;
}
