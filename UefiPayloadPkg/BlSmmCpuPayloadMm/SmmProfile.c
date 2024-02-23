/** @file
Enable SMM profile.

Copyright (c) 2012 - 2023, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017 - 2020, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/BaseLib.h>
#include <Library/CpuExceptionHandlerLib.h>
#include <Library/CpuLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PerformanceLib.h>
#include <Library/MmServicesTableLib.h>

#include <Register/Intel/Cpuid.h>

#include "BlSmmCpuPayloadMm.h"

//
// The flag indicates if execute-disable is enabled on processor.
//
BOOLEAN  mXdEnabled = FALSE;

//
// Record the page fault exception count for one instruction execution.
//
UINTN  *mPFEntryCount;

UINT64 (*mLastPFEntryValue)[MAX_PF_ENTRY_COUNT];
UINT64                    *(*mLastPFEntryPointer)[MAX_PF_ENTRY_COUNT];

/**
  Get CPU Index from APIC ID.

**/
UINTN
GetCpuIndex (
  VOID
  )
{
  return gMmst->CurrentlyExecutingCpu;
}

/**
  SMM profile specific INT 1 (single-step) exception handler.

  @param  InterruptType    Defines the type of interrupt or exception that
                           occurred on the processor.This parameter is processor architecture specific.
  @param  SystemContext    A pointer to the processor context when
                           the interrupt occurred on the processor.
**/
VOID
EFIAPI
DebugExceptionHandler (
  IN EFI_EXCEPTION_TYPE  InterruptType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  UINTN  CpuIndex;
  UINTN  PFEntry;

  if (!HEAP_GUARD_NONSTOP_MODE &&
      !NULL_DETECTION_NONSTOP_MODE)
  {
    return;
  }

  CpuIndex = GetCpuIndex ();

  //
  // Clear last PF entries
  //
  for (PFEntry = 0; PFEntry < mPFEntryCount[CpuIndex]; PFEntry++) {
    *mLastPFEntryPointer[CpuIndex][PFEntry] = mLastPFEntryValue[CpuIndex][PFEntry];
  }

  //
  // Reset page fault exception count for next page fault.
  //
  mPFEntryCount[CpuIndex] = 0;

  //
  // Flush TLB
  //
  CpuFlushTlb ();

  //
  // Clear TF in EFLAGS
  //
  ClearTrapFlag (SystemContext);
}

/**
  Initialize SMM profile data structures.

**/
VOID
InitSmmProfileInternal (
  VOID
  )
{
  mPFEntryCount = (UINTN *)AllocateZeroPool (sizeof (UINTN) * mMaxNumberOfCpus);
  ASSERT (mPFEntryCount != NULL);
  mLastPFEntryValue = (UINT64 (*)[MAX_PF_ENTRY_COUNT])AllocateZeroPool (
                                                        sizeof (mLastPFEntryValue[0]) * mMaxNumberOfCpus
                                                        );
  ASSERT (mLastPFEntryValue != NULL);
  mLastPFEntryPointer = (UINT64 *(*)[MAX_PF_ENTRY_COUNT])AllocateZeroPool (
                                                           sizeof (mLastPFEntryPointer[0]) * mMaxNumberOfCpus
                                                           );
  ASSERT (mLastPFEntryPointer != NULL);
}

/**
  Initialize SMM profile in SMM CPU entry point.

  @param[in] Cr3  The base address of the page tables to use in SMM.

**/
VOID
InitSmmProfile (
  VOID
  )
{
  //
  // Skip SMM profile initialization if feature is disabled
  //
  if (!HEAP_GUARD_NONSTOP_MODE &&
      !NULL_DETECTION_NONSTOP_MODE)
  {
    return;
  }

  //
  // Initialize SmmProfile here
  //
  InitSmmProfileInternal ();

  //
  // Initialize profile IDT.
  //
  InitIdtr ();
}

/**
  Update page table to map the memory correctly in order to make the instruction
  which caused page fault execute successfully. And it also save the original page
  table to be restored in single-step exception.

  @param  PageTable           PageTable Address.
  @param  PFAddress           The memory address which caused page fault exception.
  @param  CpuIndex            The index of the processor.
  @param  ErrorCode           The Error code of exception.

**/
VOID
RestorePageTableBelow4G (
  UINT64  *PageTable,
  UINT64  PFAddress,
  UINTN   CpuIndex,
  UINTN   ErrorCode
  )
{
  UINTN     PTIndex;
  UINTN     PFIndex;
  IA32_CR4  Cr4;
  BOOLEAN   Enable5LevelPaging;

  Cr4.UintN          = AsmReadCr4 ();
  Enable5LevelPaging = (BOOLEAN)(Cr4.Bits.LA57 == 1);

  //
  // PML5
  //
  if (Enable5LevelPaging) {
    PTIndex = (UINTN)BitFieldRead64 (PFAddress, 48, 56);
    ASSERT (PageTable[PTIndex] != 0);
    PageTable = (UINT64 *)(UINTN)(PageTable[PTIndex] & PHYSICAL_ADDRESS_MASK);
  }

  //
  // PML4
  //
  if (sizeof (UINT64) == sizeof (UINTN)) {
    PTIndex = (UINTN)BitFieldRead64 (PFAddress, 39, 47);
    ASSERT (PageTable[PTIndex] != 0);
    PageTable = (UINT64 *)(UINTN)(PageTable[PTIndex] & PHYSICAL_ADDRESS_MASK);
  }

  //
  // PDPTE
  //
  PTIndex = (UINTN)BitFieldRead64 (PFAddress, 30, 38);

  if ((PageTable[PTIndex] & IA32_PG_P) == 0) {
    //
    // For 32-bit case, because a full map page table for 0-4G is created by default,
    // and since the PDPTE must be one non-leaf entry, the PDPTE must always be present.
    // So, ASSERT it must be the 64-bit case running here.
    //
    ASSERT (sizeof (UINT64) == sizeof (UINTN));

    //
    // If the entry is not present, allocate one page from page pool for it
    //
    PageTable[PTIndex] = AllocPage () | mAddressEncMask | PAGE_ATTRIBUTE_BITS;
  }

  ASSERT (PageTable[PTIndex] != 0);
  PageTable = (UINT64 *)(UINTN)(PageTable[PTIndex] & PHYSICAL_ADDRESS_MASK);

  //
  // PD
  //
  PTIndex = (UINTN)BitFieldRead64 (PFAddress, 21, 29);
  if ((PageTable[PTIndex] & IA32_PG_P) == 0) {
    //
    // A 2M page size will be used directly when the 2M entry is marked as non-present.
    //

    //
    // Record old entries with non-present status
    // Old entries include the memory which instruction is at and the memory which instruction access.
    //
    //
    ASSERT (mPFEntryCount[CpuIndex] < MAX_PF_ENTRY_COUNT);
    if (mPFEntryCount[CpuIndex] < MAX_PF_ENTRY_COUNT) {
      PFIndex                                = mPFEntryCount[CpuIndex];
      mLastPFEntryValue[CpuIndex][PFIndex]   = PageTable[PTIndex];
      mLastPFEntryPointer[CpuIndex][PFIndex] = &PageTable[PTIndex];
      mPFEntryCount[CpuIndex]++;
    }

    //
    // Set new entry
    //
    PageTable[PTIndex]  = (PFAddress & ~((1ull << 21) - 1));
    PageTable[PTIndex] |= (UINT64)IA32_PG_PS;
    PageTable[PTIndex] |= (UINT64)PAGE_ATTRIBUTE_BITS;
    if ((ErrorCode & IA32_PF_EC_ID) != 0) {
      PageTable[PTIndex] &= ~IA32_PG_NX;
    }
  } else {
    //
    // If the 2M entry is marked as present, a 4K page size will be utilized.
    // In this scenario, the 2M entry must be a non-leaf entry.
    //
    ASSERT (PageTable[PTIndex] != 0);
    PageTable = (UINT64 *)(UINTN)(PageTable[PTIndex] & PHYSICAL_ADDRESS_MASK);

    //
    // 4K PTE
    //
    PTIndex = (UINTN)BitFieldRead64 (PFAddress, 12, 20);

    //
    // Record old entries with non-present status
    // Old entries include the memory which instruction is at and the memory which instruction access.
    //
    //
    ASSERT (mPFEntryCount[CpuIndex] < MAX_PF_ENTRY_COUNT);
    if (mPFEntryCount[CpuIndex] < MAX_PF_ENTRY_COUNT) {
      PFIndex                                = mPFEntryCount[CpuIndex];
      mLastPFEntryValue[CpuIndex][PFIndex]   = PageTable[PTIndex];
      mLastPFEntryPointer[CpuIndex][PFIndex] = &PageTable[PTIndex];
      mPFEntryCount[CpuIndex]++;
    }

    //
    // Set new entry
    //
    PageTable[PTIndex]  = (PFAddress & ~((1ull << 12) - 1));
    PageTable[PTIndex] |= (UINT64)PAGE_ATTRIBUTE_BITS;
    if ((ErrorCode & IA32_PF_EC_ID) != 0) {
      PageTable[PTIndex] &= ~IA32_PG_NX;
    }
  }
}

/**
  Handler for Page Fault triggered by Guard page.

  @param  ErrorCode  The Error code of exception.

**/
VOID
GuardPagePFHandler (
  UINTN  ErrorCode
  )
{
  UINT64  *PageTable;
  UINT64  PFAddress;
  UINT64  RestoreAddress;
  UINTN   RestorePageNumber;
  UINTN   CpuIndex;

  PageTable = (UINT64 *)AsmReadCr3 ();
  PFAddress = AsmReadCr2 ();
  CpuIndex  = GetCpuIndex ();

  //
  // Memory operation cross pages, like "rep mov" instruction, will cause
  // infinite loop between this and Debug Trap handler. We have to make sure
  // that current page and the page followed are both in PRESENT state.
  //
  RestorePageNumber = 2;
  RestoreAddress    = PFAddress;
  while (RestorePageNumber > 0) {
    RestorePageTableBelow4G (PageTable, RestoreAddress, CpuIndex, ErrorCode);
    RestoreAddress += EFI_PAGE_SIZE;
    RestorePageNumber--;
  }

  //
  // Flush TLB
  //
  CpuFlushTlb ();
}

/**
  Replace INT1 exception handler to restore page table to absent/execute-disable state
  in order to trigger page fault again to save SMM profile data..

**/
VOID
InitIdtr (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = RegisterCpuInterruptHandler (EXCEPT_IA32_DEBUG, DebugExceptionHandler);
  ASSERT_EFI_ERROR (Status);
}
