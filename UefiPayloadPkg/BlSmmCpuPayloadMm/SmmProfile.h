/** @file
SMM profile header file.

Copyright (c) 2012 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_PROFILE_H_
#define _SMM_PROFILE_H_

#include <PiSmm.h>

#include "SmmProfileInternal.h"

/**
  Initialize SMM profile in SMM CPU entry point.

  @param[in] Cr3  The base address of the page tables to use in SMM.

**/
VOID
InitSmmProfile (
  VOID
  );

/**
  Page fault IDT handler for SMM Profile.

**/
VOID
EFIAPI
PageFaultIdtHandlerSmmProfile (
  VOID
  );

/**
  Update page table according to protected memory ranges and the 4KB-page mapped memory ranges.

**/
VOID
InitPaging (
  VOID
  );

/**
  Get CPU Index from APIC ID.

**/
UINTN
GetCpuIndex (
  VOID
  );

/**
  Handler for Page Fault triggered by Guard page.

  @param  ErrorCode  The Error code of exception.

**/
VOID
GuardPagePFHandler (
  UINTN  ErrorCode
  );

//
// The flag indicates if execute-disable is enabled on processor.
//
extern BOOLEAN  mXdEnabled;

#endif // _SMM_PROFILE_H_
