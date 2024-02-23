/** @file
SMM profile internal header file.

Copyright (c) 2012 - 2024, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2020, AMD Incorporated. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_PROFILE_INTERNAL_H_
#define _SMM_PROFILE_INTERNAL_H_

#include <PiMm.h>
#include <Library/BaseLib.h>
#include <Library/PcdLib.h>

#include "SmmProfileArch.h"

#define MAX_PF_ENTRY_COUNT  10

#define IA32_PF_EC_ID  (1u << 4)

#define HEAP_GUARD_NONSTOP_MODE      \
        ((PcdGet8 (PcdHeapGuardPropertyMask) & (BIT6|BIT3|BIT2)) > BIT6)

#define NULL_DETECTION_NONSTOP_MODE  \
        ((PcdGet8 (PcdNullPointerDetectionPropertyMask) & (BIT6|BIT1)) > BIT6)

extern UINTN              *mPFEntryCount;
extern UINT64 (*mLastPFEntryValue)[MAX_PF_ENTRY_COUNT];
extern UINT64                    *(*mLastPFEntryPointer)[MAX_PF_ENTRY_COUNT];

//
// Internal functions
//

/**
  Update IDT table to replace page fault handler and INT 1 handler.

**/
VOID
InitIdtr (
  VOID
  );

/**
  Clear TF in FLAGS.

  @param  SystemContext    A pointer to the processor context when
                           the interrupt occurred on the processor.

**/
VOID
ClearTrapFlag (
  IN OUT EFI_SYSTEM_CONTEXT  SystemContext
  );

#endif // _SMM_PROFILE_H_
