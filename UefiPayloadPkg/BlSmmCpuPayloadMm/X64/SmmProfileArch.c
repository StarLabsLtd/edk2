/** @file
X64 processor specific functions to enable SMM profile.

Copyright (c) 2012 - 2024, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2017, AMD Incorporated. All rights reserved.<BR>

SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>

#include "BlSmmCpuPayloadMm.h"

/**
  Clear TF in FLAGS.

  @param  SystemContext    A pointer to the processor context when
                           the interrupt occurred on the processor.

**/
VOID
ClearTrapFlag (
  IN OUT EFI_SYSTEM_CONTEXT  SystemContext
  )
{
  SystemContext.SystemContextX64->Rflags &= (UINTN) ~BIT8;
}
