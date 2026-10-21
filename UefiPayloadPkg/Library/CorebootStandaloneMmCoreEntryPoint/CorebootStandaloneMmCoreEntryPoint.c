/** @file
  Entry point for a Standalone MM core owned by coreboot.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>

#include <Library/StandaloneMmCoreEntryPoint.h>

VOID  *gHobList = NULL;

VOID
EFIAPI
_ModuleEntryPoint (
  IN VOID  *Context
  )
{
  if (gHobList == NULL) {
    gHobList = Context;
    ProcessModuleEntryPointList (Context);
  }
}

VOID
EFIAPI
EfiMain (
  IN VOID  *Context
  )
{
  _ModuleEntryPoint (Context);
}
