/** @file

  HOB construction interface for the cdk2 EDK II backend.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_EFI_HOBS_H_
#define CDK2_EFI_HOBS_H_

#include "entry/Cdk2EfiEntry.h"

EFI_STATUS
Cdk2EfiBuildHobFromBl (
  VOID
  );

VOID
Cdk2EfiBuildGenericHob (
  VOID
  );

EFI_STATUS
Cdk2EfiFindFreeMemForHobCallback (
  IN MEMORY_MAP_ENTRY  *MemoryMapEntry,
  IN VOID              *Params
  );

#endif
