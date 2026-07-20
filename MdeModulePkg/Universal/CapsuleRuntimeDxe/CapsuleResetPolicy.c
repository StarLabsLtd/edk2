/** @file
  Capsule staging reset policy.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "CapsuleResetPolicy.h"

EFI_RESET_TYPE
GetCapsuleResetType (
  IN BOOLEAN  PersistAcrossReset
  )
{
  return PersistAcrossReset ? EfiResetWarm : EfiResetCold;
}
