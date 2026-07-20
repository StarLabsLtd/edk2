/** @file
  Capsule staging reset policy.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

EFI_RESET_TYPE
GetCapsuleResetType (
  IN BOOLEAN  PersistAcrossReset
  );
