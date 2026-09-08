/** @file
  This library provides some payload MM helper functions.

  Copyright (c) 2025, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PAYLOAD_MM_HELPER_LIB_H_
#define _PAYLOAD_MM_HELPER_LIB_H_

#include <PiDxe.h>

#include <Guid/PayloadMmInterfaceInfoGuid.h>

// Boot-only command transport. Cmd contains the APMC command and subcommand.
UINTN
EFIAPI
TriggerSmi (
  IN UINTN  Cmd,
  IN UINTN  Arg,
  IN UINTN  Retry
  );

/**
  Fills control-flow fields used by payload MM assembly code.

**/
VOID
EFIAPI
CheckFeatureSupported (
  IN PAYLOAD_MM_EDK2_PRIVATE_DATA  *PrivateData
  );

#endif
