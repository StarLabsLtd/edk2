/** @file
  Coreboot table handoff HOB.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

extern EFI_GUID  gUefiPayloadCorebootTableGuid;

typedef struct {
  UINT64  Address;
  UINT32  Size;
  UINT32  Reserved;
} COREBOOT_TABLE_HOB;
