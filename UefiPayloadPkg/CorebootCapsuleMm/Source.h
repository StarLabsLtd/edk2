/** @file
  Private validated source for the capsule verifier.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once
#include <Uefi.h>
typedef struct {
  EFI_PHYSICAL_ADDRESS Address;
  UINTN Size;
} CAPSULE_SOURCE;
BOOLEAN CapsuleSourceInit(CAPSULE_SOURCE *Source, EFI_PHYSICAL_ADDRESS Address, UINTN Size);
BOOLEAN CapsuleSourceRead(VOID *Context, UINTN Offset, VOID *Buffer, UINTN Size);
