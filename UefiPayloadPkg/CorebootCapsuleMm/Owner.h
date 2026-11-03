/** @file
  Private state for the protected capsule owner, not an MM wire protocol.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once
#include <Uefi.h>
#include <Library/CapsuleVerifyLib.h>
#define CAPSULE_MAX_REGIONS 32U

typedef struct {
  UINTN Offset;
  UINTN Size;
} CAPSULE_RANGE;

typedef EFI_STATUS (*CAPSULE_RESOLVE)(VOID *Context, CONST CHAR8 Name[16], CAPSULE_RANGE *Range);
typedef EFI_STATUS (*CAPSULE_PROGRAM)(VOID *Context, UINTN Block,
                                     CONST CAPSULE_RANGE *Ranges, UINTN Count, UINT8 *Image, BOOLEAN CheckOnly);

/* Installed once by the trusted owner. No request may supply this policy. */
typedef struct {
  CONST UINT8 *Root;
  UINTN RootSize;
  UINTN FlashSize;
  UINT32 LowestSupportedVersion;
  CAPSULE_RESOLVE Resolve;
  CAPSULE_PROGRAM Program;
  VOID *Context;
  CAPSULE_RANGE VariableStore;
} CAPSULE_POLICY;

typedef struct {
  CONST CAPSULE_POLICY *Policy;
  CAPSULE_VERIFIER Verifier;
  CAPSULE_RANGE Ranges[CAPSULE_MAX_REGIONS];
  UINT8 ImageFmap[CAPSULE_BLOCK_SIZE];
  UINTN RangeCount;
  BOOLEAN Active;
} CAPSULE_OWNER;

VOID CapsuleOwnerClose(CAPSULE_OWNER *Owner);
EFI_STATUS CapsuleOwnerBegin(CAPSULE_OWNER *Owner, CONST UINT8 *Signature, UINTN Size);
EFI_STATUS CapsuleOwnerProgram(CAPSULE_OWNER *Owner, UINTN Block);
