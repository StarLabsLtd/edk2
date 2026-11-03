/** @file
  Private bounded verification for the coreboot capsule owner.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once
#include <Base.h>

#define CAPSULE_BLOCK_SIZE  65536U
#define CAPSULE_MAX_BLOCKS  512U
#define CAPSULE_SHA256_SIZE 32U

/* The owner validates the source range and copies into protected memory. */
typedef BOOLEAN (*CAPSULE_READ)(VOID *Context, UINTN Offset, VOID *Buffer, UINTN Size);

typedef struct {
  CAPSULE_READ Read;
  VOID         *Context;
  UINTN        SignedSize;
  UINTN        ImageOffset;
  UINTN        ImageSize;
  UINT8        Buffer[CAPSULE_BLOCK_SIZE];
  UINT8        Hashes[CAPSULE_MAX_BLOCKS][CAPSULE_SHA256_SIZE];
  /* Signed header and trailer, concatenated without the firmware image. */
  UINT8        Metadata[CAPSULE_BLOCK_SIZE];
  UINTN        MetadataSize;
  UINTN        Position;
  UINTN        BlockUsed;
  UINTN        BlockCount;
  BOOLEAN      Failed;
  BOOLEAN      Verified;
  VOID         *BlockDigest;
} CAPSULE_VERIFIER;

/* All parameters and the complete verifier must reside in protected memory. */
BOOLEAN CapsuleVerify (CAPSULE_VERIFIER *State, CONST UINT8 *Signature,
                       UINTN SignatureSize, CONST UINT8 *Root, UINTN RootSize);
/* Copies and checks one flash block; only State->Buffer may then be programmed. */
BOOLEAN CapsuleReadVerifiedBlock (CAPSULE_VERIFIER *State, UINTN Block);
