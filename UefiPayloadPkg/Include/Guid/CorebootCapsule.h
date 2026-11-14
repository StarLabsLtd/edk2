/** @file
  Coreboot capsule communication and private owner handoff.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once
#include <Uefi.h>
extern EFI_GUID gCorebootCapsuleInfoGuid;
extern EFI_GUID gCorebootCapsuleUpdateGuid;
#define COREBOOT_CAPSULE_REVISION 2U
#define COREBOOT_CAPSULE_INFO 1U
#define COREBOOT_CAPSULE_BEGIN 2U
#define COREBOOT_CAPSULE_PROGRAM 3U
#define COREBOOT_CAPSULE_CLOSE 5U
#define COREBOOT_CAPSULE_MAX_SIGNATURE 65536U
#pragma pack(1)
typedef struct {
  UINT32 Revision, Size, FlashSize, BlockSize, LowestSupportedVersion;
  UINT32 Read, Resolve, Program, Buffer, BufferSize;
  EFI_GUID ImageGuid;
} COREBOOT_CAPSULE_PRIVATE_INFO;
typedef struct {
  UINT32 Revision, Command, Transaction;
  /* Command status uses the IA32 EFI error bit, independent of caller width. */
  UINT32 Result;
} COREBOOT_CAPSULE_HEADER;
typedef struct {
  COREBOOT_CAPSULE_HEADER Header;
  UINT32 FlashSize, BlockSize, LowestSupportedVersion;
} COREBOOT_CAPSULE_GEOMETRY;
typedef struct {
  COREBOOT_CAPSULE_HEADER Header;
  UINT64 Address;
  UINT32 SignedSize, ImageOffset, SignatureSize;
  UINT8 Signature[];
} COREBOOT_CAPSULE_START;
typedef struct {
  COREBOOT_CAPSULE_HEADER Header;
  UINT32 Block;
} COREBOOT_CAPSULE_BLOCK;
#pragma pack()
STATIC_ASSERT(sizeof(COREBOOT_CAPSULE_PRIVATE_INFO) == 56, "Capsule private handoff ABI");
STATIC_ASSERT(OFFSET_OF(COREBOOT_CAPSULE_PRIVATE_INFO, ImageGuid) == 40, "Capsule namespace ABI");
STATIC_ASSERT(sizeof(COREBOOT_CAPSULE_HEADER) == 16, "Capsule wire header ABI");
STATIC_ASSERT(OFFSET_OF(COREBOOT_CAPSULE_START, Signature) == 36, "Capsule begin ABI");
