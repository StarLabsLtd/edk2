/** @file
  Host checks for the production protected-update transaction.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "Owner.h"
VOID *EFIAPI
CopyMem(VOID *d, CONST VOID *s, UINTN n)
{
  return memcpy(d, s, n);
}
INTN EFIAPI
CompareMem(CONST VOID *a, CONST VOID *b, UINTN n)
{
  return memcmp(a, b, n);
}
static unsigned Programs;
static BOOLEAN  Mutate, FailProgram;
static BOOLEAN ShiftLayout, FailPreflight;
static BOOLEAN
Read(VOID *c, UINTN o, VOID *b, UINTN n)
{
  FILE *f = c;
  if (fseek(f, (long)o, SEEK_SET) || fread(b, 1, n, f) != n)
    return FALSE;
  if (Mutate && o <= 4096 && 4096 < o + n)
    ((UINT8 *)b)[4096 - o] ^= 1;
  return TRUE;
}
static UINT8 *
Load(const char *p, UINTN *n)
{
  FILE *f = fopen(p, "rb");
  if (!f)
    exit(2);
  fseek(f, 0, SEEK_END);
  *n = ftell(f);
  rewind(f);
  UINT8 *b = malloc(*n);
  if (!b || fread(b, 1, *n, f) != *n)
    exit(2);
  fclose(f);
  return b;
}
static EFI_STATUS
Resolve(VOID *C, CONST CHAR8 Name[16], CAPSULE_RANGE *R)
{
  (void)C;
  CONST CHAR8 Expected[16] = "COREBOOT";
  CONST CHAR8 Bios[16] = "BIOS";
  if (!memcmp(Name, Bios, 16)) {
    R->Offset=0; R->Size=2*CAPSULE_BLOCK_SIZE; return EFI_SUCCESS;
  }
  CONST CHAR8 Ec[16] = "EC";
  if (!memcmp(Name, Ec, 16)) {
    R->Offset = 61440; R->Size = 4096; return EFI_SUCCESS;
  }
  if (memcmp(Name, Expected, 16))
    return EFI_NOT_FOUND;
  R->Offset = ShiftLayout ? 4097 : 4096;
  R->Size   = CAPSULE_BLOCK_SIZE - 8192;
  return EFI_SUCCESS;
}
static EFI_STATUS
Program(VOID *C, UINTN Block, CONST CAPSULE_RANGE *R, UINTN Count, UINT8 *Image, BOOLEAN CheckOnly)
{
  (void)C;
  (void)Image;
  if (CheckOnly) return FailPreflight ? EFI_WRITE_PROTECTED : EFI_SUCCESS;
  if (Block ||
      (ShiftLayout ? (Count != 1 || R[0].Offset != 0 || R[0].Size != 2 * CAPSULE_BLOCK_SIZE) :
                     (Count != 2 || R[0].Offset != 4096 || R[0].Size != CAPSULE_BLOCK_SIZE - 8192 ||
                      R[1].Offset != 61440 || R[1].Size != 4096)))
    abort();
  Programs++;
  return FailProgram ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
#define CHECK(X)                                                                                   \
  do {                                                                                             \
    if (!(X)) {                                                                                    \
      fprintf(stderr, "failed line %u: %s\n", __LINE__, #X);                                       \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)
int
main(int argc, char **argv)
{
  if (argc != 4)
    return 2;
  UINTN          SignatureSize, RootSize;
  UINT8         *Signature = Load(argv[2], &SignatureSize), *Root = Load(argv[3], &RootSize);
  FILE          *f     = fopen(argv[1], "rb");
  CAPSULE_OWNER *Owner = calloc(1, sizeof(*Owner));
  CHECK(f && Owner);
  CAPSULE_POLICY Policy       = {.Root                   = Root,
                                 .RootSize               = RootSize,
                                 .FlashSize              = 2 * CAPSULE_BLOCK_SIZE,
                                 .LowestSupportedVersion = 10,
                                 .Resolve                = Resolve,
                                 .Program                = Program,
                                 .VariableStore          = {CAPSULE_BLOCK_SIZE, CAPSULE_BLOCK_SIZE}};
  Owner->Policy               = &Policy;
  Owner->Verifier.Read        = Read;
  Owner->Verifier.Context     = f;
  Owner->Verifier.ImageOffset = 16;
  Owner->Verifier.ImageSize   = Policy.FlashSize;
  fseek(f, 0, SEEK_END);
  Owner->Verifier.SignedSize = ftell(f);
  rewind(f);
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_ACCESS_DENIED && Programs == 0);
  FailPreflight = TRUE;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_WRITE_PROTECTED &&
        !Owner->Active && Programs == 0);
  FailPreflight = FALSE;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_SUCCESS && Owner->Active);
  CHECK(CapsuleOwnerProgram(Owner, 1) == EFI_SUCCESS && Programs == 0);
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_SUCCESS && Programs == 1);
  Mutate = TRUE;
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_SECURITY_VIOLATION && !Owner->Active && Programs == 1);
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_SECURITY_VIOLATION &&
        !Owner->Active);
  Mutate                        = FALSE;
  Policy.LowestSupportedVersion = 43;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_INCOMPATIBLE_VERSION &&
        !Owner->Active);
  Policy.LowestSupportedVersion = 10;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_SUCCESS);
  CapsuleOwnerClose(Owner);
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_ACCESS_DENIED && Programs == 1);
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_SUCCESS);
  FailProgram = TRUE;
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_DEVICE_ERROR && !Owner->Active && Programs == 2);
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_ACCESS_DENIED && Programs == 2);
  FailProgram = FALSE;
  ShiftLayout = TRUE;
  FailPreflight = TRUE;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_WRITE_PROTECTED &&
        !Owner->Active && Programs == 2);
  FailPreflight = FALSE;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_SUCCESS);
  CHECK(Owner->RangeCount == 1 && Owner->Ranges[0].Offset == 0 && Owner->Ranges[0].Size == Policy.FlashSize);
  CHECK(CapsuleOwnerProgram(Owner, 1) == EFI_SUCCESS && Programs == 2);
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_SUCCESS && Programs == 3);
  CapsuleOwnerClose(Owner);
  Policy.VariableStore.Offset = 0;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_INCOMPATIBLE_VERSION &&
        !Owner->Active && Programs == 3);
  puts("Owner transaction: signature, region, version, cancellation and program failure checks "
       "passed");
  fclose(f);
  free(Owner);
  free(Signature);
  free(Root);
  return 0;
}

INTN EFIAPI AsciiStrCmp(CONST CHAR8 *A, CONST CHAR8 *B) { return strcmp(A, B); }
