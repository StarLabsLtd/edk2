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
static BOOLEAN ShiftLayout, ShiftEc, FailPreflight;
static UINTN MutationOffset = 4096;
static BOOLEAN
Read(VOID *c, UINTN o, VOID *b, UINTN n)
{
  FILE *f = c;
  if (fseek(f, (long)o, SEEK_SET) || fread(b, 1, n, f) != n)
    return FALSE;
  if (Mutate && o <= MutationOffset && MutationOffset < o + n)
    ((UINT8 *)b)[MutationOffset - o] ^= 1;
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
    R->Offset = ShiftEc ? 61439 : 61440; R->Size = 4096; return EFI_SUCCESS;
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
static UINT32 AbSlot;
static unsigned Commits;
static BOOLEAN FailCommit;

static EFI_STATUS
AbResolve(VOID *Context, CONST CHAR8 Name[16], CAPSULE_RANGE *Range)
{
  CONST CHAR8 Names[6][16] = {
    "FW_MAIN_A", "RW_FWID_A", "VBLOCK_A", "FW_MAIN_B", "RW_FWID_B", "VBLOCK_B"
  };
  (void)Context;
  for (UINTN Index = 0; Index < ARRAY_SIZE(Names); Index++) {
    if (!memcmp(Name, Names[Index], sizeof(Names[Index]))) {
      UINTN Base = (1 + Index / 3) * CAPSULE_BLOCK_SIZE;
      CONST UINTN Offsets[3] = {4096, CAPSULE_BLOCK_SIZE - 64, 0};
      CONST UINTN Sizes[3] = {CAPSULE_BLOCK_SIZE - 4096 - 64, 64, 4096};
      Range->Offset = Base + Offsets[Index % 3];
      Range->Size = Sizes[Index % 3];
      return EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}

static EFI_STATUS
AbProgram(VOID *Context, UINTN Block, CONST CAPSULE_RANGE *Ranges, UINTN Count,
          UINT8 *Image, BOOLEAN CheckOnly)
{
  (void)Context;
  (void)Image;
  if (Block != AbSlot || Count != 3) {
    abort();
  }
  for (UINTN Index = 0; Index < Count; Index++) {
    if (Ranges[Index].Offset < AbSlot * CAPSULE_BLOCK_SIZE ||
        Ranges[Index].Offset + Ranges[Index].Size > (AbSlot + 1) * CAPSULE_BLOCK_SIZE) {
      abort();
    }
  }
  if (CheckOnly) {
    return EFI_SUCCESS;
  }
  Programs++;
  return FailProgram ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS
AbCommit(VOID *Context, UINT32 Slot)
{
  (void)Context;
  if (Slot != AbSlot) {
    abort();
  }
  if (FailCommit) {
    return EFI_DEVICE_ERROR;
  }
  Commits++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EcProgram(VOID *Context, UINTN Block, CONST CAPSULE_RANGE *Ranges, UINTN Count,
          UINT8 *Image, BOOLEAN CheckOnly)
{
  (void)Context;
  (void)Image;
  if (Block != 0 || Count != 1 || Ranges[0].Offset != 61440 || Ranges[0].Size != 4096) {
    abort();
  }
  if (!CheckOnly) {
    Programs++;
  }
  return EFI_SUCCESS;
}

static int
TestEc(CAPSULE_OWNER *Owner, CAPSULE_POLICY *Policy, CONST UINT8 *Signature, UINTN Size,
       BOOLEAN Reject)
{
  Policy->UpdateSlot = AbSlot;
  Policy->Commit = AbCommit;
  Policy->Program = EcProgram;
  if (Reject) {
    CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_INCOMPATIBLE_VERSION);
    CHECK(!Owner->Active && Programs == 0 && Commits == 0);
    return 0;
  }
  Policy->ImageGuid.Data1 ^= 1;
  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SECURITY_VIOLATION);
  Policy->ImageGuid.Data1 ^= 1;
  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  CHECK(Owner->RangeCount == 1 && !Owner->ArmTrial);
  CHECK(CapsuleOwnerProgram(Owner, 1) == EFI_INVALID_PARAMETER);
  CHECK(Programs == 0 && Commits == 0);
  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_SUCCESS);
  CHECK(CapsuleOwnerProgram(Owner, 1) == EFI_SUCCESS);
  CHECK(Programs == 1 && Commits == 0);
  CHECK(CapsuleOwnerProgram(Owner, 1) == EFI_INVALID_PARAMETER);
  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  Mutate = TRUE;
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_SECURITY_VIOLATION);
  CHECK(Programs == 1 && Commits == 0);
  Mutate = FALSE;
  ShiftEc = TRUE;
  /* A shifted EC layout must never turn into a whole-BIOS fallback. */
  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_INCOMPATIBLE_VERSION);
  CHECK(!Owner->Active && Programs == 1 && Commits == 0);
  puts("EC-only owner: authenticated bounded writes, no A/B commit, mutation/layout rejection passed");
  return 0;
}

static int
TestAb(CAPSULE_OWNER *Owner, CAPSULE_POLICY *Policy, CONST UINT8 *Signature, UINTN Size)
{
  Policy->UpdateSlot = AbSlot;
  Policy->Resolve = AbResolve;
  Policy->Program = AbProgram;
  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SECURITY_VIOLATION);
  Policy->Commit = AbCommit;
  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  CHECK(Owner->RangeCount == 3);
  CHECK(CapsuleOwnerProgram(Owner, 1) == EFI_INVALID_PARAMETER && !Owner->Active);
  CHECK(Programs == 0 && Commits == 0);

  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  for (UINTN Block = 0; Block < 3; Block++) {
    CHECK(CapsuleOwnerProgram(Owner, Block) == EFI_SUCCESS);
    CHECK(Commits == 0);
  }
  CapsuleOwnerClose(Owner);
  CHECK(Programs == 1 && Commits == 0);

  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  for (UINTN Block = 0; Block < 4; Block++) {
    CHECK(CapsuleOwnerProgram(Owner, Block) == EFI_SUCCESS);
  }
  CHECK(Programs == 2 && Commits == 1);
  CHECK(CapsuleOwnerProgram(Owner, 3) == EFI_INVALID_PARAMETER && !Owner->Active);
  CHECK(Commits == 1);

  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  FailProgram = TRUE;
  for (UINTN Block = 0; Block <= AbSlot; Block++) {
    CHECK(CapsuleOwnerProgram(Owner, Block) ==
          (Block == AbSlot ? EFI_DEVICE_ERROR : EFI_SUCCESS));
  }
  CHECK(!Owner->Active && Commits == 1);
  FailProgram = FALSE;

  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  MutationOffset = AbSlot * CAPSULE_BLOCK_SIZE + 4096;
  Mutate = TRUE;
  for (UINTN Block = 0; Block <= AbSlot; Block++) {
    CHECK(CapsuleOwnerProgram(Owner, Block) ==
          (Block == AbSlot ? EFI_SECURITY_VIOLATION : EFI_SUCCESS));
  }
  CHECK(!Owner->Active && Commits == 1);
  Mutate = FALSE;

  CHECK(CapsuleOwnerBegin(Owner, Signature, Size) == EFI_SUCCESS);
  FailCommit = TRUE;
  for (UINTN Block = 0; Block < 4; Block++) {
    CHECK(CapsuleOwnerProgram(Owner, Block) ==
          (Block == 3 ? EFI_DEVICE_ERROR : EFI_SUCCESS));
  }
  CHECK(!Owner->Active && Commits == 1);
  puts("A/B owner: inactive-only writes, ordered completion, cancellation and failure checks passed");
  return 0;
}

int
main(int argc, char **argv)
{
  if (argc != 4 && argc != 5 && argc != 6)
    return 2;
  UINTN          SignatureSize, RootSize;
  UINT8         *Signature = Load(argv[2], &SignatureSize), *Root = Load(argv[3], &RootSize);
  FILE          *f     = fopen(argv[1], "rb");
  CAPSULE_OWNER *Owner = calloc(1, sizeof(*Owner));
  CHECK(f && Owner);
  CAPSULE_POLICY Policy       = {.Root                   = Root,
                                 .RootSize               = RootSize,
                                 .FlashSize              = 2 * CAPSULE_BLOCK_SIZE,
                                 .ImageGuid              = {0x00112233, 0x4455, 0x6677,
                                                          {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}},
                                 .LowestSupportedVersion = 10,
                                 .Resolve                = Resolve,
                                 .Program                = Program,
                                 .VariableStore          = {CAPSULE_BLOCK_SIZE, CAPSULE_BLOCK_SIZE}};
  if (argc == 6) {
    Policy.FlashSize = !strcmp(argv[4], "ab") ? 4 * CAPSULE_BLOCK_SIZE :
                       2 * CAPSULE_BLOCK_SIZE;
    if (!strcmp(argv[4], "ab")) {
      Policy.VariableStore = (CAPSULE_RANGE){0, CAPSULE_BLOCK_SIZE};
    }
    AbSlot = (UINT32)strtoul(argv[5], NULL, 0);
  }
  Owner->Policy               = &Policy;
  Owner->Verifier.Read        = Read;
  Owner->Verifier.Context     = f;
  Owner->Verifier.ImageOffset = argc == 5 ? strtoul(argv[4], NULL, 0) : 32;
  Owner->Verifier.ImageSize   = Policy.FlashSize;
  fseek(f, 0, SEEK_END);
  Owner->Verifier.SignedSize = ftell(f);
  rewind(f);
  if (argc == 6) {
    int Result = !strcmp(argv[4], "ab") ?
      TestAb(Owner, &Policy, Signature, SignatureSize) :
      TestEc(Owner, &Policy, Signature, SignatureSize, !strcmp(argv[4], "ec-reject"));
    fclose(f);
    free(Owner);
    free(Signature);
    free(Root);
    return Result;
  }
  CHECK(CapsuleOwnerProgram(Owner, 0) == EFI_ACCESS_DENIED && Programs == 0);
  if (argc == 5) {
    CHECK(EFI_ERROR(CapsuleOwnerBegin(Owner, Signature, SignatureSize)) && !Owner->Active);
    fclose(f);
    free(Owner);
    free(Signature);
    free(Root);
    return 0;
  }
  Policy.ImageGuid.Data1 ^= 1;
  CHECK(CapsuleOwnerBegin(Owner, Signature, SignatureSize) == EFI_SECURITY_VIOLATION &&
        !Owner->Active && Programs == 0);
  Policy.ImageGuid.Data1 ^= 1;
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
