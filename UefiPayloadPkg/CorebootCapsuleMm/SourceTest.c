/** @file
  Host checks for production capsule source-range validation.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "Source.c"
EFI_GUID gCorebootCapsuleRamGuid = {.Data1 = 0xaeb3440c};
static EFI_HOB_RESOURCE_DESCRIPTOR Resource;
static BOOLEAN Outside = TRUE;
VOID *EFIAPI
CopyMem(VOID *d, CONST VOID *s, UINTN n)
{
  return memcpy(d, s, n);
}
BOOLEAN EFIAPI
CompareGuid(CONST EFI_GUID *a, CONST EFI_GUID *b)
{
  return memcmp(a, b, sizeof(*a)) == 0;
}
BOOLEAN EFIAPI
MmIsBufferOutsideMmValid(EFI_PHYSICAL_ADDRESS a, UINT64 n)
{
  (void)a;
  (void)n;
  return Outside;
}
VOID *EFIAPI
GetFirstHob(UINT16 Type)
{
  return Type == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR ? &Resource : NULL;
}
VOID *EFIAPI
GetNextHob(UINT16 Type, CONST VOID *Start)
{
  (void)Type;
  (void)Start;
  return NULL;
}
#define CHECK(X)                                                                                   \
  do {                                                                                             \
    if (!(X)) {                                                                                    \
      fprintf(stderr, "failed %u: %s\n", __LINE__, #X);                                            \
      return 1;                                                                                    \
    }                                                                                              \
  } while (0)
int
main(void)
{
  CAPSULE_SOURCE Source;
  UINT8 *Memory = malloc(4096);
  UINT8 Buffer[16];
  CHECK(Memory);
  memset(Memory, 0x55, 4096);
  Resource.Header.HobLength = sizeof(Resource);
  Resource.Owner = gCorebootCapsuleRamGuid;
  Resource.ResourceType = EFI_RESOURCE_SYSTEM_MEMORY;
  Resource.PhysicalStart = (UINTN)Memory;
  Resource.ResourceLength = 4096;
  CHECK(CapsuleSourceInit(&Source, (UINTN)Memory, 4096));
  CHECK(CapsuleSourceRead(&Source, 4080, Buffer, sizeof(Buffer)) && Buffer[0] == 0x55);
  CHECK(!CapsuleSourceRead(&Source, 4081, Buffer, sizeof(Buffer)));
  CHECK(!CapsuleSourceInit(&Source, (UINTN)Memory + 1, 4096) && Source.Size == 0);
  CHECK(!CapsuleSourceRead(&Source, 0, Buffer, 1));
  CHECK(!CapsuleSourceInit(&Source, MAX_UINT32 - 3, 8));
  CHECK(!CapsuleSourceInit(&Source, 0, 4096));
  Outside = FALSE;
  CHECK(!CapsuleSourceInit(&Source, (UINTN)Memory, 4096));
  Outside = TRUE;
  Resource.ResourceType = EFI_RESOURCE_MEMORY_MAPPED_IO;
  CHECK(!CapsuleSourceInit(&Source, (UINTN)Memory, 4096));
  Resource.ResourceType = EFI_RESOURCE_SYSTEM_MEMORY;
  Resource.Owner.Data1 ^= 1;
  CHECK(!CapsuleSourceInit(&Source, (UINTN)Memory, 4096));
  free(Memory);
  puts("Capsule source: trusted RAM, bounds, MMIO and SMRAM refusal checks passed");
  return 0;
}
