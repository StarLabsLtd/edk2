/** @file
  Production client framing, staging lifetime and complete-block iteration.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "CorebootCapsuleLib.c"
EFI_GUID gCorebootCapsuleUpdateGuid = {.Data1 = 1};
EFI_GUID gEfiCertPkcs7Guid = {.Data1 = 2};
EFI_GUID gEfiMmCommunication2ProtocolGuid = {.Data1 = 3};
static EFI_BOOT_SERVICES Services;
EFI_BOOT_SERVICES *gBS = &Services;
static EFI_MM_COMMUNICATION2_PROTOCOL Communication;
static unsigned Mode, Programs, Closes, Frees;
static EFI_STATUS ProgramStatus;
static UINT8 Arena[128 * EFI_PAGE_SIZE] __attribute__((aligned(EFI_PAGE_SIZE)));
static unsigned MapMode, MapCalls, Allocations, Pools;
static BOOLEAN ArenaBusy, OwnerActive;
static unsigned ZeroCount, FailZeroAt;
static enum { NoFault, CloseDenied, CloseLost, CloseWrongToken,
              BeginLost, BeginShort, BeginShortError, BeginErrorToken, BeginWrongSource,
              BeginRejected } Fault;
VOID *EFIAPI CopyMem(VOID *d, CONST VOID *s, UINTN n) { return memcpy(d, s, n); }
VOID *EFIAPI ZeroMem(VOID *d, UINTN n) { return memset(d, 0, n); }
BOOLEAN EFIAPI CompareGuid(CONST GUID *a, CONST GUID *b) { return !memcmp(a, b, sizeof(*a)); }
UINT32 EFIAPI ReadUnaligned32(CONST VOID *p) { UINT32 v; memcpy(&v, p, sizeof(v)); return v; }
VOID *EFIAPI AllocateZeroPool(UINTN n)
{
  VOID *p;
  ZeroCount++;
  if (ZeroCount == FailZeroAt) return NULL;
  p = calloc(1, n);
  if (p) Pools++;
  return p;
}
VOID *EFIAPI AllocatePool(UINTN n) { VOID *p = malloc(n); if (p) Pools++; return p; }
VOID EFIAPI FreePool(VOID *p) { if (!p || !Pools) abort(); Pools--; free(p); }
static EFI_STATUS EFIAPI GetMap(UINTN *size, EFI_MEMORY_DESCRIPTOR *map,
                                UINTN *key, UINTN *stride, UINT32 *version)
{
  EFI_MEMORY_DESCRIPTOR d = {0};
  UINTN needed = 3 * (sizeof(d) + 16);
  *key = 1;
  *stride = sizeof(d) + 16;
  *version = MapMode == 3 ? 0 : EFI_MEMORY_DESCRIPTOR_VERSION;
  MapCalls++;
  if (!map || *size < needed || (MapMode == 1 && *size < needed + 3 * *stride)) {
    *size = MapMode == 1 && map ? needed + 3 * *stride : needed;
    return EFI_BUFFER_TOO_SMALL;
  }
  *size = needed;
  d.Type = EfiConventionalMemory;
  d.PhysicalStart = BASE_4GB;
  d.NumberOfPages = 64;
  memcpy(map, &d, sizeof(d));
  d.PhysicalStart = (UINTN)Arena + 64 * EFI_PAGE_SIZE;
  d.NumberOfPages = MapMode == 4 ? 1 : 48;
  memcpy((UINT8 *)map + *stride, &d, sizeof(d));
  d.PhysicalStart = (UINTN)Arena;
  d.NumberOfPages = MapMode == 4 ? 1 : 48;
  memcpy((UINT8 *)map + 2 * *stride, &d, sizeof(d));
  if (MapMode == 6) *size = needed + 3 * *stride;
  if (MapMode == 7) *stride = 0;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Pages(EFI_ALLOCATE_TYPE t, EFI_MEMORY_TYPE m, UINTN n, EFI_PHYSICAL_ADDRESS *a)
{
  Allocations++;
  if (t != AllocateAddress || m != EfiBootServicesData || n != 33 ||
      (*a != (UINTN)Arena && *a != (UINTN)Arena + 64 * EFI_PAGE_SIZE) || ArenaBusy) abort();
  if (MapMode == 5 || (MapMode == 8 && *a == (UINTN)Arena) ||
      (MapMode == 2 && Allocations == 1)) { *a = MAX_UINT64; return EFI_NOT_FOUND; }
  ArenaBusy = TRUE;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI FreePagesMock(EFI_PHYSICAL_ADDRESS a, UINTN n)
{
  if (!ArenaBusy || a != mSource || n != 33) abort();
  ArenaBusy = FALSE;
  Frees++;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI SendMock(CONST EFI_MM_COMMUNICATION2_PROTOCOL *p, VOID *physical, VOID *virtual, UINTN *size)
{
  EFI_MM_COMMUNICATE_HEADER *h = virtual;
  COREBOOT_CAPSULE_HEADER *r = (VOID *)h->Data;
  (void)p; (void)physical;
  if (Mode == 1) return EFI_DEVICE_ERROR;
  if (Mode == 2) { h->HeaderGuid.Data1++; return EFI_SUCCESS; }
  if (Mode == 3) { h->MessageLength++; return EFI_SUCCESS; }
  if (Mode == 4) { *size = 0; return EFI_SUCCESS; }
  switch (r->Command) {
    case COREBOOT_CAPSULE_INFO: {
      COREBOOT_CAPSULE_GEOMETRY *g = (VOID *)r;
      g->FlashSize = 2 * 65536;
      g->BlockSize = Mode == 5 ? 0 : 65536;
      return EFI_SUCCESS;
    }
    case COREBOOT_CAPSULE_BEGIN: {
      COREBOOT_CAPSULE_START *b = (VOID *)r;
      UINT64 Count;
      memcpy(&Count, (UINT8 *)(UINTN)b->Address + b->SignedSize - 8, 8);
      if (b->ImageOffset != 16 || b->SignatureSize != 1 || b->Signature[0] != 0xa5 || Count != 9)
        abort();
      if (OwnerActive) abort();
      if (Fault == BeginRejected) {
        b->Header.Result = BIT31 | 26;
      } else {
        OwnerActive = TRUE;
        b->Header.Transaction = 7;
        if (Fault == BeginShortError || Fault == BeginErrorToken) {
          b->Header.Result = BIT31 | 26;
          if (Fault == BeginShortError) b->Header.Transaction = 0;
        }
        if (Fault == BeginWrongSource) b->Address++;
      }
      h->MessageLength = Fault == BeginShort || Fault == BeginShortError ? sizeof(*r) : sizeof(*b);
      *size = OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data) + h->MessageLength;
      return Fault == BeginLost ? EFI_DEVICE_ERROR : EFI_SUCCESS;
    }
    case COREBOOT_CAPSULE_PROGRAM: {
      COREBOOT_CAPSULE_BLOCK *b = (VOID *)r;
      if (r->Transaction != 7) {
        r->Result = BIT31 | 15;
        return EFI_SUCCESS;
      }
      Programs++;
      r->Result = b->Block == 0 ?
        (UINT32)ProgramStatus | (EFI_ERROR(ProgramStatus) ? BIT31 : 0) : 0;
      if (r->Result & BIT31) OwnerActive = FALSE;
      return EFI_SUCCESS;
    }
    case COREBOOT_CAPSULE_CLOSE:
      Closes++;
      if (Fault == CloseDenied) return EFI_ACCESS_DENIED;
      r->Result = OwnerActive ? 0 : BIT31 | 15;
      OwnerActive = FALSE;
      if (Fault == CloseWrongToken) r->Transaction++;
      return Fault == CloseLost ? EFI_DEVICE_ERROR : EFI_SUCCESS;
    default: return EFI_UNSUPPORTED;
  }
}
static EFI_STATUS EFIAPI Locate(EFI_GUID *g, VOID *r, VOID **p)
{ (void)g; (void)r; *p = &Communication; return EFI_SUCCESS; }
static EFI_STATUS EFIAPI Cancel(UINTN Percentage)
{ (void)Percentage; return EFI_ABORTED; }
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "client %u: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
  UINT32 Flash, Block;
  UINTN Size = sizeof(UINT64) + OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData) + 1 + 16 + 2 * 65536;
  EFI_FIRMWARE_IMAGE_AUTHENTICATION *Image = calloc(1, Size);
  UINT8 *Payload;
  CHECK(Image);
  Communication.Communicate = SendMock;
  Services.LocateProtocol = Locate;
  Services.AllocatePages = Pages;
  Services.FreePages = FreePagesMock;
  Services.GetMemoryMap = GetMap;
  for (Mode = 1; Mode <= 5; Mode++) {
    CHECK(EFI_ERROR(CorebootCapsuleGeometry(&Flash, &Block)) && !mFlashSize);
  }
  Mode = 0;
  CHECK(CorebootCapsuleGeometry(&Flash, &Block) == EFI_SUCCESS && Flash == 131072 && Block == 65536);
  CHECK(CorebootCapsuleApply(NULL) == EFI_ACCESS_DENIED);
  CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SECURITY_VIOLATION);
  Image->MonotonicCount = 9;
  Image->AuthInfo.Hdr.dwLength = OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData) + 1;
  Image->AuthInfo.Hdr.wRevision = 0x0200;
  Image->AuthInfo.Hdr.wCertificateType = WIN_CERT_TYPE_EFI_GUID;
  Image->AuthInfo.CertType = gEfiCertPkcs7Guid;
  Image->AuthInfo.CertData[0] = 0xa5;
  Payload = (UINT8 *)Image + sizeof(UINT64) + Image->AuthInfo.Hdr.dwLength;
  Payload[0] = 'M'; Payload[1] = 'S'; Payload[2] = 'S'; Payload[3] = '1';
  Payload[4] = 16;
  CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS && mTransaction == 7 && mSourcePages);
  CHECK((VOID *)(UINTN)mSource != Payload && !memcmp((VOID *)(UINTN)mSource, Payload, 16 + 131072));
  CHECK(CorebootCapsuleApply(NULL) == EFI_SUCCESS && Programs == 2 && Closes == 1 && Frees == 1 && !mTransaction && !mSourcePages);
  CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
  ProgramStatus = EFI_SECURITY_VIOLATION;
  CHECK(CorebootCapsuleApply(NULL) == EFI_SECURITY_VIOLATION && Programs == 3 && Frees == 2);
  CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
  ProgramStatus = EFI_SUCCESS;
  CHECK(CorebootCapsuleApply(Cancel) == EFI_SUCCESS && Programs == 5 && Frees == 3);
  CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
  ProgramStatus = EFI_NOT_FOUND;
  CHECK(CorebootCapsuleApply(NULL) == EFI_NOT_FOUND && Programs == 6 && Frees == 4);
  CHECK(!Pools && !ArenaBusy);
  for (MapMode = 1; MapMode <= 8; MapMode++) {
    MapCalls = Allocations = 0;
    if (MapMode <= 2 || MapMode == 8) {
      CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
      CHECK(mSource == (UINTN)Arena + (MapMode == 8 ? 64 * EFI_PAGE_SIZE : 0) && mSourcePages == 33 && ArenaBusy);
      CHECK(MapCalls == (MapMode == 8 ? 6 : 4) &&
            Allocations == (MapMode == 8 ? 3 : MapMode == 2 ? 2 : 1));
      CorebootCapsuleClose();
    } else {
      CHECK(EFI_ERROR(CorebootCapsuleAuthenticate(Image, Size)));
      CHECK(Allocations == (MapMode == 5 ? 4 : 0));
      CHECK(MapCalls == (MapMode == 4 || MapMode == 5 ? 16 : 2));
      CHECK(!mSourcePages && !mTransaction);
    }
    CHECK(!Pools && !ArenaBusy);
  }
  {
    EFI_MEMORY_DESCRIPTOR Map[4] = {{0}};
    EFI_PHYSICAL_ADDRESS Address;
    Map[0].Type = EfiConventionalMemory;
    Map[0].PhysicalStart = BASE_4GB - EFI_PAGE_SIZE;
    Map[0].NumberOfPages = 2;
    Map[1].Type = EfiReservedMemoryType;
    Map[1].PhysicalStart = 2 * SIZE_1MB;
    Map[1].NumberOfPages = 64;
    Map[2].Type = EfiConventionalMemory;
    Map[2].PhysicalStart = SIZE_1MB - EFI_PAGE_SIZE;
    Map[2].NumberOfPages = 34;
    CHECK(FindSourceAddress(Map, sizeof(Map), sizeof(Map[0]), 33, SIZE_1MB, &Address) == EFI_SUCCESS);
    CHECK(Address == SIZE_1MB);
    Map[3].Type = EfiConventionalMemory;
    Map[3].PhysicalStart = MAX_UINT64 - EFI_PAGE_SIZE + 1;
    Map[3].NumberOfPages = 1;
    CHECK(FindSourceAddress(Map, sizeof(Map), sizeof(Map[0]), 33, SIZE_1MB, &Address) == EFI_SUCCESS);
    CHECK(Address == SIZE_1MB);
    Map[2].NumberOfPages = 33;
    CHECK(FindSourceAddress(Map, sizeof(Map), sizeof(Map[0]), 33, SIZE_1MB, &Address) == EFI_OUT_OF_RESOURCES);
    Map[2].PhysicalStart = MAX_UINT64 - EFI_PAGE_SIZE + 1;
    Map[2].NumberOfPages = 2;
    CHECK(FindSourceAddress(Map, sizeof(Map), sizeof(Map[0]), 33, SIZE_1MB, &Address) == EFI_DEVICE_ERROR);
    Map[2].PhysicalStart = SIZE_1MB + 1;
    Map[2].NumberOfPages = 64;
    CHECK(FindSourceAddress(Map, sizeof(Map), sizeof(Map[0]), 33, SIZE_1MB, &Address) == EFI_DEVICE_ERROR);
    CHECK(FindSourceAddress(Map, sizeof(Map) - 1, sizeof(Map[0]), 33, SIZE_1MB, &Address) == EFI_INVALID_PARAMETER);
    CHECK(FindSourceAddress(Map, sizeof(Map), sizeof(Map[0]) - 1, 33, SIZE_1MB, &Address) == EFI_INVALID_PARAMETER);
    CHECK(FindSourceAddress(Map, sizeof(Map), sizeof(Map[0]), 0, SIZE_1MB, &Address) == EFI_INVALID_PARAMETER);
  }
  MapMode = 0;
  ProgramStatus = EFI_SUCCESS;
  {
    unsigned before, allocated;
    CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
    before = Frees;
    FailZeroAt = ZeroCount + 1;
    CorebootCapsuleClose();
    CHECK(OwnerActive && ArenaBusy && mClosing && mTransaction == 7 && Frees == before);
    CHECK(CorebootCapsuleApply(NULL) == EFI_ACCESS_DENIED);
    allocated = Allocations;
    FailZeroAt = ZeroCount + 1;
    CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_NOT_READY && Allocations == allocated);
    FailZeroAt = 0;
    CorebootCapsuleClose();
    CorebootCapsuleClose();
    CHECK(!OwnerActive && !ArenaBusy && Frees == before + 1);

    CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
    before = Frees;
    Fault = CloseDenied;
    CorebootCapsuleClose();
    CHECK(OwnerActive && ArenaBusy && mClosing && Frees == before);
    CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_NOT_READY);
    Fault = NoFault;
    CorebootCapsuleClose();
    CHECK(!ArenaBusy && Frees == before + 1);

    for (unsigned fault = CloseLost; fault <= CloseWrongToken; fault++) {
      CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
      before = Frees;
      Fault = fault;
      CorebootCapsuleClose();
      CHECK(!OwnerActive && ArenaBusy && mClosing && Frees == before);
      CHECK(CorebootCapsuleApply(NULL) == EFI_ACCESS_DENIED);
      Fault = NoFault;
      CorebootCapsuleClose();
      CorebootCapsuleClose();
      CHECK(!ArenaBusy && !mTransaction && Frees == before + 1);
    }
    CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SUCCESS);
    before = Frees;
    Fault = CloseLost;
    CHECK(CorebootCapsuleApply(NULL) == EFI_DEVICE_ERROR && ArenaBusy && !OwnerActive);
    Fault = NoFault;
    CorebootCapsuleClose();
    CHECK(Frees == before + 1);

    /* Both request and transport-packet allocation failures precede BEGIN. */
    for (unsigned allocation = 1; allocation <= 2; allocation++) {
      before = Frees;
      FailZeroAt = ZeroCount + allocation;
      CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_OUT_OF_RESOURCES);
      CHECK(!OwnerActive && !ArenaBusy && !mSourcePages && Frees == before + 1);
      FailZeroAt = 0;
    }
    Fault = BeginRejected;
    before = Frees;
    CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_SECURITY_VIOLATION);
    CHECK(!OwnerActive && !ArenaBusy && Frees == before + 1);
    Fault = NoFault;

    for (unsigned fault = BeginLost; fault <= BeginWrongSource; fault++) {
      before = Frees;
      Fault = fault;
      CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_DEVICE_ERROR);
      CHECK(OwnerActive && ArenaBusy && !mTransaction && mClosing && Frees == before);
      allocated = Allocations;
      CHECK(CorebootCapsuleAuthenticate(Image, Size) == EFI_NOT_READY && Allocations == allocated);
      CHECK(CorebootCapsuleApply(NULL) == EFI_ACCESS_DENIED);
      CorebootCapsuleClose();
      CHECK(OwnerActive && ArenaBusy && Frees == before);
      /* Model the owner's confirmed ExitBootServices shutdown. */
      OwnerActive = FALSE;
      ReleaseSource();
      CHECK(!ArenaBusy && !mSourcePages && Frees == before + 1);
      Fault = NoFault;
    }
    CHECK(!Pools);
  }
  free(Image);
  puts("Capsule client: framing, lifetime, block iteration, low RAM selection, allocation races and uncertain-delivery lifetime passed");
  return 0;
}
