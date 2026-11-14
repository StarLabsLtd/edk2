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
VOID *EFIAPI CopyMem(VOID *d, CONST VOID *s, UINTN n) { return memcpy(d, s, n); }
VOID *EFIAPI ZeroMem(VOID *d, UINTN n) { return memset(d, 0, n); }
BOOLEAN EFIAPI CompareGuid(CONST GUID *a, CONST GUID *b) { return !memcmp(a, b, sizeof(*a)); }
UINT32 EFIAPI ReadUnaligned32(CONST VOID *p) { UINT32 v; memcpy(&v, p, sizeof(v)); return v; }
VOID *EFIAPI AllocateZeroPool(UINTN n) { return calloc(1, n); }
VOID *EFIAPI AllocatePool(UINTN n) { return malloc(n); }
VOID EFIAPI FreePool(VOID *p) { free(p); }
static EFI_STATUS EFIAPI Pages(EFI_ALLOCATE_TYPE t, EFI_MEMORY_TYPE m, UINTN n, EFI_PHYSICAL_ADDRESS *a)
{ (void)t; (void)m; *a = (UINTN)malloc(EFI_PAGES_TO_SIZE(n)); return *a ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES; }
static EFI_STATUS EFIAPI FreePagesMock(EFI_PHYSICAL_ADDRESS a, UINTN n)
{ (void)n; free((VOID *)(UINTN)a); Frees++; return EFI_SUCCESS; }
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
      b->Header.Transaction = 7;
      h->MessageLength = sizeof(*b);
      *size = OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data) + sizeof(*b);
      return EFI_SUCCESS;
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
      return EFI_SUCCESS;
    }
    case COREBOOT_CAPSULE_CLOSE:
      Closes++;
      return EFI_SUCCESS;
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
  free(Image);
  puts("Capsule client: response framing, staged lifetime, block iteration, progress failure and errors passed");
  return 0;
}
