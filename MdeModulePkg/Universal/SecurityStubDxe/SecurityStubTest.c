/** @file
  Exercise production external-image measurement admission with protocol mocks.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#undef NULL
static int Required;
#define _PCD_VALUE_PcdTpm2MeasurementRequired Required
#include "SecurityStub.c"

static BOOLEAN Resident, Present;
static EFI_STATUS LocateStatus, CapabilityStatus, HandlerStatus;
static UINT32 Banks;
static unsigned Handlers;
static EFI_BOOT_SERVICES Services;
EFI_BOOT_SERVICES *gBS = &Services;
EFI_GUID gEfiTcg2ProtocolGuid;

BOOLEAN FileFromFv(CONST EFI_DEVICE_PATH_PROTOCOL *File) { return Resident; }
EFI_STATUS Defer3rdPartyImageLoad(CONST EFI_DEVICE_PATH_PROTOCOL *File, BOOLEAN Policy)
{ return EFI_SUCCESS; }
EFI_STATUS EFIAPI ExecuteSecurity2Handlers(UINT32 Operation, UINT32 Authentication,
  CONST EFI_DEVICE_PATH_PROTOCOL *File, VOID *Buffer, UINTN Size, BOOLEAN Policy)
{ Handlers++; return HandlerStatus; }
static EFI_STATUS EFIAPI Capability(EFI_TCG2_PROTOCOL *This,
  EFI_TCG2_BOOT_SERVICE_CAPABILITY *Result)
{
  Result->TPMPresentFlag = Present;
  Result->ActivePcrBanks = Banks;
  return CapabilityStatus;
}
static EFI_TCG2_PROTOCOL Tcg2 = { .GetCapability = Capability };
static EFI_STATUS EFIAPI Locate(EFI_GUID *Guid, VOID *Registration, VOID **Protocol)
{ *Protocol = &Tcg2; return LocateStatus; }
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "admission %u: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void)
{
  EFI_DEVICE_PATH_PROTOCOL File = { 0 };
  UINT8 Image = 0;
  Services.LocateProtocol = Locate;
  Required = TRUE;
  LocateStatus = EFI_NOT_FOUND;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SECURITY_VIOLATION && !Handlers);
  CHECK(Security2StubAuthenticate(NULL, NULL, &Image, 1, TRUE) == EFI_SECURITY_VIOLATION && !Handlers);
  Resident = TRUE;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SUCCESS && Handlers == 1);
  Resident = FALSE;
  LocateStatus = EFI_SUCCESS;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SECURITY_VIOLATION && Handlers == 1);
  Present = TRUE;
  Banks = EFI_TCG2_BOOT_HASH_ALG_SHA1;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SECURITY_VIOLATION && Handlers == 1);
  Banks = EFI_TCG2_BOOT_HASH_ALG_SHA256;
  CapabilityStatus = EFI_DEVICE_ERROR;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SECURITY_VIOLATION && Handlers == 1);
  CapabilityStatus = EFI_SUCCESS;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SUCCESS && Handlers == 2);
  HandlerStatus = EFI_SECURITY_VIOLATION;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SECURITY_VIOLATION && Handlers == 3);
  Required = FALSE;
  LocateStatus = EFI_NOT_FOUND;
  HandlerStatus = EFI_SUCCESS;
  CHECK(Security2StubAuthenticate(NULL, &File, &Image, 1, TRUE) == EFI_SUCCESS && Handlers == 4);
  puts("Production image admission: strict external, resident bootstrap and default policy passed");
  return 0;
}
