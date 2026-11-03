/** @file
  Host checks for the production pre-execution policy.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "CorebootImagePolicyLib.c"

EFI_GUID gEfiFirmwareVolume2ProtocolGuid = {.Data1 = 1};
EFI_GUID gEfiMmCommunication2ProtocolGuid = {.Data1 = 2};
EFI_GUID gEfiEventReadyToBootGuid = {.Data1 = 3};
static EFI_BOOT_SERVICES Services;
EFI_BOOT_SERVICES *gBS = &Services;
static EFI_FIRMWARE_VOLUME2_PROTOCOL Volume;
static EFI_MM_COMMUNICATION2_PROTOCOL Communication;
static unsigned Calls, Reads, Frees;
static EFI_STATUS FindStatus, SendStatus, ReadStatus;
static BOOLEAN TeOnly;
static unsigned char Firmware[] = {1, 2, 3, 4};
static struct {
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH File;
  EFI_DEVICE_PATH_PROTOCOL End;
} Path = {
  .File = {.Header = {MEDIA_DEVICE_PATH, MEDIA_PIWG_FW_FILE_DP, {sizeof (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH), 0}}},
  .End = {END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {4, 0}}
};

VOID *EFIAPI CopyMem (VOID *D, CONST VOID *S, UINTN N) {return memcpy (D, S, N);}
VOID *EFIAPI ZeroMem (VOID *D, UINTN N) {return memset (D, 0, N);}
INTN EFIAPI CompareMem (CONST VOID *A, CONST VOID *B, UINTN N) {return memcmp (A, B, N);}
BOOLEAN EFIAPI CompareGuid (CONST EFI_GUID *A, CONST EFI_GUID *B) {return memcmp (A, B, sizeof (*A)) == 0;}
VOID EFIAPI FreePool (VOID *P) {Frees++; free (P);}
RETURN_STATUS EFIAPI RegisterSecurity2Handler (IN SECURITY2_FILE_AUTHENTICATION_HANDLER Handler, IN UINT32 Operation) {return (Handler == AuthorizeImage && Operation == (EFI_AUTH_OPERATION_VERIFY_IMAGE | EFI_AUTH_OPERATION_IMAGE_REQUIRED)) ? RETURN_SUCCESS : RETURN_INVALID_PARAMETER;}
static EFI_STATUS EFIAPI LocatePath (EFI_GUID *G, EFI_DEVICE_PATH_PROTOCOL **P, EFI_HANDLE *H) {*H = &Volume; return EFI_SUCCESS;}
static EFI_STATUS EFIAPI Handle (EFI_HANDLE H, EFI_GUID *G, VOID **P) {*P = &Volume; return EFI_SUCCESS;}
static EFI_STATUS EFIAPI Locate (EFI_GUID *G, VOID *R, VOID **P) {*P = &Communication; return FindStatus;}
static EFI_STATUS EFIAPI Section (CONST EFI_FIRMWARE_VOLUME2_PROTOCOL *V, CONST EFI_GUID *N, EFI_SECTION_TYPE Type, UINTN Instance, VOID **P, UINTN *Size, UINT32 *Auth) {
  Reads++;
  if (TeOnly && Type == EFI_SECTION_PE32) return EFI_NOT_FOUND;
  if (EFI_ERROR (ReadStatus)) return ReadStatus;
  *Size = sizeof (Firmware); *P = malloc (*Size); memcpy (*P, Firmware, *Size); *Auth = 0; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Send (CONST EFI_MM_COMMUNICATION2_PROTOCOL *This, VOID *Physical, VOID *Virtual, UINTN *Size) {
  EFI_MM_COMMUNICATE_HEADER *H = Virtual;
  if (Physical != Virtual || *Size != OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + 1 || H->MessageLength != 1 || !CompareGuid (&H->HeaderGuid, &gEfiEventReadyToBootGuid)) abort ();
  Calls++; return SendStatus;
}
#define CHECK(X) do { if (!(X)) {fprintf (stderr, "failed line %u: %s\n", __LINE__, #X); return 1;} } while (0)
int main (void) {
  unsigned char Changed[] = {1, 2, 3, 5};
  Services.LocateDevicePath = LocatePath; Services.HandleProtocol = Handle; Services.LocateProtocol = Locate;
  Volume.ReadSection = Section; Communication.Communicate = Send;
  CHECK (CorebootImagePolicyConstructor (NULL, NULL) == EFI_SUCCESS);
  CHECK (AuthorizeImage (0, (VOID *)&Path, Firmware, sizeof (Firmware), FALSE) == EFI_SUCCESS && Calls == 0 && !mClosed);
  CHECK (Reads == 1 && Frees == 1);
  TeOnly = TRUE;
  CHECK (FirmwareImage ((VOID *)&Path, Firmware, sizeof (Firmware)));
  CHECK (Reads == 3 && Frees == 2);
  TeOnly = FALSE;
  Path.File.Header.Length[0]--;
  CHECK (!FirmwareImage ((VOID *)&Path, Firmware, sizeof (Firmware)));
  Path.File.Header.Length[0]++;
  CHECK (!FirmwareImage ((VOID *)&Path, Firmware, sizeof (Firmware) - 1));
  FindStatus = EFI_NOT_FOUND;
  CHECK (AuthorizeImage (0, (VOID *)&Path, Changed, sizeof (Changed), FALSE) == EFI_ACCESS_DENIED && !mClosed && Calls == 0);
  FindStatus = EFI_SUCCESS; SendStatus = EFI_OUT_OF_RESOURCES;
  CHECK (AuthorizeImage (0, NULL, Changed, sizeof (Changed), FALSE) == EFI_ACCESS_DENIED && !mClosed && Calls == 1);
  SendStatus = EFI_SUCCESS;
  CHECK (AuthorizeImage (0, (VOID *)&Path, Changed, sizeof (Changed), FALSE) == EFI_SUCCESS && mClosed && Calls == 2);
  CHECK (AuthorizeImage (0, NULL, Changed, sizeof (Changed), FALSE) == EFI_SUCCESS && Calls == 2);
  mClosed = FALSE; ReadStatus = EFI_DEVICE_ERROR;
  CHECK (AuthorizeImage (0, (VOID *)&Path, Firmware, sizeof (Firmware), FALSE) == EFI_SUCCESS && mClosed && Calls == 3);
  puts ("Image policy: firmware byte comparison, refusal, retry and one-way closure passed"); return 0;
}
UINT8 EFIAPI DevicePathType (CONST VOID *P) {return ((CONST EFI_DEVICE_PATH_PROTOCOL *)P)->Type;}
UINT8 EFIAPI DevicePathSubType (CONST VOID *P) {return ((CONST EFI_DEVICE_PATH_PROTOCOL *)P)->SubType;}
UINTN EFIAPI DevicePathNodeLength (CONST VOID *P) {CONST EFI_DEVICE_PATH_PROTOCOL *N=P;return N->Length[0] | ((UINTN)N->Length[1] << 8);}
EFI_DEVICE_PATH_PROTOCOL *EFIAPI NextDevicePathNode (CONST VOID *P) {return (VOID *)((CONST UINT8 *)P + DevicePathNodeLength(P));}
BOOLEAN EFIAPI IsDevicePathEnd (CONST VOID *P) {return DevicePathType(P)==END_DEVICE_PATH_TYPE && DevicePathSubType(P)==END_ENTIRE_DEVICE_PATH_SUBTYPE;}
GUID *EFIAPI CopyGuid (GUID *D, CONST GUID *S) {return memcpy(D,S,sizeof(*D));}
