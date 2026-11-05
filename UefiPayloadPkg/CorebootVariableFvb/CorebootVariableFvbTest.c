/** @file
  Host checks for the production MM firmware-volume adapter.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "CorebootVariableFvb.c"

VOID *EFIAPI CopyMem (VOID *Destination, CONST VOID *Source, UINTN Length)
{
  return memcpy (Destination, Source, Length);
}

VOID EFIAPI CpuDeadLoop (VOID)
{
  abort ();
}

INTN EFIAPI CompareMem (CONST VOID *First, CONST VOID *Second, UINTN Length)
{
  return memcmp (First, Second, Length);
}

static unsigned char Flash[256];
static unsigned char Staging[64];
static unsigned int Erases;
static unsigned int ReadCalls;
static unsigned int ReadBytes;
static unsigned int FailReadAt;
static unsigned int ReadyInstalls;
static int Fail;
static int FailValidation;
static int FailInstall;
static int FailFvbInstall;
static int FailNotify;
static unsigned int FvbInstalls;
static unsigned int ValidationInstalls;
static unsigned int ValidationUninstalls;
static unsigned int NotifyRegistrations;
static unsigned int NotifyUnregistrations;
static EFI_MM_SYSTEM_TABLE Mmst;
EFI_MM_SYSTEM_TABLE *gMmst = &Mmst;
EFI_GUID gCorebootVariableStoreReadyGuid = { 0x254972cc, 0xabdc, 0x4494,
                                            { 0x96, 0x16, 0x68, 0xac, 0x16, 0xa5, 0x33, 0xbd } };
EFI_GUID gCorebootVariableServiceInfoGuid = { 1 };
EFI_GUID gCorebootVariableStoreInfoGuid = { 2 };
EFI_GUID gVariableFlashInfoHobGuid = { 3 };
EFI_GUID gEdkiiFtwStoreValidationProtocolGuid = { 4 };
EFI_GUID gEfiSmmFirmwareVolumeBlockProtocolGuid = { 5 };
EFI_GUID gEfiSmmFaultTolerantWriteProtocolGuid = { 6 };

static struct {
  EFI_HOB_GUID_TYPE Header;
  COREBOOT_VARIABLE_SERVICE_INFO Data;
} ServiceHob;
static struct {
  EFI_HOB_GUID_TYPE Header;
  COREBOOT_VARIABLE_STORE_INFO Data;
} StoreHob;
static struct {
  EFI_HOB_GUID_TYPE Header;
  VARIABLE_FLASH_INFO Data;
} FlashHob;
static VARIABLE_FLASH_INFO ExpectedInfo;

VOID *EFIAPI GetFirstGuidHob (CONST EFI_GUID *Guid)
{
  if (memcmp (Guid, &gCorebootVariableServiceInfoGuid, sizeof (*Guid)) == 0) {
    return &ServiceHob.Header;
  }

  if (memcmp (Guid, &gCorebootVariableStoreInfoGuid, sizeof (*Guid)) == 0) {
    return &StoreHob.Header;
  }

  if (memcmp (Guid, &gVariableFlashInfoHobGuid, sizeof (*Guid)) == 0) {
    return &FlashHob.Header;
  }

  return NULL;
}

EFI_STATUS EFIAPI SmmStoreGetFlashInfo (
  EFI_PHYSICAL_ADDRESS Base, UINTN BlockSize, UINTN BlockCount, VARIABLE_FLASH_INFO *Info
  )
{
  if ((Base != StoreHob.Data.StoreBase) || (BlockSize != 64) || (BlockCount != 4)) {
    return EFI_INVALID_PARAMETER;
  }

  *Info = ExpectedInfo;
  return EFI_SUCCESS;
}

static UINT32 EFIAPI ReadOp (UINT32 Offset, UINT32 Size)
{
  ReadCalls++;
  ReadBytes += Size;
  if (Fail || ((FailReadAt != 0) && (ReadCalls == FailReadAt))) {
    return 1;
  }

  memcpy (Staging, Flash + Offset, Size);
  return 0;
}

static UINT32 EFIAPI WriteOp (UINT32 Offset, UINT32 Size)
{
  UINT32 Index;

  if (Fail) {
    return 1;
  }

  // SPI NOR programming clears bits; it cannot set them without an erase.
  for (Index = 0; Index < Size; Index++) {
    Flash[Offset + Index] &= Staging[Index];
  }
  return 0;
}

static UINT32 EFIAPI EraseOp (UINT32 Offset, UINT32 Size)
{
  if (Fail) {
    return 1;
  }

  Erases++;
  memset (Flash + Offset, 0xff, Size);
  return 0;
}

static UINT32 EFIAPI ValidateOp (VOID)
{
  return (UINT32)FailValidation;
}

static EFI_STATUS EFIAPI InstallProtocol (
  EFI_HANDLE *Handle, EFI_GUID *Protocol, EFI_INTERFACE_TYPE Type, VOID *Interface
  )
{
  (void)Handle;
  (void)Protocol;
  (void)Type;
  (void)Interface;
  if (memcmp (Protocol, &gEdkiiFtwStoreValidationProtocolGuid, sizeof (*Protocol)) == 0) {
    ValidationInstalls++;
    *Handle = (EFI_HANDLE)(UINTN)1;
    return EFI_SUCCESS;
  }

  if (memcmp (Protocol, &gEfiSmmFirmwareVolumeBlockProtocolGuid, sizeof (*Protocol)) == 0) {
    if (FailFvbInstall) {
      return EFI_DEVICE_ERROR;
    }

    FvbInstalls++;
    return EFI_SUCCESS;
  }

  if (FailInstall) {
    return EFI_DEVICE_ERROR;
  }

  ReadyInstalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI UninstallProtocol (EFI_HANDLE Handle, EFI_GUID *Protocol, VOID *Interface)
{
  (void)Handle;
  (void)Protocol;
  (void)Interface;
  ValidationUninstalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI RegisterNotify (
  CONST EFI_GUID *Protocol, EFI_MM_NOTIFY_FN Function, VOID **Registration
  )
{
  (void)Protocol;
  if (Function == NULL) {
    NotifyUnregistrations++;
  } else {
    if (FailNotify) {
      return EFI_OUT_OF_RESOURCES;
    }
    NotifyRegistrations++;
    *Registration = (VOID *)(UINTN)1;
  }

  return EFI_SUCCESS;
}

#define CHECK(Expression) do { \
  if (!(Expression)) { \
    fprintf (stderr, "failed: %s at line %d\n", #Expression, __LINE__); \
    return 1; \
  } \
} while (0)

int main (void)
{
  COREBOOT_VARIABLE_SERVICE_INFO Info = {0};
  unsigned char Out[8];
  UINTN Size;
  UINTN BlockSize;
  UINTN Blocks;
  EFI_FVB_ATTRIBUTES_2 Attributes;
  EFI_PHYSICAL_ADDRESS Address;
  VARIABLE_FLASH_INFO FlashInfo = {0};
  BOOLEAN Erased;

  memset (Flash, 0x33, sizeof (Flash));
  Info.StoreBuffer = (UINT32)(UINTN)Staging;
  Info.StoreBufferSize = sizeof (Staging);
  Info.StoreRead = (UINT32)(UINTN)ReadOp;
  Info.StoreWrite = (UINT32)(UINTN)WriteOp;
  Info.StoreErase = (UINT32)(UINTN)EraseOp;
  Info.StoreValidate = (UINT32)(UINTN)ValidateOp;
  Info.Revision = COREBOOT_VARIABLE_SERVICE_INFO_REVISION;
  Info.Size = sizeof (Info);
  mService = &Info;
  mStore.StoreSize = sizeof (Flash);
  mStore.BlockSize = sizeof (Staging);
  Mmst.MmInstallProtocolInterface = InstallProtocol;
  Mmst.MmUninstallProtocolInterface = UninstallProtocol;
  Mmst.MmRegisterProtocolNotify = RegisterNotify;

  ServiceHob.Header.Header.HobLength = sizeof (ServiceHob);
  ServiceHob.Data = Info;
  StoreHob.Header.Header.HobLength = sizeof (StoreHob);
  StoreHob.Data.Revision = COREBOOT_VARIABLE_STORE_INFO_REVISION;
  StoreHob.Data.StoreBase = 0x10000;
  StoreHob.Data.StoreSize = sizeof (Flash);
  StoreHob.Data.BlockSize = sizeof (Staging);
  FlashHob.Header.Header.HobLength = sizeof (FlashHob);
  ExpectedInfo.FtwWorkingBaseAddress = 0x10040;
  ExpectedInfo.FtwSpareBaseAddress = 0x10080;
  ExpectedInfo.FtwSpareLength = 128;
  FlashHob.Data = ExpectedInfo;

  ServiceHob.Data.Revision = 0;
  CHECK (CorebootVariableFvbEntryPoint (NULL, NULL) == EFI_INVALID_PARAMETER);
  CHECK (ValidationInstalls == 0 && FvbInstalls == 0);
  ServiceHob.Data.Revision = COREBOOT_VARIABLE_SERVICE_INFO_REVISION;
  FailFvbInstall = 1;
  CHECK (CorebootVariableFvbEntryPoint (NULL, NULL) == EFI_DEVICE_ERROR);
  CHECK (ValidationUninstalls == 1 && NotifyUnregistrations == 1);
  FailFvbInstall = 0;
  FailNotify = 1;
  CHECK (CorebootVariableFvbEntryPoint (NULL, NULL) == EFI_OUT_OF_RESOURCES);
  CHECK (ValidationInstalls == 2 && ValidationUninstalls == 2 && FvbInstalls == 0);
  FailNotify = 0;
  CHECK (CorebootVariableFvbEntryPoint (NULL, NULL) == EFI_SUCCESS);
  CHECK (ValidationInstalls == 3 && NotifyRegistrations == 2 && FvbInstalls == 1);
  mService = &Info;

  // A non-erased prefix avoids a full-block read.
  memset (Flash + 64, 0xff, 64);
  Flash[64] = 0;
  ReadCalls = ReadBytes = 0;
  CHECK (WorkspaceErased (64, &Erased) == EFI_SUCCESS && !Erased);
  CHECK (ReadCalls == 1 && ReadBytes == 1);

  // An erased prefix still requires checking the rest of the workspace.
  Flash[64] = 0xff;
  Flash[127] = 0;
  ReadCalls = ReadBytes = 0;
  CHECK (WorkspaceErased (64, &Erased) == EFI_SUCCESS && !Erased);
  CHECK (ReadCalls == 2 && ReadBytes == 65);
  Flash[127] = 0xff;
  ReadCalls = ReadBytes = 0;
  CHECK (WorkspaceErased (64, &Erased) == EFI_SUCCESS && Erased);
  CHECK (ReadCalls == 2 && ReadBytes == 65);

  ReadCalls = 0;
  FailReadAt = 2;
  CHECK (WorkspaceErased (64, &Erased) == EFI_DEVICE_ERROR);
  FailReadAt = 0;
  memset (Flash + 64, 0x33, 64);

  mStore.StoreBase = 0x10000;
  FlashInfo.FtwWorkingBaseAddress = mStore.StoreBase + 64;
  FlashInfo.FtwSpareBaseAddress = mStore.StoreBase + 128;
  FlashInfo.FtwSpareLength = 128;
  CHECK (CheckBeforeRecovery (&FlashInfo) == EFI_SUCCESS);
  FailValidation = COREBOOT_VARIABLE_STORE_IO_ERROR;
  CHECK (CheckBeforeRecovery (&FlashInfo) == EFI_DEVICE_ERROR);
  FailValidation = COREBOOT_VARIABLE_STORE_INVALID;
  memset (Flash + 64, 0xff, 128);
  CHECK (CheckBeforeRecovery (&FlashInfo) == EFI_VOLUME_CORRUPTED);
  FailValidation = 0;
  CHECK (CheckBeforeRecovery (&FlashInfo) == EFI_VOLUME_CORRUPTED);
  memset (Flash + 192, 0xff, 64);
  CHECK (CheckBeforeRecovery (&FlashInfo) == EFI_SUCCESS);
  FailValidation = COREBOOT_VARIABLE_STORE_INVALID;
  Flash[64] = 0;
  CHECK (CheckBeforeRecovery (&FlashInfo) == EFI_SUCCESS);
  Fail = 1;
  CHECK (CheckBeforeRecovery (&FlashInfo) == EFI_DEVICE_ERROR);
  Fail = 0;
  FailValidation = 0;
  memset (Flash, 0x33, sizeof (Flash));

  CHECK (StoreGetAttributes (NULL, &Attributes) == EFI_SUCCESS);
  CHECK ((Attributes & (EFI_FVB2_READ_STATUS | EFI_FVB2_WRITE_STATUS)) ==
         (EFI_FVB2_READ_STATUS | EFI_FVB2_WRITE_STATUS));
  CHECK (StoreSetAttributes (NULL, &Attributes) == EFI_SUCCESS);
  Attributes = 0;
  CHECK (StoreSetAttributes (NULL, &Attributes) == EFI_INVALID_PARAMETER);
  CHECK (StoreGetAddress (NULL, &Address) == EFI_SUCCESS && Address == mStore.StoreBase);
  CHECK (StoreGetBlockSize (NULL, 1, &BlockSize, &Blocks) == EFI_SUCCESS);
  CHECK (BlockSize == 64 && Blocks == 3);
  CHECK (StoreGetBlockSize (NULL, 4, &BlockSize, &Blocks) == EFI_INVALID_PARAMETER);
  Size = sizeof (Out);
  CHECK (Transfer (FALSE, 0, 1, &Size, Out) == EFI_SUCCESS);
  CHECK (Size == sizeof (Out) && Out[0] == 0x33);
  Size = sizeof (Out);
  CHECK (Transfer (FALSE, 0, 63, &Size, Out) == EFI_BAD_BUFFER_SIZE && Size == 1);
  Flash[67] = 0xff;
  Out[0] = 0x42;
  Size = 1;
  CHECK (Transfer (TRUE, 1, 3, &Size, Out) == EFI_SUCCESS && Flash[67] == 0x42);
  Out[0] = 0xff;
  Size = 1;
  CHECK (Transfer (TRUE, 1, 3, &Size, Out) == EFI_SUCCESS && Flash[67] == 0x42);
  Flash[127] = 0xff;
  Out[0] = 0x24;
  Size = sizeof (Out);
  CHECK (Transfer (TRUE, 1, 63, &Size, Out) == EFI_BAD_BUFFER_SIZE);
  CHECK (Size == 1 && Flash[127] == 0x24 && Flash[128] == 0x33);
  Fail = 1;
  Out[0] = 0x55;
  Size = 1;
  CHECK (Transfer (FALSE, 0, 0, &Size, Out) == EFI_DEVICE_ERROR);
  CHECK (Size == 0 && Out[0] == 0x55);
  Size = 1;
  CHECK (Transfer (TRUE, 1, 3, &Size, Out) == EFI_DEVICE_ERROR);
  CHECK (Size == 0 && Flash[67] == 0x42);
  CHECK (StoreErase (NULL, (EFI_LBA)0, (UINTN)1,
                     EFI_LBA_LIST_TERMINATOR) == EFI_DEVICE_ERROR);
  CHECK (Erases == 0 && Flash[0] == 0x33);
  Fail = 0;
  CHECK (StoreErase (NULL, (EFI_LBA)0, (UINTN)1, (EFI_LBA)4, (UINTN)1,
                     EFI_LBA_LIST_TERMINATOR) == EFI_INVALID_PARAMETER);
  CHECK (Erases == 0);
  CHECK (StoreErase (NULL, (EFI_LBA)0, (UINTN)1, (EFI_LBA)2, (UINTN)1,
                     EFI_LBA_LIST_TERMINATOR) == EFI_SUCCESS);
  CHECK (Erases == 2 && Flash[0] == 0xff && Flash[128] == 0xff && Flash[64] == 0x33);

  FailValidation = 1;
  CHECK (StoreRecoveryComplete (NULL, NULL, NULL) == EFI_DEVICE_ERROR);
  CHECK (!mValidated && ReadyInstalls == 0);
  FailValidation = 0;
  FailInstall = 1;
  CHECK (StoreRecoveryComplete (NULL, NULL, NULL) == EFI_DEVICE_ERROR);
  CHECK (!mValidated && ReadyInstalls == 0);
  FailInstall = 0;
  CHECK (StoreRecoveryComplete (NULL, NULL, NULL) == EFI_SUCCESS);
  CHECK (mValidated && ReadyInstalls == 1);
  CHECK (StoreRecoveryComplete (NULL, NULL, NULL) == EFI_SUCCESS && ReadyInstalls == 1);
  puts ("FVB transfer, erase and recovery checks passed");
  return 0;
}
