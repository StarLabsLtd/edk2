/** @file
  Publish the fixed-service variable store as an MM FVB instance.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Guid/VariableFlashInfo.h>
#include <Protocol/SmmFaultTolerantWrite.h>
#include <Library/HobLib.h>
#include <Library/MmServicesTableLib.h>
#include "FvbMmStore.h"
#include "FvbService.h"

STATIC VARIABLE_FLASH_INFO  mFlashInfo;

EFI_STATUS
GetInitialVariableData (
  OUT VOID   **VarData,
  OUT UINTN  *VarSize
  )
{
  if ((VarData == NULL) || (VarSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *VarData = NULL;
  *VarSize = 0;
  return EFI_NOT_FOUND;
}

EFI_STATUS
InstallFvbProtocol (
  IN EFI_FW_VOL_INSTANCE  *FwhInstance,
  IN UINTN                InstanceNum
  )
{
  EFI_FW_VOL_BLOCK_DEVICE  *FvbDevice;
  EFI_HANDLE               FvbHandle;
  EFI_STATUS               Status;

  FvbDevice = AllocateRuntimeCopyPool (sizeof (*FvbDevice), &mFvbDeviceTemplate);
  if (FvbDevice == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  FvbDevice->Instance = InstanceNum;
  FvbHandle           = NULL;
  Status              = gMmst->MmInstallProtocolInterface (
                                  &FvbHandle,
                                  &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                                  EFI_NATIVE_INTERFACE,
                                  &FvbDevice->FwVolBlockInstance
                                  );
  if (EFI_ERROR (Status)) {
    FreePool (FvbDevice);
  }

  return Status;
}

STATIC
EFI_STATUS
EFIAPI
FtwReady (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  MM_FVB_STORE_HEADER  Store;
  EFI_STATUS           Status;

  Status = MmFvbReadStoreHeader (&mFlashInfo, mFlashInfo.NvVariableBaseAddress, &Store);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Recovered variable store is invalid: %r\n", Status));
    CpuDeadLoop ();
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FvbMmInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_FIRMWARE_VOLUME_HEADER  *ValidatedHeader;
  CONST VARIABLE_FLASH_INFO   *FormatInfo;
  CONST VARIABLE_FLASH_INFO   *Info;
  EFI_HOB_GUID_TYPE           *Hob;
  MM_FVB_STORE_HEADER         Store;
  BOOLEAN                     Format;
  VOID                        *Registration;
  EFI_STATUS                  Status;

  Status = LibFvbFlashDeviceInit ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Hob = GetFirstGuidHob (&gVariableFlashInfoHobGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (mFlashInfo))) {
    return EFI_NOT_FOUND;
  }

  Info   = GET_GUID_HOB_DATA (Hob);
  Status = MmFvbValidateGeometry (Info, &mFlashInfo);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MmFvbInspectStorage (&mFlashInfo, &Store, &Format);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ValidatedHeader = Format ? NULL : (VOID *)Store.Bytes;
  FormatInfo      = Format ? &mFlashInfo : NULL;
  Status          = gMmst->MmRegisterProtocolNotify (
                             &gEfiSmmFaultTolerantWriteProtocolGuid,
                             FtwReady,
                             &Registration
                             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FvbInitialize (ValidatedHeader, FormatInfo);
  if (EFI_ERROR (Status) &&
      EFI_ERROR (gMmst->MmRegisterProtocolNotify (&gEfiSmmFaultTolerantWriteProtocolGuid, NULL, &Registration)))
  {
    CpuDeadLoop ();
  }

  return Status;
}
