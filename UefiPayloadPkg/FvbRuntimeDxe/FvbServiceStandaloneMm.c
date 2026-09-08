/** @file
  SMM Firmware Volume Block Driver.

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Guid/VariableFlashInfo.h>
#include <Library/FvLib.h>
#include <Library/MmServicesTableLib.h>
#include "FvbSmmCommon.h"
#include "FvbService.h"

/**
  Get intial variable data.

  @param[out]  VarData          Valid variable data.
  @param[out]  VarSize          Valid variable size.

  @retval RETURN_SUCCESS        Successfully found initial variable data.
  @retval RETURN_NOT_FOUND      Failed to find the variable data file from FV.
  @retval EFI_INVALID_PARAMETER VarData or VarSize is null.

**/
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

/**
  The function installs EFI_SMM_FIRMWARE_VOLUME_BLOCK protocol
  for each FV in the system.

  @param[in]  FwhInstance   The pointer to a FW volume instance structure,
                            which contains the information about one FV.
  @param[in]  InstanceNum   The instance number which can be used as a ID
                            to locate this FwhInstance in other functions.

  @retval     EFI_SUCESS    Installed successfully.
  @retval     Else          Did not install successfully.

**/
EFI_STATUS
InstallFvbProtocol (
  IN  EFI_FW_VOL_INSTANCE  *FwhInstance,
  IN  UINTN                InstanceNum
  )
{
  EFI_FW_VOL_BLOCK_DEVICE     *FvbDevice;
  EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader;
  EFI_STATUS                  Status;
  EFI_HANDLE                  FvbHandle;
  FV_MEMMAP_DEVICE_PATH       *FvDevicePath;
  VOID                        *TempPtr;

  FvbDevice = (EFI_FW_VOL_BLOCK_DEVICE *)AllocateRuntimeCopyPool (
                                           sizeof (EFI_FW_VOL_BLOCK_DEVICE),
                                           &mFvbDeviceTemplate
                                           );
  if (FvbDevice == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  FvbDevice->Instance = InstanceNum;
  FwVolHeader         = &FwhInstance->VolumeHeader;

  //
  // Set up the devicepath
  //
  if (FwVolHeader->ExtHeaderOffset == 0) {
    //
    // FV does not contains extension header, then produce MEMMAP_DEVICE_PATH
    //
    TempPtr               = AllocateRuntimeCopyPool (sizeof (FV_MEMMAP_DEVICE_PATH), &mFvMemmapDevicePathTemplate);
    FvbDevice->DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)TempPtr;
    if (FvbDevice->DevicePath == NULL) {
      FreePool (FvbDevice);
      return EFI_OUT_OF_RESOURCES;
    }

    FvDevicePath                                = (FV_MEMMAP_DEVICE_PATH *)FvbDevice->DevicePath;
    FvDevicePath->MemMapDevPath.StartingAddress = FwhInstance->FvBase;
    FvDevicePath->MemMapDevPath.EndingAddress   = FwhInstance->FvBase + FwVolHeader->FvLength - 1;
  } else {
    TempPtr               = AllocateRuntimeCopyPool (sizeof (FV_PIWG_DEVICE_PATH), &mFvPIWGDevicePathTemplate);
    FvbDevice->DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)TempPtr;
    if (FvbDevice->DevicePath == NULL) {
      FreePool (FvbDevice);
      return EFI_OUT_OF_RESOURCES;
    }

    CopyGuid (
      &((FV_PIWG_DEVICE_PATH *)FvbDevice->DevicePath)->FvDevPath.FvName,
      (GUID *)(UINTN)(FwhInstance->FvBase + FwVolHeader->ExtHeaderOffset)
      );
  }

  //
  // Publish FVB last so a failed installation cannot leave a callable instance.
  //
  FvbHandle = NULL;
  Status    = gMmst->MmInstallProtocolInterface (
                       &FvbHandle,
                       &gEfiDevicePathProtocolGuid,
                       EFI_NATIVE_INTERFACE,
                       FvbDevice->DevicePath
                       );
  if (EFI_ERROR (Status)) {
    FreePool (FvbDevice->DevicePath);
    FreePool (FvbDevice);
    return Status;
  }

  Status = gMmst->MmInstallProtocolInterface (
                    &FvbHandle,
                    &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &FvbDevice->FwVolBlockInstance
                    );
  if (EFI_ERROR (Status)) {
    // A failed uninstall leaves only the device path published, not FVB.
    if (!EFI_ERROR (
           gMmst->MmUninstallProtocolInterface (
                    FvbHandle,
                    &gEfiDevicePathProtocolGuid,
                    FvbDevice->DevicePath
                    )
           ))
    {
      FreePool (FvbDevice->DevicePath);
      FreePool (FvbDevice);
    }
  }

  return Status;
}

/**
  The driver entry point for SMM Firmware Volume Block Driver.

  The function does the necessary initialization work
  Firmware Volume Block Driver.

  @param[in]  ImageHandle       The firmware allocated handle for the UEFI image.
  @param[in]  SystemTable       A pointer to the EFI system table.

  @retval     EFI_SUCCESS       This funtion always return EFI_SUCCESS.
                                It will ASSERT on errors.

**/
EFI_STATUS
EFIAPI
FvbStandaloneMmInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                  Status;
  EFI_HOB_GUID_TYPE           *Hob;
  VARIABLE_FLASH_INFO         *Info;
  EFI_FIRMWARE_VOLUME_HEADER  *Header;
  VARIABLE_STORE_HEADER       *Variable;
  UINTN                       Size;

  union {
    UINT64    Alignment;
    UINT8     Bytes[sizeof (EFI_FIRMWARE_VOLUME_HEADER) + sizeof (EFI_FV_BLOCK_MAP_ENTRY) + sizeof (VARIABLE_STORE_HEADER)];
  } Store;

  Status = LibFvbFlashDeviceInit ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Initialization has validated the HOB and confined access to the existing store.
  Hob    = GetFirstGuidHob (&gVariableFlashInfoHobGuid);
  Info   = GET_GUID_HOB_DATA (Hob);
  Size   = sizeof (Store.Bytes);
  Status = LibFvbFlashDeviceRead ((UINTN)Info->NvVariableBaseAddress, &Size, Store.Bytes);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Header = (VOID *)Store.Bytes;
  if ((Size != sizeof (Store.Bytes)) ||
      (Header->HeaderLength != sizeof (*Header) + sizeof (EFI_FV_BLOCK_MAP_ENTRY)) ||
      (Header->ExtHeaderOffset != 0) ||
      (Header->Signature != EFI_FVH_SIGNATURE) || (Header->Revision != EFI_FVH_REVISION) ||
      !CompareGuid (&Header->FileSystemGuid, &gEfiSystemNvDataFvGuid) ||
      (Header->FvLength != Info->NvVariableLength + Info->FtwWorkingLength + Info->FtwSpareLength) ||
      (Header->BlockMap[0].Length != Info->FtwWorkingLength) ||
      (Header->BlockMap[0].NumBlocks != Header->FvLength / Info->FtwWorkingLength) ||
      (Header->BlockMap[1].Length != 0) || (Header->BlockMap[1].NumBlocks != 0) ||
      (CalculateSum16 ((UINT16 *)Header, Header->HeaderLength) != 0))
  {
    // Migration must never format an unrecognized or damaged persistent store.
    return EFI_VOLUME_CORRUPTED;
  }

  Variable = (VOID *)(Store.Bytes + Header->HeaderLength);
  if (!CompareGuid (&Variable->Signature, &gEfiAuthenticatedVariableGuid) ||
      (Info->NvVariableLength < Header->HeaderLength) ||
      (Variable->Size != Info->NvVariableLength - Header->HeaderLength) ||
      (Variable->Format != VARIABLE_STORE_FORMATTED) || (Variable->State != VARIABLE_STORE_HEALTHY))
  {
    return EFI_VOLUME_CORRUPTED;
  }

  return FvbInitialize (Header);
}
