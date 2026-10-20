/** @file
  SMM Firmware Volume Block Driver.

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/DxeServicesLib.h>
#include <Library/SmmServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
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
  EFI_STATUS                     Status;
  VOID                           *ImageData;
  UINTN                          ImageSize;
  EFI_FIRMWARE_VOLUME_HEADER     *FvHeader;
  VARIABLE_STORE_HEADER          *VariableStore;
  AUTHENTICATED_VARIABLE_HEADER  *Variable;
  UINTN                          VariableSize;
  UINTN                          VarEndAddr;

  if ((VarData == NULL) || (VarSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = GetSectionFromAnyFv (PcdGetPtr (PcdNvsDataFile), EFI_SECTION_RAW, 0, &ImageData, &ImageSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  FvHeader      = (EFI_FIRMWARE_VOLUME_HEADER *)ImageData;
  VariableStore = (VARIABLE_STORE_HEADER *)((UINT8 *)ImageData + FvHeader->HeaderLength);
  VarEndAddr    = (UINTN)VariableStore + VariableStore->Size;
  Variable      = (AUTHENTICATED_VARIABLE_HEADER *)HEADER_ALIGN (VariableStore + 1);
  *VarData      = (VOID *)Variable;
  while (((UINTN)Variable < VarEndAddr)) {
    if (Variable->StartId != VARIABLE_DATA) {
      break;
    }

    VariableSize = sizeof (AUTHENTICATED_VARIABLE_HEADER) + Variable->DataSize + Variable->NameSize;
    Variable     = (AUTHENTICATED_VARIABLE_HEADER *)HEADER_ALIGN ((UINTN)Variable + VariableSize);
  }

  *VarSize = (UINTN)Variable - HEADER_ALIGN (VariableStore + 1);

  return EFI_SUCCESS;
}

/**
  The function installs EFI_SMM_FIRMWARE_VOLUME_BLOCK protocol
  for each FV in the system.

  @param[in]  FwhInstance   The pointer to a FW volume instance structure,
                            which contains the information about one FV.
  @param[in]  InstanceNum   The instance number which can be used as a ID
                            to locate this FwhInstance in other functions.

  @retval     EFI_SUCCESS   Installed successfully.
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
  // Publish the callable FVB interface only after its device path is ready.
  //
  FvbHandle = NULL;
  Status    = gSmst->SmmInstallProtocolInterface (
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

  Status = gSmst->SmmInstallProtocolInterface (
                    &FvbHandle,
                    &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &FvbDevice->FwVolBlockInstance
                    );
  if (EFI_ERROR (Status)) {
    if (!EFI_ERROR (
           gSmst->SmmUninstallProtocolInterface (
                    FvbHandle,
                    &gEfiDevicePathProtocolGuid,
                    FvbDevice->DevicePath
                    )
           ))
    {
      FreePool (FvbDevice->DevicePath);
    }

    FreePool (FvbDevice);
    return Status;
  }

  //
  // Notify the Fvb wrapper driver SMM fvb is ready
  //
  FvbHandle = NULL;
  Status    = gBS->InstallProtocolInterface (
                     &FvbHandle,
                     &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                     EFI_NATIVE_INTERFACE,
                     &FvbDevice->FwVolBlockInstance
                     );

  // FVB consumers may now retain callbacks into this image. Keep it resident
  // even if the separate DXE wrapper notification fails.
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Fvb: DXE wrapper notification failed: %r\n", Status));
  }

  return EFI_SUCCESS;
}

/**
  The driver entry point for SMM Firmware Volume Block Driver.

  The function does the necessary initialization work
  Firmware Volume Block Driver.

  @param[in]  ImageHandle       The firmware allocated handle for the UEFI image.
  @param[in]  SystemTable       A pointer to the EFI system table.

  @retval     EFI_SUCCESS       This function always return EFI_SUCCESS.
                                It will ASSERT on errors.

**/
EFI_STATUS
EFIAPI
FvbSmmInitialize (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return FvbInitialize (NULL, NULL);
}
