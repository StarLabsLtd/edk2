/** @file
  SMM Firmware Volume Block Driver.

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiMm.h>
#include <Guid/VariableFlashInfo.h>
#include <Guid/SystemNvDataGuid.h>
#include <Protocol/SmmFaultTolerantWrite.h>
#include <Library/FvLib.h>
#include <Library/MmServicesTableLib.h>
#include "FvbSmmCommon.h"
#include "FvbService.h"

typedef union {
  UINT64    Alignment;
  UINT8     Bytes[sizeof (EFI_FIRMWARE_VOLUME_HEADER) + sizeof (EFI_FV_BLOCK_MAP_ENTRY) + sizeof (VARIABLE_STORE_HEADER)];
} STORE_HEADER;

STATIC VARIABLE_FLASH_INFO  mFlashInfo;

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

/** Read and validate the existing store without changing its contents. **/
STATIC
EFI_STATUS
ReadStoreHeader (
  IN EFI_PHYSICAL_ADDRESS  Address,
  OUT STORE_HEADER         *Store
  )
{
  EFI_STATUS                  Status;
  VARIABLE_FLASH_INFO         *Info;
  EFI_FIRMWARE_VOLUME_HEADER  *Header;
  VARIABLE_STORE_HEADER       *Variable;
  UINTN                       Size;

  Info   = &mFlashInfo;
  Size   = sizeof (Store->Bytes);
  Status = LibFvbFlashDeviceRead ((UINTN)Address, &Size, Store->Bytes);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Size != sizeof (Store->Bytes)) {
    return EFI_DEVICE_ERROR;
  }

  Header = (VOID *)Store->Bytes;
  if ((Header->HeaderLength != sizeof (*Header) + sizeof (EFI_FV_BLOCK_MAP_ENTRY)) ||
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

  Variable = (VOID *)(Store->Bytes + Header->HeaderLength);
  if (!CompareGuid (&Variable->Signature, &gEfiAuthenticatedVariableGuid) ||
      (Info->NvVariableLength < Header->HeaderLength) ||
      (Variable->Size != Info->NvVariableLength - Header->HeaderLength) ||
      (Variable->Format != VARIABLE_STORE_FORMATTED) || (Variable->State != VARIABLE_STORE_HEALTHY))
  {
    return EFI_VOLUME_CORRUPTED;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ReadWorkingHeader (
  IN EFI_PHYSICAL_ADDRESS                      Address,
  OUT EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  *Header
  )
{
  EFI_STATUS  Status;
  UINTN       Size;

  Size   = sizeof (*Header);
  Status = LibFvbFlashDeviceRead ((UINTN)Address, &Size, (UINT8 *)Header);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Size == sizeof (*Header) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

STATIC
EFI_STATUS
ReadRecoveryHeader (
  OUT STORE_HEADER  *Store
  )
{
  EFI_STATUS                               Status;
  EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  Expected;
  EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  Header;

  // This layout's entire primary working block must fit the spare image.
  if ((mFlashInfo.FtwWorkingLength < sizeof (Expected)) ||
      (mFlashInfo.NvVariableLength + mFlashInfo.FtwWorkingLength != mFlashInfo.FtwSpareLength))
  {
    return EFI_VOLUME_CORRUPTED;
  }

  SetMem (&Expected, sizeof (Expected), MAX_UINT8);
  CopyGuid (&Expected.Signature, &gEdkiiWorkingBlockSignatureGuid);
  Expected.WriteQueueSize    = mFlashInfo.FtwWorkingLength - sizeof (Expected);
  Expected.Crc               = CalculateCrc32 (&Expected, sizeof (Expected));
  Expected.WorkingBlockValid = FTW_VALID_STATE;

  Status = ReadWorkingHeader (mFlashInfo.FtwWorkingBaseAddress, &Header);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // A valid primary workspace must not be replaced with an unrelated spare.
  if (CompareMem (&Header, &Expected, sizeof (Header)) == 0) {
    return EFI_VOLUME_CORRUPTED;
  }

  Status = ReadWorkingHeader (mFlashInfo.FtwSpareBaseAddress + mFlashInfo.NvVariableLength, &Header);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (CompareMem (&Header, &Expected, sizeof (Header)) != 0) {
    return EFI_VOLUME_CORRUPTED;
  }

  // FTW validates the complete spare journal before restoring the working block.
  return ReadStoreHeader (mFlashInfo.FtwSpareBaseAddress, Store);
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
  STORE_HEADER  Store;
  EFI_STATUS    Status;

  Status = ReadStoreHeader (mFlashInfo.NvVariableBaseAddress, &Store);
  if (EFI_ERROR (Status)) {
    // Notify return values are ignored; do not dispatch Variable on bad media.
    DEBUG ((DEBUG_ERROR, "Recovered variable store is invalid: %r\n", Status));
    CpuDeadLoop ();
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FvbStandaloneMmInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_FIRMWARE_VOLUME_HEADER  *ValidatedHeader;
  EFI_HOB_GUID_TYPE           *Hob;
  EFI_STATUS                  Status;
  CONST VARIABLE_FLASH_INFO   *FormatInfo;
  STORE_HEADER                Store;
  VOID                        *Registration;

  Status = LibFvbFlashDeviceInit ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Flash initialization validated the HOB and confined access to this store.
  Hob = GetFirstGuidHob (&gVariableFlashInfoHobGuid);
  CopyMem (&mFlashInfo, GET_GUID_HOB_DATA (Hob), sizeof (mFlashInfo));
  ValidatedHeader = (VOID *)Store.Bytes;
  FormatInfo      = NULL;
  Status          = ReadStoreHeader (mFlashInfo.NvVariableBaseAddress, &Store);
  if (Status == EFI_VOLUME_CORRUPTED) {
    Status = ReadRecoveryHeader (&Store);
    if (Status == EFI_VOLUME_CORRUPTED) {
      ValidatedHeader = NULL;
      FormatInfo      = &mFlashInfo;
      Status          = EFI_SUCCESS;
    }
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gMmst->MmRegisterProtocolNotify (&gEfiSmmFaultTolerantWriteProtocolGuid, FtwReady, &Registration);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FvbInitialize (ValidatedHeader, FormatInfo);
  if (EFI_ERROR (Status)) {
    if (EFI_ERROR (gMmst->MmRegisterProtocolNotify (&gEfiSmmFaultTolerantWriteProtocolGuid, NULL, &Registration))) {
      CpuDeadLoop ();
    }
  }

  return Status;
}
