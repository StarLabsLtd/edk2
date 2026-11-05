/** @file
  Internal firmware-volume interface for the coreboot variable store.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>

#include <Guid/CorebootVariableService.h>
#include <Guid/CorebootVariableStoreInfo.h>
#include <Guid/VariableFlashInfo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include <Protocol/FtwStoreValidation.h>
#include <Protocol/SmmFaultTolerantWrite.h>
#include <Protocol/SmmFirmwareVolumeBlock.h>

typedef UINT32 (EFIAPI *STORE_TRANSFER)(UINT32 Offset, UINT32 Size);
typedef UINT32 (EFIAPI *STORE_VALIDATE)(VOID);

STATIC COREBOOT_VARIABLE_SERVICE_INFO  *mService;
STATIC COREBOOT_VARIABLE_STORE_INFO    mStore;
STATIC VOID                            *mRegistration;
STATIC EFI_HANDLE                      mFvbHandle;
STATIC EFI_HANDLE                      mValidationHandle;
STATIC BOOLEAN                         mValidated;

STATIC
EFI_STATUS
EFIAPI
StoreValidatePrimary (
  VOID
  )
{
  STORE_VALIDATE  Validate;

  Validate = (STORE_VALIDATE)(UINTN)mService->StoreValidate;
  if ((Validate == NULL) || (Validate () != COREBOOT_VARIABLE_REGISTER_SUCCESS)) {
    return EFI_VOLUME_CORRUPTED;
  }

  return EFI_SUCCESS;
}

STATIC EDKII_FTW_STORE_VALIDATION_PROTOCOL  mStoreValidation = {
  StoreValidatePrimary
};

#define STORE_ATTRIBUTES  (EFI_FVB2_READ_ENABLED_CAP | EFI_FVB2_READ_STATUS | \
                           EFI_FVB2_WRITE_ENABLED_CAP | EFI_FVB2_WRITE_STATUS | \
                           EFI_FVB2_STICKY_WRITE | EFI_FVB2_MEMORY_MAPPED | \
                           EFI_FVB2_ERASE_POLARITY)

STATIC
EFI_STATUS
WorkspaceErased (
  IN  UINT32   Offset,
  OUT BOOLEAN  *Erased
  )
{
  STORE_TRANSFER  Read;
  UINT8           *Buffer;
  UINTN           Index;

  Read   = (STORE_TRANSFER)(UINTN)mService->StoreRead;
  Buffer = (UINT8 *)(UINTN)mService->StoreBuffer;
  if ((Read == NULL) || (Buffer == NULL) ||
      (Read (Offset, 1) != COREBOOT_VARIABLE_REGISTER_SUCCESS))
  {
    return EFI_DEVICE_ERROR;
  }

  // One programmed byte proves the workspace is not erased.
  if (Buffer[0] != MAX_UINT8) {
    *Erased = FALSE;
    return EFI_SUCCESS;
  }

  if (Read (Offset, mStore.BlockSize) != COREBOOT_VARIABLE_REGISTER_SUCCESS) {
    return EFI_DEVICE_ERROR;
  }

  *Erased = TRUE;
  for (Index = 0; Index < mStore.BlockSize; Index++) {
    if (Buffer[Index] != MAX_UINT8) {
      *Erased = FALSE;
      break;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
CheckBeforeRecovery (
  IN CONST VARIABLE_FLASH_INFO  *FlashInfo
  )
{
  STORE_VALIDATE  Validate;
  UINT32          Result;
  BOOLEAN         WorkingErased;
  BOOLEAN         SpareErased;
  EFI_STATUS      Status;
  UINTN           Index;
  UINT32          SpareOffset;

  Validate = (STORE_VALIDATE)(UINTN)mService->StoreValidate;
  if (Validate == NULL) {
    return EFI_DEVICE_ERROR;
  }

  Result = Validate ();
  if ((Result != COREBOOT_VARIABLE_REGISTER_SUCCESS) &&
      (Result != COREBOOT_VARIABLE_STORE_INVALID))
  {
    return EFI_DEVICE_ERROR;
  }

  /* FTW may initialize blank workspaces only when the primary is valid. */
  Status = WorkspaceErased ((UINT32)(FlashInfo->FtwWorkingBaseAddress - mStore.StoreBase),
                            &WorkingErased);
  if (EFI_ERROR (Status) || !WorkingErased) {
    return Status;
  }

  SpareOffset = (UINT32)(FlashInfo->FtwSpareBaseAddress - mStore.StoreBase);
  Status = WorkspaceErased (SpareOffset, &SpareErased);
  if (EFI_ERROR (Status) || !SpareErased) {
    return Status;
  }

  if (Result != COREBOOT_VARIABLE_REGISTER_SUCCESS) {
    return EFI_VOLUME_CORRUPTED;
  }

  /* Initializing FTW erases the entire spare, not just its first block. */
  for (Index = mStore.BlockSize; Index < FlashInfo->FtwSpareLength; Index += mStore.BlockSize) {
    Status = WorkspaceErased (SpareOffset + (UINT32)Index, &SpareErased);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (!SpareErased) {
      return EFI_VOLUME_CORRUPTED;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
StoreGetAttributes (
  IN  CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *This,
  OUT EFI_FVB_ATTRIBUTES_2                     *Attributes
  )
{
  if (Attributes == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Attributes = STORE_ATTRIBUTES;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
StoreSetAttributes (
  IN     CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *This,
  IN OUT EFI_FVB_ATTRIBUTES_2                     *Attributes
  )
{
  if ((Attributes == NULL) || (*Attributes != STORE_ATTRIBUTES)) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
StoreGetAddress (
  IN  CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *This,
  OUT EFI_PHYSICAL_ADDRESS                    *Address
  )
{
  if (Address == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Address = mStore.StoreBase;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
StoreGetBlockSize (
  IN  CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *This,
  IN  EFI_LBA                                 Lba,
  OUT UINTN                                   *BlockSize,
  OUT UINTN                                   *NumberOfBlocks
  )
{
  UINTN  Count;

  Count = mStore.StoreSize / mStore.BlockSize;
  if ((BlockSize == NULL) || (NumberOfBlocks == NULL) || (Lba >= Count)) {
    return EFI_INVALID_PARAMETER;
  }

  *BlockSize      = mStore.BlockSize;
  *NumberOfBlocks = Count - (UINTN)Lba;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Transfer (
  IN     BOOLEAN  Write,
  IN     EFI_LBA  Lba,
  IN     UINTN    Offset,
  IN OUT UINTN    *NumBytes,
  IN OUT UINT8    *Buffer
  )
{
  UINTN           Count;
  UINTN           Size;
  UINT32          Position;
  STORE_TRANSFER  Operation;
  UINT8           *Staging;
  BOOLEAN         Partial;

  Count = mStore.StoreSize / mStore.BlockSize;
  if ((NumBytes == NULL) || (Buffer == NULL) || (Lba >= Count) ||
      (Offset >= mStore.BlockSize))
  {
    return EFI_INVALID_PARAMETER;
  }

  Size    = *NumBytes;
  Partial = Size > mStore.BlockSize - Offset;
  if (Partial) {
    Size = mStore.BlockSize - Offset;
  }

  *NumBytes = Size;
  if (Size == 0) {
    return EFI_SUCCESS;
  }

  Position  = (UINT32)Lba * mStore.BlockSize + (UINT32)Offset;
  Staging   = (UINT8 *)(UINTN)mService->StoreBuffer;
  Operation = (STORE_TRANSFER)(UINTN)(Write ? mService->StoreWrite : mService->StoreRead);
  if ((Staging == NULL) || (Operation == NULL) || (mService->StoreBufferSize != mStore.BlockSize)) {
    return EFI_DEVICE_ERROR;
  }

  if (Write) {
    CopyMem (Staging, Buffer, Size);
  }

  if (Operation (Position, (UINT32)Size) != COREBOOT_VARIABLE_REGISTER_SUCCESS) {
    *NumBytes = 0;
    return EFI_DEVICE_ERROR;
  }

  if (!Write) {
    CopyMem (Buffer, Staging, Size);
  }

  return Partial ? EFI_BAD_BUFFER_SIZE : EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
StoreRead (
  IN     CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *This,
  IN     EFI_LBA                                  Lba,
  IN     UINTN                                    Offset,
  IN OUT UINTN                                    *NumBytes,
  OUT    UINT8                                    *Buffer
  )
{
  return Transfer (FALSE, Lba, Offset, NumBytes, Buffer);
}

STATIC
EFI_STATUS
EFIAPI
StoreWrite (
  IN     CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *This,
  IN     EFI_LBA                                  Lba,
  IN     UINTN                                    Offset,
  IN OUT UINTN                                    *NumBytes,
  IN     UINT8                                    *Buffer
  )
{
  return Transfer (TRUE, Lba, Offset, NumBytes, Buffer);
}

STATIC
EFI_STATUS
EFIAPI
StoreErase (
  IN CONST EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL  *This,
  ...
  )
{
  VA_LIST         Args;
  EFI_LBA         Lba;
  UINTN           Count;
  UINTN           Total;
  UINTN           Index;
  STORE_TRANSFER  Operation;

  Total = mStore.StoreSize / mStore.BlockSize;
  VA_START (Args, This);
  while ((Lba = VA_ARG (Args, EFI_LBA)) != EFI_LBA_LIST_TERMINATOR) {
    Count = VA_ARG (Args, UINTN);
    if ((Lba >= Total) || (Count == 0) || (Count > Total - (UINTN)Lba)) {
      VA_END (Args);
      return EFI_INVALID_PARAMETER;
    }
  }

  VA_END (Args);
  Operation = (STORE_TRANSFER)(UINTN)mService->StoreErase;
  if (Operation == NULL) {
    return EFI_DEVICE_ERROR;
  }

  VA_START (Args, This);
  while ((Lba = VA_ARG (Args, EFI_LBA)) != EFI_LBA_LIST_TERMINATOR) {
    Count = VA_ARG (Args, UINTN);
    for (Index = 0; Index < Count; Index++) {
      if (Operation (((UINT32)Lba + (UINT32)Index) * mStore.BlockSize, mStore.BlockSize) !=
          COREBOOT_VARIABLE_REGISTER_SUCCESS)
      {
        VA_END (Args);
        return EFI_DEVICE_ERROR;
      }
    }
  }

  VA_END (Args);
  return EFI_SUCCESS;
}

STATIC EFI_SMM_FIRMWARE_VOLUME_BLOCK_PROTOCOL  mFvb = {
  StoreGetAttributes,
  StoreSetAttributes,
  StoreGetAddress,
  StoreGetBlockSize,
  StoreRead,
  StoreWrite,
  StoreErase,
  NULL
};

STATIC
EFI_STATUS
EFIAPI
StoreRecoveryComplete (
  IN CONST EFI_GUID  *Protocol,
  IN VOID            *Interface,
  IN EFI_HANDLE      Handle
  )
{
  EFI_HANDLE      ReadyHandle;

  if (mValidated) {
    return EFI_SUCCESS;
  }

  if (EFI_ERROR (StoreValidatePrimary ())) {
    return EFI_DEVICE_ERROR;
  }

  ReadyHandle = NULL;
  if (EFI_ERROR (gMmst->MmInstallProtocolInterface (
                        &ReadyHandle,
                        &gCorebootVariableStoreReadyGuid,
                        EFI_NATIVE_INTERFACE,
                        NULL
                        )))
  {
    return EFI_DEVICE_ERROR;
  }

  mValidated = TRUE;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CorebootVariableFvbEntryPoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  EFI_HOB_GUID_TYPE           *Hob;
  COREBOOT_VARIABLE_STORE_INFO  *Store;
  VARIABLE_FLASH_INFO         *FlashInfo;
  VARIABLE_FLASH_INFO         Expected;
  EFI_STATUS                  Status;

  Hob = GetFirstGuidHob (&gCorebootVariableServiceInfoGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*mService))) {
    return EFI_NOT_FOUND;
  }

  mService = GET_GUID_HOB_DATA (Hob);
  if ((mService->Revision != COREBOOT_VARIABLE_SERVICE_INFO_REVISION) ||
      (mService->Size != sizeof (*mService)) || (mService->Reserved != 0) ||
      (mService->StoreRead == 0) || (mService->StoreWrite == 0) ||
      (mService->StoreErase == 0) || (mService->StoreValidate == 0) ||
      (mService->StoreBuffer == 0) || (mService->StoreBufferSize == 0) ||
      (mService->StoreBufferSize - 1 > MAX_UINT32 - mService->StoreBuffer))
  {
    return EFI_INVALID_PARAMETER;
  }

  Hob      = GetFirstGuidHob (&gCorebootVariableStoreInfoGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*Store))) {
    return EFI_NOT_FOUND;
  }

  Store = GET_GUID_HOB_DATA (Hob);
  if ((Store->Revision != COREBOOT_VARIABLE_STORE_INFO_REVISION) ||
      (Store->StoreBase == 0) || (Store->StoreBase > MAX_UINT32) ||
      (Store->StoreSize == 0) || (Store->StoreSize - 1 > MAX_UINT32 - Store->StoreBase) ||
      (Store->BlockSize == 0) || (Store->StoreSize % Store->BlockSize != 0) ||
      (Store->StoreOffset % Store->BlockSize != 0) ||
      (mService->StoreBufferSize != Store->BlockSize))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = SmmStoreGetFlashInfo (Store->StoreBase, Store->BlockSize,
                                Store->StoreSize / Store->BlockSize, &Expected);
  Hob = GetFirstGuidHob (&gVariableFlashInfoHobGuid);
  if (EFI_ERROR (Status) || (Hob == NULL) ||
      (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*FlashInfo)))
  {
    return EFI_INVALID_PARAMETER;
  }

  FlashInfo = GET_GUID_HOB_DATA (Hob);
  if (CompareMem (FlashInfo, &Expected, sizeof (Expected)) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (&mStore, Store, sizeof (mStore));
  Status = CheckBeforeRecovery (&Expected);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mValidationHandle = NULL;
  Status = gMmst->MmInstallProtocolInterface (
                    &mValidationHandle,
                    &gEdkiiFtwStoreValidationProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mStoreValidation
                    );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gMmst->MmRegisterProtocolNotify (
                    &gEfiSmmFaultTolerantWriteProtocolGuid,
                    StoreRecoveryComplete,
                    &mRegistration
                    );
  if (EFI_ERROR (Status)) {
    if (EFI_ERROR (gMmst->MmUninstallProtocolInterface (
                           mValidationHandle,
                           &gEdkiiFtwStoreValidationProtocolGuid,
                           &mStoreValidation
                           )))
    {
      CpuDeadLoop ();
    }

    return Status;
  }

  mFvbHandle = NULL;
  Status = gMmst->MmInstallProtocolInterface (
                    &mFvbHandle,
                    &gEfiSmmFirmwareVolumeBlockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mFvb
                    );
  if (EFI_ERROR (Status)) {
    if (EFI_ERROR (gMmst->MmRegisterProtocolNotify (
                           &gEfiSmmFaultTolerantWriteProtocolGuid,
                           NULL,
                           &mRegistration
                           )) ||
        EFI_ERROR (gMmst->MmUninstallProtocolInterface (
                           mValidationHandle,
                           &gEdkiiFtwStoreValidationProtocolGuid,
                           &mStoreValidation
                           )))
    {
      CpuDeadLoop ();
    }
  }

  return Status;
}
