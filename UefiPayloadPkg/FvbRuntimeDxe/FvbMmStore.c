/** @file
  Validate fixed-service variable storage before it is published through FVB.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Guid/SystemNvDataGuid.h>
#include <Protocol/SmmFaultTolerantWrite.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FlashDeviceLib.h>
#include <Library/FvLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include "FvbMmStore.h"

STATIC
EFI_STATUS
StoreIsErased (
  IN CONST VARIABLE_FLASH_INFO  *Info
  )
{
  UINT8       Buffer[256];
  UINTN       Index;
  UINTN       Length;
  UINTN       Offset;
  UINTN       StoreSize;
  EFI_STATUS  Status;

  StoreSize = (UINTN)(Info->NvVariableLength + Info->FtwWorkingLength + Info->FtwSpareLength);
  for (Offset = 0; Offset < StoreSize; Offset += Length) {
    Length = MIN (sizeof (Buffer), StoreSize - Offset);
    Status = LibFvbFlashDeviceRead ((UINTN)Info->NvVariableBaseAddress + Offset, &Length, Buffer);
    if (EFI_ERROR (Status) || (Length == 0)) {
      return EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR;
    }

    for (Index = 0; Index < Length; Index++) {
      if (Buffer[Index] != MAX_UINT8) {
        return EFI_COMPROMISED_DATA;
      }
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
MmFvbValidateGeometry (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT VARIABLE_FLASH_INFO       *Validated
  )
{
  UINT64      BlockCount;
  UINT32      Remainder;
  UINT64      StoreSize;
  EFI_STATUS  Status;

  if ((Info == NULL) || (Validated == NULL) ||
      (Info->FtwWorkingLength == 0) || (Info->FtwWorkingLength > MAX_UINT32) ||
      (Info->NvVariableLength < sizeof (MM_FVB_STORE_HEADER)) ||
      (Info->NvVariableLength > MAX_UINT64 - Info->FtwWorkingLength) ||
      (Info->NvVariableLength + Info->FtwWorkingLength > MAX_UINT64 - Info->FtwSpareLength))
  {
    return EFI_INVALID_PARAMETER;
  }

  StoreSize = Info->NvVariableLength + Info->FtwWorkingLength + Info->FtwSpareLength;
  BlockCount = DivU64x32Remainder (StoreSize, (UINT32)Info->FtwWorkingLength, &Remainder);
  if ((Remainder != 0) || (BlockCount > MAX_UINTN) || (StoreSize > MAX_UINTN) ||
      (Info->NvVariableBaseAddress > MAX_UINTN) ||
      (StoreSize - 1 > MAX_UINTN - Info->NvVariableBaseAddress))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = SmmStoreGetFlashInfo (
             Info->NvVariableBaseAddress,
             (UINTN)Info->FtwWorkingLength,
             (UINTN)BlockCount,
             Validated
             );
  if (EFI_ERROR (Status) || (CompareMem (Info, Validated, sizeof (*Validated)) != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
MmFvbReadStoreHeader (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  IN EFI_PHYSICAL_ADDRESS       Address,
  OUT MM_FVB_STORE_HEADER       *Store
  )
{
  EFI_FIRMWARE_VOLUME_HEADER  *Header;
  VARIABLE_STORE_HEADER       *Variable;
  UINT64                      NumBlocks;
  UINT32                      Remainder;
  UINTN                       Size;
  EFI_STATUS                  Status;

  Size   = sizeof (Store->Bytes);
  Status = LibFvbFlashDeviceRead ((UINTN)Address, &Size, Store->Bytes);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Size != sizeof (Store->Bytes)) {
    return EFI_DEVICE_ERROR;
  }

  Header = (VOID *)Store->Bytes;
  if ((Header->Signature != EFI_FVH_SIGNATURE) ||
      (Header->Revision != EFI_FVH_REVISION) ||
      !CompareGuid (&Header->FileSystemGuid, &gEfiSystemNvDataFvGuid) ||
      (Header->HeaderLength < sizeof (*Header) + sizeof (EFI_FV_BLOCK_MAP_ENTRY)) ||
      (Header->HeaderLength > sizeof (Store->Bytes)) ||
      ((Header->HeaderLength & 1) != 0) ||
      (CalculateSum16 ((UINT16 *)Header, Header->HeaderLength) != 0))
  {
    return EFI_VOLUME_CORRUPTED;
  }

  NumBlocks = DivU64x32Remainder (Header->FvLength, Info->FtwWorkingLength, &Remainder);
  if ((Header->HeaderLength != sizeof (*Header) + sizeof (EFI_FV_BLOCK_MAP_ENTRY)) ||
      (Header->ExtHeaderOffset != 0) ||
      (Header->FvLength != Info->NvVariableLength + Info->FtwWorkingLength + Info->FtwSpareLength) ||
      (Header->BlockMap[0].Length != Info->FtwWorkingLength) ||
      (Remainder != 0) || (NumBlocks > MAX_UINT32) ||
      (Header->BlockMap[0].NumBlocks != NumBlocks) ||
      (Header->BlockMap[1].Length != 0) || (Header->BlockMap[1].NumBlocks != 0))
  {
    return EFI_UNSUPPORTED;
  }

  Variable = (VOID *)(Store->Bytes + Header->HeaderLength);
  if (!CompareGuid (&Variable->Signature, &gEfiAuthenticatedVariableGuid) ||
      (Info->NvVariableLength < Header->HeaderLength) ||
      (Variable->Size != Info->NvVariableLength - Header->HeaderLength) ||
      (Variable->Format != VARIABLE_STORE_FORMATTED) ||
      (Variable->State != VARIABLE_STORE_HEALTHY))
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
  UINTN       Size;
  EFI_STATUS  Status;

  Size   = sizeof (*Header);
  Status = LibFvbFlashDeviceRead ((UINTN)Address, &Size, (UINT8 *)Header);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Size == sizeof (*Header) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS
MmFvbReadRecoveryHeader (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT MM_FVB_STORE_HEADER       *Store
  )
{
  EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  Expected;
  EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  Header;
  BOOLEAN                                  PrimaryWorkingBlockValid;
  BOOLEAN                                  SpareWorkingBlockValid;
  EFI_STATUS                               Status;

  if ((Info->FtwWorkingLength < sizeof (Expected)) ||
      (Info->FtwWorkingLength > Info->FtwSpareLength) ||
      (Info->NvVariableLength > Info->FtwSpareLength))
  {
    return EFI_UNSUPPORTED;
  }

  SetMem (&Expected, sizeof (Expected), MAX_UINT8);
  CopyGuid (&Expected.Signature, &gEdkiiWorkingBlockSignatureGuid);
  Expected.WriteQueueSize    = Info->FtwWorkingLength - sizeof (Expected);
  Expected.Crc               = CalculateCrc32 (&Expected, sizeof (Expected));
  Expected.WorkingBlockValid = FTW_VALID_STATE;

  Status = ReadWorkingHeader (Info->FtwWorkingBaseAddress, &Header);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  PrimaryWorkingBlockValid = CompareMem (&Header, &Expected, sizeof (Header)) == 0;
  Status                   = ReadWorkingHeader (Info->FtwSpareBaseAddress, &Header);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  SpareWorkingBlockValid = CompareMem (&Header, &Expected, sizeof (Header)) == 0;
  Status = MmFvbReadStoreHeader (Info, Info->FtwSpareBaseAddress, Store);
  if (EFI_ERROR (Status) && (Status != EFI_VOLUME_CORRUPTED)) {
    return Status;
  }

  if (PrimaryWorkingBlockValid) {
    return (Status == EFI_VOLUME_CORRUPTED) ? EFI_COMPROMISED_DATA : Status;
  }

  if (SpareWorkingBlockValid || !EFI_ERROR (Status)) {
    return EFI_COMPROMISED_DATA;
  }

  return Status;
}

EFI_STATUS
MmFvbInspectStorage (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT MM_FVB_STORE_HEADER       *Store,
  OUT BOOLEAN                   *Format
  )
{
  EFI_STATUS  Status;

  if ((Info == NULL) || (Store == NULL) || (Format == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Format = FALSE;
  Status  = MmFvbReadStoreHeader (Info, Info->NvVariableBaseAddress, Store);
  if (Status != EFI_VOLUME_CORRUPTED) {
    return Status;
  }

  Status = MmFvbReadRecoveryHeader (Info, Store);
  if (Status != EFI_VOLUME_CORRUPTED) {
    return Status;
  }

  Status = StoreIsErased (Info);
  if (!EFI_ERROR (Status)) {
    *Format = TRUE;
  }

  return Status;
}
