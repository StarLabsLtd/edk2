/** @file
  Adapt the existing FMP flash calls to a verified MM transaction.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <Library/CorebootCapsuleLib.h>
#include <Library/SmmStoreLib.h>

EFI_STATUS SmmStoreLibInitialize(VOID)
{
  UINT32 Flash, Block;
  return CorebootCapsuleGeometry(&Flash, &Block);
}
EFI_STATUS SmmStoreLibGetBlockSize(UINTN *BlockSize)
{
  UINT32 Flash, Block;
  EFI_STATUS Status;
  if (!BlockSize) return EFI_INVALID_PARAMETER;
  Status = CorebootCapsuleGeometry(&Flash, &Block);
  if (!EFI_ERROR(Status)) *BlockSize = Block;
  return Status;
}
EFI_STATUS SmmStoreLibGetNumBlocks(UINTN *NumBlocks)
{
  UINT32 Flash, Block;
  EFI_STATUS Status;
  if (!NumBlocks) return EFI_INVALID_PARAMETER;
  Status = CorebootCapsuleGeometry(&Flash, &Block);
  if (!EFI_ERROR(Status)) *NumBlocks = Flash / Block;
  return Status;
}
/* The selected FMP path programs through CorebootCapsuleApply, not raw I/O. */
EFI_STATUS SmmStoreLibReadAnyBlock(EFI_LBA Block, UINTN Offset, UINTN *Size, UINT8 *Buffer) { return EFI_UNSUPPORTED; }
EFI_STATUS SmmStoreLibEraseAnyBlock(EFI_LBA Block) { return EFI_UNSUPPORTED; }
EFI_STATUS SmmStoreLibWriteAnyBlock(EFI_LBA Block, UINTN Offset, UINTN *Size, UINT8 *Buffer) { return EFI_UNSUPPORTED; }
VOID EFIAPI SmmStoreLibDeinitialize(VOID) { CorebootCapsuleClose(); }

/* Fixed-MM variables use the private FVB, not this capsule-only adapter. */
EFI_STATUS EFIAPI SmmStoreLibVariableBegin(UINT64 *Generation) { return EFI_UNSUPPORTED; }
EFI_STATUS EFIAPI SmmStoreLibVariableEnd(VOID) { return EFI_UNSUPPORTED; }
EFI_STATUS SmmStoreLibGetMmioAddress(EFI_PHYSICAL_ADDRESS *Address) { return EFI_UNSUPPORTED; }
EFI_STATUS SmmStoreLibRead(EFI_LBA Block, UINTN Offset, UINTN *Size, UINT8 *Buffer) { return EFI_UNSUPPORTED; }
EFI_STATUS SmmStoreLibWrite(EFI_LBA Block, UINTN Offset, UINTN *Size, UINT8 *Buffer) { return EFI_UNSUPPORTED; }
EFI_STATUS SmmStoreLibEraseBlock(EFI_LBA Block) { return EFI_UNSUPPORTED; }
VOID EFIAPI SmmStoreLibVirtualAddressChange(CONVERT_POINTER_CALLBACK Callback) { }
