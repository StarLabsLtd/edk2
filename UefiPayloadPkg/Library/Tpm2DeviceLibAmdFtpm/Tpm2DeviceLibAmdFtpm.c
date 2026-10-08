/** @file
  AMD firmware TPM transport using the bootloader's reduced CRB interface.

  Copyright (c) 2026, Star Labs Ltd. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <IndustryStandard/Tpm2Acpi.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/UefiLib.h>
#include <Guid/TpmInstance.h>

STATIC UINTN   mControlArea;
STATIC UINTN   mCommand;
STATIC UINTN   mResponse;
STATIC UINT32  mCommandSize;
STATIC UINT32  mResponseSize;

// The CRB address registers are only four-byte aligned.
STATIC
UINT64
ReadBufferAddress (
  IN UINTN  Address
  )
{
  return MmioRead32 (Address) | LShiftU64 (MmioRead32 (Address + sizeof (UINT32)), 32);
}

STATIC
EFI_STATUS
WaitForCompletion (
  IN UINTN  TimeoutUs
  )
{
  while ((MmioRead32 (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, Start)) & BIT0) != 0) {
    if (TimeoutUs == 0) {
      return EFI_TIMEOUT;
    }

    MicroSecondDelay (100);
    TimeoutUs -= 100;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
AmdFtpmRequestUseTpm (
  VOID
  )
{
  EFI_TPM2_ACPI_TABLE  *Table;
  UINT64              Command;
  UINT64              Response;

  if (mControlArea != 0) {
    return EFI_SUCCESS;
  }

  Table = (VOID *)EfiLocateFirstAcpiTable (EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE);
  if ((Table == NULL) || (Table->Header.Length < sizeof (*Table)) ||
      (Table->StartMethod != EFI_TPM2_ACPI_TABLE_START_METHOD_ACPI) ||
      (Table->AddressOfControlArea == 0) ||
      (Table->AddressOfControlArea > MAX_UINTN - sizeof (EFI_TPM2_ACPI_CONTROL_AREA)) ||
      ((Table->AddressOfControlArea & (sizeof (UINT32) - 1)) != 0))
  {
    return EFI_NOT_FOUND;
  }

  mControlArea  = (UINTN)Table->AddressOfControlArea;
  Command       = ReadBufferAddress (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, Command));
  Response      = ReadBufferAddress (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, Response));
  mCommandSize  = MmioRead32 (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, CommandSize));
  mResponseSize = MmioRead32 (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, ResponseSize));
  if ((Command == 0) || (Response == 0) ||
      (mCommandSize < sizeof (TPM2_COMMAND_HEADER)) ||
      (mResponseSize < sizeof (TPM2_RESPONSE_HEADER)) ||
      (Command > MAX_UINTN - mCommandSize) || (Response > MAX_UINTN - mResponseSize))
  {
    mControlArea = 0;
    return EFI_DEVICE_ERROR;
  }

  mCommand  = (UINTN)Command;
  mResponse = (UINTN)Response;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
AmdFtpmSubmitCommand (
  IN UINT32      InputParameterBlockSize,
  IN UINT8       *InputParameterBlock,
  IN OUT UINT32  *OutputParameterBlockSize,
  IN UINT8       *OutputParameterBlock
  )
{
  EFI_STATUS  Status;
  UINT32      ResponseSize;
  UINT32      ReturnedSize;

  if ((InputParameterBlock == NULL) || (OutputParameterBlockSize == NULL) ||
      (OutputParameterBlock == NULL) || (InputParameterBlockSize < sizeof (TPM2_COMMAND_HEADER)))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = AmdFtpmRequestUseTpm ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (InputParameterBlockSize > mCommandSize) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Status = WaitForCompletion (250000);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  CopyMem ((VOID *)mCommand, InputParameterBlock, InputParameterBlockSize);
  ZeroMem ((VOID *)mResponse, mResponseSize);
  MmioWrite32 (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, ResponseSize), mResponseSize);
  MemoryFence ();
  MmioWrite8 (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, Start), BIT0);
  Status = WaitForCompletion (3500000);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((MmioRead32 (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, Error)) & BIT0) != 0) {
    return EFI_DEVICE_ERROR;
  }

  ReturnedSize = MmioRead32 (mControlArea + OFFSET_OF (EFI_TPM2_ACPI_CONTROL_AREA, ResponseSize));
  if ((ReturnedSize < sizeof (TPM2_RESPONSE_HEADER)) || (ReturnedSize > mResponseSize)) {
    return EFI_DEVICE_ERROR;
  }

  MemoryFence ();
  ResponseSize = SwapBytes32 (ReadUnaligned32 ((UINT32 *)(mResponse + OFFSET_OF (TPM2_RESPONSE_HEADER, paramSize))));
  if ((ResponseSize < sizeof (TPM2_RESPONSE_HEADER)) || (ResponseSize > ReturnedSize)) {
    return EFI_DEVICE_ERROR;
  }

  if (ResponseSize > *OutputParameterBlockSize) {
    *OutputParameterBlockSize = ResponseSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (OutputParameterBlock, (VOID *)mResponse, ResponseSize);
  *OutputParameterBlockSize = ResponseSize;
  return EFI_SUCCESS;
}

STATIC TPM2_DEVICE_INTERFACE  mAmdFtpm = {
  TPM_DEVICE_INTERFACE_TPM20_DTPM,
  AmdFtpmSubmitCommand,
  AmdFtpmRequestUseTpm
};

EFI_STATUS
EFIAPI
AmdFtpmConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = Tpm2RegisterTpm2DeviceLib (&mAmdFtpm);
  return (Status == EFI_UNSUPPORTED) ? EFI_SUCCESS : Status;
}
