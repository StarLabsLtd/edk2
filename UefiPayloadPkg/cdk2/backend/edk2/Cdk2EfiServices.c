/** @file

  EDK II service callbacks for the native cdk2 entry path.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2NativeServices.h>

#include "Cdk2EfiBackend.h"
#include "Cdk2EfiHobs.h"

EFI_MEMORY_TYPE_INFORMATION  mDefaultMemoryTypeInformation[] = {
  { EfiACPIReclaimMemory,   FixedPcdGet32 (PcdMemoryTypeEfiACPIReclaimMemory)   },
  { EfiACPIMemoryNVS,       FixedPcdGet32 (PcdMemoryTypeEfiACPIMemoryNVS)       },
  { EfiReservedMemoryType,  FixedPcdGet32 (PcdMemoryTypeEfiReservedMemoryType)  },
  { EfiRuntimeServicesData, FixedPcdGet32 (PcdMemoryTypeEfiRuntimeServicesData) },
  { EfiRuntimeServicesCode, FixedPcdGet32 (PcdMemoryTypeEfiRuntimeServicesCode) },
  { EfiMaxMemoryType,       0                                                   }
};

EFI_STATUS
EFIAPI
Cdk2EfiPopulateHobs (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_STATUS                  Status;
  EFI_HOB_HANDOFF_INFO_TABLE  *HobInfo;

  if (Context == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2EfiBuildHobFromBl ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Cdk2EfiBuildHobFromBl Status = %r\n", Status));
    return Status;
  }

  Cdk2EfiBuildGenericHob ();

  HobInfo = (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList;
  BuildMemoryTypeInformationHob (
    mDefaultMemoryTypeInformation,
    sizeof (mDefaultMemoryTypeInformation),
    HobInfo->BootMode
    );
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2EfiBuildSerialHob (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_STATUS                          Status;
  SERIAL_PORT_INFO                    SerialPortInfo;
  UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  *UniversalSerialPort;

  if (Context == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = ParseSerialInfo (&SerialPortInfo);
  if (EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  UniversalSerialPort = BuildGuidHob (
                          &gUniversalPayloadSerialPortInfoGuid,
                          sizeof (UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO)
                          );
  ASSERT (UniversalSerialPort != NULL);
  if (UniversalSerialPort == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  UniversalSerialPort->Header.Revision = UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_REVISION;
  UniversalSerialPort->Header.Length   = sizeof (UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO);
  UniversalSerialPort->UseMmio         = (SerialPortInfo.Type == 1) ? FALSE : TRUE;
  UniversalSerialPort->RegisterBase    = SerialPortInfo.BaseAddr;
  UniversalSerialPort->BaudRate        = SerialPortInfo.Baud;
  UniversalSerialPort->RegisterStride  = (UINT8)SerialPortInfo.RegWidth;

  // Set PCD here (vs in PlatformHookLib.c) to avoid adding a new field to the
  // UniversalSerialPort structure.
  if (SerialPortInfo.InputHertz > 0) {
    Status = PcdSet32S (PcdSerialClockRate, SerialPortInfo.InputHertz);
    if (RETURN_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to set PcdSerialClockRate; Status = %r\n", Status));
      return Status;
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2EfiApplyBootMode (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *HobInfo;

  if (Context == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  HobInfo = (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList;
  if ((GetFirstHob (EFI_HOB_TYPE_UEFI_CAPSULE) != NULL) || ParseIsDiskCapsulesBoot ()) {
    HobInfo->BootMode = BOOT_ON_FLASH_UPDATE;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2EfiInitializeLibraries (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ProcessLibraryConstructorList ();
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2EfiSetBootloaderParameter (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return PcdSet64S (PcdBootloaderParameter, Context->BootloaderParameter);
}

EFI_STATUS
EFIAPI
Cdk2EfiFindHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT UINTN                  *HobMemBase
  )
{
  if (Context == NULL || HobMemBase == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return ParseMemoryInfo (Cdk2EfiFindFreeMemForHobCallback, HobMemBase);
}

EFI_STATUS
EFIAPI
Cdk2EfiInitializeFloatingPoint (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  InitializeFloatingPointUnits ();
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2EfiMaskLegacyInterrupts (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  IoWrite8 (LEGACY_8259_MASK_REGISTER_MASTER, 0xFF);
  IoWrite8 (LEGACY_8259_MASK_REGISTER_SLAVE, 0xFF);
  return EFI_SUCCESS;
}
