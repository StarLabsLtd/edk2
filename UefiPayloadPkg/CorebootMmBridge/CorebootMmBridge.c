/** @file
  Bind the fixed Standalone MM core to coreboot's SMM dispatcher.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>

#include <Guid/CorebootVariableService.h>
#include <Library/HobLib.h>
#include <Library/MmServicesTableLib.h>
#include <Protocol/MmConfiguration.h>

STATIC COREBOOT_VARIABLE_REGISTER_MM_ENTRY  mRegisterMmEntry;

STATIC
EFI_STATUS
EFIAPI
RegisterMmEntry (
  IN CONST EFI_MM_CONFIGURATION_PROTOCOL  *This,
  IN EFI_MM_ENTRY_POINT                   EntryPoint
  )
{
  COREBOOT_VARIABLE_REGISTER_MM_ENTRY  Register;

  if ((EntryPoint == NULL) || (mRegisterMmEntry == NULL) ||
      ((UINTN)EntryPoint > MAX_UINT32))
  {
    return EFI_INVALID_PARAMETER;
  }

  Register         = mRegisterMmEntry;
  mRegisterMmEntry = NULL;
  return (Register ((UINT32)(UINTN)EntryPoint) == COREBOOT_VARIABLE_REGISTER_SUCCESS) ?
         EFI_SUCCESS : EFI_DEVICE_ERROR;
}

STATIC EFI_MM_RESERVED_MMRAM_REGION  mReservedRegions[] = {
  { 0, 0 }
};

STATIC EFI_MM_CONFIGURATION_PROTOCOL  mMmConfiguration = {
  mReservedRegions,
  RegisterMmEntry
};

EFI_STATUS
EFIAPI
CorebootMmBridgeEntryPoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  COREBOOT_VARIABLE_SERVICE_INFO  *ServiceInfo;
  EFI_HOB_GUID_TYPE               *Hob;
  EFI_HANDLE                      Handle;

  Hob = GetFirstGuidHob (&gCorebootVariableServiceInfoGuid);
  if ((Hob == NULL) ||
      (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*ServiceInfo)))
  {
    return EFI_NOT_FOUND;
  }

  ServiceInfo = GET_GUID_HOB_DATA (Hob);
  if ((ServiceInfo->Revision != COREBOOT_VARIABLE_SERVICE_REVISION) ||
      (ServiceInfo->Size != sizeof (*ServiceInfo)) ||
      (ServiceInfo->Reserved != 0) || (ServiceInfo->RegisterMmEntry == 0) ||
      (ServiceInfo->CommunicationBuffer == 0) ||
      (ServiceInfo->CommunicationBufferSize < sizeof (COREBOOT_VARIABLE_SERVICE_BUFFER)))
  {
    return EFI_INVALID_PARAMETER;
  }

  mRegisterMmEntry = (COREBOOT_VARIABLE_REGISTER_MM_ENTRY)(UINTN)ServiceInfo->RegisterMmEntry;

  Handle = NULL;
  return gMmst->MmInstallProtocolInterface (
                  &Handle,
                  &gEfiMmConfigurationProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMmConfiguration
                  );
}
