/** @file
  Bind the fixed Standalone MM core to coreboot's SMM dispatcher.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>

#include <Guid/CorebootVariableService.h>
#include <Guid/EventGroup.h>
#include <Guid/SmmVariableCommon.h>
#include <Library/HobLib.h>
#include <Library/MmServicesTableLib.h>
#include <Protocol/MmConfiguration.h>
#include <Protocol/SmmVariable.h>

STATIC COREBOOT_VARIABLE_REGISTER_MM_ENTRY  mRegisterMmEntry;
STATIC EFI_HANDLE                           mExternalImageStartedHandle;

STATIC
EFI_STATUS
EFIAPI
ExternalImageStarted (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_HANDLE  Handle;
  EFI_STATUS  Status;

  if ((CommBuffer == NULL) || (CommBufferSize == NULL) ||
      (*CommBufferSize != sizeof (UINT8)) || (*(UINT8 *)CommBuffer != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (mExternalImageStartedHandle != NULL) {
    return EFI_SUCCESS;
  }

  Handle = NULL;
  Status = gMmst->MmInstallProtocolInterface (
                    &Handle,
                    &gEfiEventExternalImageStartGuid,
                    EFI_NATIVE_INTERFACE,
                    NULL
                    );
  if (!EFI_ERROR (Status)) {
    mExternalImageStartedHandle = Handle;
  }

  return Status;
}

STATIC
EFI_STATUS
EFIAPI
VariableServiceReady (
  IN     EFI_HANDLE  DispatchHandle,
  IN     CONST VOID  *Context         OPTIONAL,
  IN OUT VOID        *CommBuffer      OPTIONAL,
  IN OUT UINTN       *CommBufferSize  OPTIONAL
  )
{
  EFI_STATUS  Status;
  VOID        *Protocol;

  if ((CommBuffer == NULL) || (CommBufferSize == NULL) ||
      (*CommBufferSize != sizeof (UINT8)) || (*(UINT8 *)CommBuffer != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = gMmst->MmLocateProtocol (
                    &gEfiSmmVariableProtocolGuid,
                    NULL,
                    &Protocol
                    );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return gMmst->MmLocateProtocol (
                  &gSmmVariableWriteGuid,
                  NULL,
                  &Protocol
                  );
}

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
  EFI_HANDLE                      ReadyHandler;
  EFI_HANDLE                      ExternalImageHandler;
  EFI_STATUS                      Status;

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

  Status = gMmst->MmiHandlerRegister (
                    VariableServiceReady,
                    &gCorebootVariableServiceReadyGuid,
                    &ReadyHandler
                    );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gMmst->MmiHandlerRegister (
                    ExternalImageStarted,
                    &gEfiEventExternalImageStartGuid,
                    &ExternalImageHandler
                    );
  if (EFI_ERROR (Status)) {
    gMmst->MmiHandlerUnRegister (ReadyHandler);
    return Status;
  }

  Handle = NULL;
  Status = gMmst->MmInstallProtocolInterface (
                    &Handle,
                    &gEfiMmConfigurationProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mMmConfiguration
                    );
  if (EFI_ERROR (Status)) {
    gMmst->MmiHandlerUnRegister (ExternalImageHandler);
    gMmst->MmiHandlerUnRegister (ReadyHandler);
  }

  return Status;
}
