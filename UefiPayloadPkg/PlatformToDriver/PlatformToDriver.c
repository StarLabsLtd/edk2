/** @file
  EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL dispatcher for platform agents.
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/AmiPlatformToDriverAgent.h>
#include <Protocol/PlatformToDriverConfiguration.h>

STATIC EFI_HANDLE                               mCurrentControllerHandle;
STATIC AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL    *mCurrentAgent;

STATIC
EFI_STATUS
GetAgent (
  IN EFI_HANDLE  ControllerHandle,
  IN EFI_HANDLE  ChildHandle
  )
{
  EFI_STATUS  Status;
  EFI_HANDLE  *Handles;
  UINTN       HandleCount;
  UINTN       Index;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gAmiPlatformToDriverAgentProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    Handles[Index],
                    &gAmiPlatformToDriverAgentProtocolGuid,
                    (VOID **)&mCurrentAgent
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = mCurrentAgent->Supported (
                              mCurrentAgent,
                              ControllerHandle,
                              ChildHandle
                              );
    if (!EFI_ERROR (Status)) {
      gBS->FreePool (Handles);
      return EFI_SUCCESS;
    }
  }

  gBS->FreePool (Handles);
  mCurrentAgent = NULL;
  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
EFIAPI
PlatformToDriverConfigurationQuery (
  IN CONST EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL  *This,
  IN CONST EFI_HANDLE                                     ControllerHandle,
  IN CONST EFI_HANDLE                                     ChildHandle,
  IN CONST UINTN                                          *Instance,
  OUT EFI_GUID                                            **ParameterTypeGuid,
  OUT VOID                                                **ParameterBlock,
  OUT UINTN                                               *ParameterBlockSize
  )
{
  EFI_STATUS  Status;

  if ((ControllerHandle == NULL) || (Instance == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (ControllerHandle != mCurrentControllerHandle) {
    Status = GetAgent (ControllerHandle, ChildHandle);
    if (EFI_ERROR (Status)) {
      mCurrentControllerHandle = NULL;
      return EFI_NOT_FOUND;
    }

    mCurrentControllerHandle = ControllerHandle;
  }

  return mCurrentAgent->Query (
                          mCurrentAgent,
                          ControllerHandle,
                          ChildHandle,
                          (UINTN *)Instance,
                          ParameterTypeGuid,
                          ParameterBlock,
                          ParameterBlockSize
                          );
}

STATIC
EFI_STATUS
EFIAPI
PlatformToDriverConfigurationResponse (
  IN CONST EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL  *This,
  IN CONST EFI_HANDLE                                     ControllerHandle,
  IN CONST EFI_HANDLE                                     ChildHandle,
  IN CONST UINTN                                          *Instance,
  IN CONST EFI_GUID                                       *ParameterTypeGuid,
  IN CONST VOID                                           *ParameterBlock,
  IN CONST UINTN                                          ParameterBlockSize,
  IN CONST EFI_PLATFORM_CONFIGURATION_ACTION                ConfigurationAction
  )
{
  if ((ControllerHandle == NULL) || (Instance == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((ControllerHandle != mCurrentControllerHandle) || (mCurrentAgent == NULL)) {
    return EFI_NOT_FOUND;
  }

  return mCurrentAgent->Response (
                          mCurrentAgent,
                          ControllerHandle,
                          ChildHandle,
                          (UINTN *)Instance,
                          (EFI_GUID *)ParameterTypeGuid,
                          (VOID *)ParameterBlock,
                          ParameterBlockSize,
                          (UINT32)ConfigurationAction
                          );
}

STATIC EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL  mPlatformToDriver = {
  PlatformToDriverConfigurationQuery,
  PlatformToDriverConfigurationResponse
};

EFI_STATUS
EFIAPI
PlatformToDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HANDLE  Handle;

  mCurrentControllerHandle = NULL;
  mCurrentAgent            = NULL;
  Handle                   = NULL;

  return gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiPlatformToDriverConfigurationProtocolGuid,
                  &mPlatformToDriver,
                  NULL
                  );
}
