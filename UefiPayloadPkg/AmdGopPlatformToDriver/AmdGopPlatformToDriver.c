/** @file
  AMD GOP platform-to-driver agent: supplies display routing policy for any AMD
  PCI display device (vendor 0x1002).
**/

#include <Library/AmdPlatformGOPPolicy.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/Pci22.h>
#include <Protocol/PciIo.h>

STATIC PLATFORM_TO_AMDGOP_CONFIGURATION  mConfigCommonDefault = {
  1,
  (UINT32)DisplayDeviceLCD,
  (UINT32)DisplayDeviceDFP1,
  (UINT32)DisplayDeviceDFP2,
  (UINT32)DisplayDeviceDFP3,
  (UINT32)DisplayDeviceDFP4,
  (UINT32)DisplayDeviceCRT,
  { 0, 0, 0, 0, 0, 0 },
  0,
  { 0, 0, 0 }
};

STATIC PLATFORM_TO_AMDGOP_CONFIGURATION1  mConfigLcd = {
  2,
  0,
  0x80,
  0,
  0,
  0,
  0,
  0, 0, 0, 0, 0, 0, 0,
  { 0, 0, 0, 0, 0, 0, 0 },
  0,
  0,
  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

STATIC
BOOLEAN
IsAmdDisplayDevice (
  IN EFI_HANDLE  ControllerHandle
  )
{
  EFI_STATUS           Status;
  EFI_PCI_IO_PROTOCOL  *PciIo;
  PCI_TYPE00           Pci;

  Status = gBS->HandleProtocol (
                  ControllerHandle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **)&PciIo
                  );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = PciIo->Pci.Read (
                    PciIo,
                    EfiPciIoWidthUint32,
                    0,
                    sizeof (Pci) / sizeof (UINT32),
                    &Pci
                    );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  if (Pci.Hdr.VendorId != ATI_VGA_VID) {
    return FALSE;
  }

  return IS_PCI_DISPLAY (&Pci) ||
         IS_PCI_OLD_VGA (&Pci);
}

STATIC
EFI_STATUS
EFIAPI
ConfigurationSupported (
  IN AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL  *This,
  IN EFI_HANDLE                             ControllerHandle,
  IN EFI_HANDLE                             ChildHandle OPTIONAL
  )
{
  if (IsAmdDisplayDevice (ControllerHandle)) {
    DEBUG ((DEBUG_INFO, "AmdGopPlatformToDriver: AMD display controller\n"));
    return EFI_SUCCESS;
  }

  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
ConfigurationQuery (
  IN AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL  *This,
  IN EFI_HANDLE                             ControllerHandle,
  IN EFI_HANDLE                             ChildHandle OPTIONAL,
  IN UINTN                                  *Instance,
  OUT EFI_GUID                              **ParameterTypeGuid,
  OUT VOID                                  **ParameterBlock,
  OUT UINTN                                 *ParameterBlockSize
  )
{
  if ((ControllerHandle == NULL) || (Instance == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (!IsAmdDisplayDevice (ControllerHandle)) {
    return EFI_NOT_FOUND;
  }

  *ParameterTypeGuid = &gEfiPlatformToAmdGopConfigurationGuid;

  if (*Instance == 0) {
    *ParameterBlockSize = sizeof (PLATFORM_TO_AMDGOP_CONFIGURATION);
    *ParameterBlock     = &mConfigCommonDefault;
    return EFI_SUCCESS;
  }

  if (*Instance == 1) {
    *ParameterBlockSize = sizeof (PLATFORM_TO_AMDGOP_CONFIGURATION1);
    *ParameterBlock     = &mConfigLcd;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
EFIAPI
ConfigurationResponse (
  IN AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL  *This,
  IN EFI_HANDLE                             ControllerHandle,
  IN EFI_HANDLE                             ChildHandle OPTIONAL,
  IN UINTN                                  *Instance,
  IN EFI_GUID                               *ParameterTypeGuid,
  IN VOID                                   *ParameterBlock,
  IN UINTN                                  ParameterBlockSize,
  IN EFI_PLATFORM_CONFIGURATION_ACTION      ConfigurationAction
  )
{
  return EFI_SUCCESS;
}

STATIC AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL  mAgent = {
  ConfigurationSupported,
  ConfigurationQuery,
  ConfigurationResponse
};

EFI_STATUS
EFIAPI
AmdGopPlatformToDriverEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HANDLE  Handle;

  Handle = NULL;
  return gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gAmiPlatformToDriverAgentProtocolGuid,
                  &mAgent,
                  NULL
                  );
}
