/** @file
  AMD GOP platform-to-driver configuration: supplies display routing policy for the
  integrated GPU supported by the bundled Phoenix VBIOS.

  Copyright (c) 2026, Matt DeVillier. All rights reserved.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/AmdPlatformGOPPolicy.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/Pci22.h>
#include <Protocol/PciIo.h>

STATIC PLATFORM_TO_AMDGOP_CONFIGURATION  mConfigCommonDefault = {
  .Revision               = 1,
  .Priority1ActiveDisplay = DisplayDeviceLCD,
  .Priority2ActiveDisplay = DisplayDeviceDFP1,
  .Priority3ActiveDisplay = DisplayDeviceDFP2,
  .Priority4ActiveDisplay = DisplayDeviceDFP3,
  .Priority5ActiveDisplay = DisplayDeviceDFP4,
  .Priority6ActiveDisplay = DisplayDeviceCRT
};

STATIC PLATFORM_TO_AMDGOP_CONFIGURATION1  mConfigLcd = {
  .Revision            = 2,
  .LCD_BootUp_BL_Level = 0x80
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

  if ((Pci.Hdr.VendorId != ATI_VGA_VID) ||
      (Pci.Hdr.DeviceId != AMD_PHOENIX_GOP_DEVICE_ID))
  {
    return FALSE;
  }

  return IS_PCI_DISPLAY (&Pci) ||
         IS_PCI_OLD_VGA (&Pci);
}

STATIC
EFI_STATUS
EFIAPI
ConfigurationQuery (
  IN CONST EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL  *This,
  IN CONST EFI_HANDLE                                     ControllerHandle,
  IN CONST EFI_HANDLE                                     ChildHandle,
  IN CONST UINTN                                          *Instance,
  OUT EFI_GUID                                            **ParameterTypeGuid,
  OUT VOID                                                **ParameterBlock,
  OUT UINTN                                               *ParameterBlockSize
  )
{
  if ((ControllerHandle == NULL) || (Instance == NULL) ||
      (ParameterTypeGuid == NULL) || (ParameterBlock == NULL) ||
      (ParameterBlockSize == NULL))
  {
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
  IN CONST EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL  *This,
  IN CONST EFI_HANDLE                                     ControllerHandle,
  IN CONST EFI_HANDLE                                     ChildHandle,
  IN CONST UINTN                                          *Instance,
  IN CONST EFI_GUID                                       *ParameterTypeGuid,
  IN CONST VOID                                           *ParameterBlock,
  IN CONST UINTN                                          ParameterBlockSize,
  IN CONST EFI_PLATFORM_CONFIGURATION_ACTION              ConfigurationAction
  )
{
  if ((ControllerHandle == NULL) || (Instance == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  return IsAmdDisplayDevice (ControllerHandle) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

STATIC EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL  mConfiguration = {
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
                  &gEfiPlatformToDriverConfigurationProtocolGuid,
                  &mConfiguration,
                  NULL
                  );
}
