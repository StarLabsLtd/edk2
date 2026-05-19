/** @file
  Supply Phoenix VBIOS from the payload FV to the AMD GPU for external GOP.
**/

#include <PiDxe.h>
#include <IndustryStandard/Pci22.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/PciIo.h>
#include <Protocol/PciPlatform.h>

#define ATI_VGA_VID  0x1002

STATIC
BOOLEAN
IsAmdDisplayPciIo (
  IN EFI_PCI_IO_PROTOCOL  *PciIo
  )
{
  EFI_STATUS  Status;
  PCI_TYPE00  Pci;

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

  return IS_PCI_DISPLAY (&Pci) || IS_PCI_OLD_VGA (&Pci);
}

STATIC
EFI_STATUS
LoadVbiosFromFirmwareVolume (
  OUT VOID   **RomImage,
  OUT UINTN  *RomSize
  )
{
  EFI_STATUS                     Status;
  UINTN                          Index;
  UINTN                          HandleCount;
  EFI_HANDLE                     *Handles;
  EFI_FIRMWARE_VOLUME2_PROTOCOL  *Fv;
  UINT8                          *Section;
  UINTN                          SectionSize;
  UINT32                         AuthStatus;
  EFI_PHYSICAL_ADDRESS           RomAddress;
  UINTN                          Pages;

  Section     = NULL;
  SectionSize = 0;
  Handles     = NULL;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiFirmwareVolume2ProtocolGuid,
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
                    &gEfiFirmwareVolume2ProtocolGuid,
                    (VOID **)&Fv
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    Section     = NULL;
    SectionSize = 0;
    Status      = Fv->ReadSection (
                       Fv,
                       &gAmdPhoenixVbiosRomSectionGuid,
                       EFI_SECTION_RAW,
                       0,
                       (VOID **)&Section,
                       &SectionSize,
                       &AuthStatus
                       );
    if (!EFI_ERROR (Status) && (Section != NULL) && (SectionSize > 0)) {
      Pages       = EFI_SIZE_TO_PAGES (SectionSize);
      RomAddress  = 0;
      Status      = gBS->AllocatePages (
                           AllocateAnyPages,
                           EfiBootServicesCode,
                           Pages,
                           &RomAddress
                           );
      if (EFI_ERROR (Status)) {
        if (Section != NULL) {
          gBS->FreePool (Section);
        }

        break;
      }

      CopyMem ((VOID *)(UINTN)RomAddress, Section, SectionSize);
      gBS->FreePool (Section);
      Section = NULL;

      *RomImage = (VOID *)(UINTN)RomAddress;
      *RomSize  = SectionSize;
      Status    = EFI_SUCCESS;
      break;
    }
  }

  if (Handles != NULL) {
    gBS->FreePool (Handles);
  }

  return Status;
}

STATIC
EFI_STATUS
EFIAPI
AmdGopPciPlatformNotify (
  IN EFI_PCI_PLATFORM_PROTOCOL                      *This,
  IN EFI_HANDLE                                     HostBridge,
  IN EFI_PCI_HOST_BRIDGE_RESOURCE_ALLOCATION_PHASE  Phase,
  IN EFI_PCI_EXECUTION_PHASE                        ExecPhase
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
AmdGopPciPlatformPrepController (
  IN EFI_PCI_PLATFORM_PROTOCOL                     *This,
  IN EFI_HANDLE                                    HostBridge,
  IN EFI_HANDLE                                    RootBridge,
  IN EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_PCI_ADDRESS   PciAddress,
  IN EFI_PCI_CONTROLLER_RESOURCE_ALLOCATION_PHASE  Phase,
  IN EFI_PCI_EXECUTION_PHASE                       ExecPhase
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
AmdGopPciPlatformGetPciRom (
  IN  CONST EFI_PCI_PLATFORM_PROTOCOL  *This,
  IN        EFI_HANDLE                 PciHandle,
  OUT       VOID                       **RomImage,
  OUT       UINTN                      *RomSize
  )
{
  EFI_STATUS           Status;
  EFI_PCI_IO_PROTOCOL  *PciIo;

  if ((RomImage == NULL) || (RomSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *RomImage = NULL;
  *RomSize  = 0;

  Status = gBS->HandleProtocol (
                  PciHandle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **)&PciIo
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!IsAmdDisplayPciIo (PciIo)) {
    return EFI_NOT_FOUND;
  }

  Status = LoadVbiosFromFirmwareVolume (RomImage, RomSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "AmdGopPciPlatform: VBIOS FV load failed: %r\n", Status));
    return Status;
  }

  DEBUG ((
    DEBUG_INFO,
    "AmdGopPciPlatform: provided VBIOS (%u bytes) to AMD display\n",
    (UINT32)*RomSize
    ));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
AmdGopPciPlatformGetPlatformPolicy (
  IN  CONST EFI_PCI_PLATFORM_PROTOCOL  *This,
  OUT       EFI_PCI_PLATFORM_POLICY    *Policy
  )
{
  if (Policy == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Policy = EFI_RESERVE_ISA_IO_NO_ALIAS | EFI_RESERVE_VGA_IO_NO_ALIAS;
  return EFI_SUCCESS;
}

STATIC EFI_PCI_PLATFORM_PROTOCOL  mAmdGopPciPlatform = {
  AmdGopPciPlatformNotify,
  AmdGopPciPlatformPrepController,
  AmdGopPciPlatformGetPlatformPolicy,
  AmdGopPciPlatformGetPciRom
};

EFI_STATUS
EFIAPI
AmdGopPciPlatformEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HANDLE  Handle;

  Handle = NULL;
  return gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiPciPlatformProtocolGuid,
                  &mAmdGopPciPlatform,
                  NULL
                  );
}
