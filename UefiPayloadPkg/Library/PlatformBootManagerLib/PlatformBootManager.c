/** @file
  This file include all platform action which can be customized
  by IBV/OEM.

Copyright (c) 2015 - 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PlatformBootManager.h"
#include "PlatformConsole.h"
#include "PlatformLinuxEfiBoot.h"
#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/EventGroup.h>
#include <Guid/GlobalVariable.h>
#include <Guid/ImageAuthentication.h>
#include <Guid/TcgPhysicalPresenceGuid.h>
#include <IndustryStandard/Pci.h>
#include <IndustryStandard/QemuTpm.h>
#include <IndustryStandard/Usb.h>
#include <Library/BmpSupportLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/Tcg2PhysicalPresenceLib.h>
#include <Protocol/BatteryStatus.h>
#include <Protocol/EsrtManagement.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/PciIo.h>
#include <Protocol/PlatformBootManager.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/Tcg2Protocol.h>

#define PLATFORM_USB_MASS_STORAGE_CLASS  0x08
#define PLATFORM_REMOVABLE_REFRESH_RETRIES   10
#define PLATFORM_REMOVABLE_REFRESH_STALL_US  100000

typedef struct {
  USB_CLASS_DEVICE_PATH       UsbClass;
  EFI_DEVICE_PATH_PROTOCOL    End;
} USB_MASS_STORAGE_DEVICE_PATH;

typedef enum {
  PlatformBootDiscoveryInternalStorage,
  PlatformBootDiscoveryUsbMassStorage,
  PlatformBootDiscoveryRemovableMedia,
  PlatformBootDiscoveryNetwork
} PLATFORM_BOOT_DISCOVERY_TYPE;

STATIC USB_MASS_STORAGE_DEVICE_PATH  mUsbMassStorageDevicePath = {
  {
    {
      MESSAGING_DEVICE_PATH,
      MSG_USB_CLASS_DP,
      {
        (UINT8)(sizeof (USB_CLASS_DEVICE_PATH)),
        (UINT8)(sizeof (USB_CLASS_DEVICE_PATH) >> 8)
      }
    },
    0xffff,
    0xffff,
    PLATFORM_USB_MASS_STORAGE_CLASS,
    0xff,
    0xff
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { END_DEVICE_PATH_LENGTH, 0 }
  }
};

#define LOW_BATTERY_BOOT_TIMEOUT  10
#define BOOT_UI_HIDPI_HORIZONTAL_RESOLUTION  1920
#define BOOT_UI_HIDPI_VERTICAL_RESOLUTION    1080

STATIC EFI_GUID  mLowBatteryLogoFileGuid = {
  0xbe6e1243, 0x682c, 0x4186, { 0x81, 0x51, 0x44, 0x8d, 0x48, 0xaf, 0xe3, 0x41 }
};

STATIC BOOLEAN  mLowBatteryBootGuardActive;
STATIC BOOLEAN  mLowBatteryBootLogoShown;
STATIC EFI_HANDLE  mCdk2PlatformBootManagerHandle;

STATIC
EFI_STATUS
Cdk2GetUint8Variable (
  IN  CHAR16    *Name,
  IN  EFI_GUID  *Guid,
  OUT UINT8     *Value
  )
{
  EFI_STATUS  Status;
  UINT32      Attributes;
  UINTN       Size;

  Size = sizeof (*Value);
  Status = gRT->GetVariable (
                  Name,
                  Guid,
                  &Attributes,
                  &Size,
                  Value
                  );
  if (!EFI_ERROR (Status) && (Size != sizeof (*Value))) {
    return EFI_SECURITY_VIOLATION;
  }

  return Status;
}

STATIC
BOOLEAN
Cdk2IsTpmPpiAddressUsable (
  IN CONST TCG_PHYSICAL_PRESENCE_INFO  *PresenceInfo
  )
{
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR  Descriptor;
  EFI_PHYSICAL_ADDRESS             PpiAddress;
  EFI_PHYSICAL_ADDRESS             PpiEnd;
  EFI_STATUS                       Status;

  PpiAddress = PresenceInfo->PpiAddress;
  PpiEnd     = PpiAddress + sizeof (QEMU_TPM_PPI) - 1;
  if ((PpiAddress > PpiEnd) ||
      ((PpiAddress & ~(EFI_PHYSICAL_ADDRESS)EFI_PAGE_MASK) !=
       (PpiEnd & ~(EFI_PHYSICAL_ADDRESS)EFI_PAGE_MASK)))
  {
    return FALSE;
  }

  Status = gDS->GetMemorySpaceDescriptor (PpiAddress, &Descriptor);
  if (EFI_ERROR (Status)) {
    return (BOOLEAN)(Status == EFI_NOT_FOUND);
  }

  return (BOOLEAN)(
                  (Descriptor.GcdMemoryType == EfiGcdMemoryTypeReserved) ||
                  (Descriptor.GcdMemoryType == EfiGcdMemoryTypeSystemMemory)
                  );
}

STATIC
BOOLEAN
Cdk2HasTpm2PhysicalPresenceHob (
  VOID
  )
{
  EFI_HOB_GUID_TYPE           *GuidHob;
  TCG_PHYSICAL_PRESENCE_INFO  *PresenceInfo;

  GuidHob = GetFirstGuidHob (&gEfiTcgPhysicalPresenceInfoHobGuid);
  if (GuidHob == NULL) {
    return FALSE;
  }

  if (GET_GUID_HOB_DATA_SIZE (GuidHob) < sizeof (*PresenceInfo)) {
    return FALSE;
  }

  PresenceInfo = (TCG_PHYSICAL_PRESENCE_INFO *)GET_GUID_HOB_DATA (GuidHob);
  if ((PresenceInfo->PpiAddress == 0) ||
      (PresenceInfo->PpiAddress == MAX_UINT32))
  {
    return FALSE;
  }

  if (!Cdk2IsTpmPpiAddressUsable (PresenceInfo)) {
    return FALSE;
  }

  if (PresenceInfo->TpmVersion != UEFIPAYLOAD_TPM_VERSION_2) {
    return FALSE;
  }

  if ((PresenceInfo->PpiVersion != UEFIPAYLOAD_TPM_PPI_VERSION_NONE) &&
      (PresenceInfo->PpiVersion != UEFIPAYLOAD_TPM_PPI_VERSION_1_30))
  {
    return FALSE;
  }

  return TRUE;
}

STATIC
EFI_STATUS
Cdk2ValidateAntiTamperBootPolicy (
  VOID
  )
{
  EFI_TCG2_BOOT_SERVICE_CAPABILITY  Capability;
  EFI_TCG2_PROTOCOL                 *Tcg2;
  EFI_STATUS                        Status;
  UINT32                            ActivePcrBanks;
  UINT8                             CustomMode;
  UINT8                             SecureBoot;
  UINT8                             SecureBootEnable;
  UINT8                             SetupMode;
  UINT8                             VendorKeys;

  if (!FixedPcdGetBool (PcdCdk2AntiTamperBoot)) {
    return EFI_SUCCESS;
  }

  Status = Cdk2GetUint8Variable (
             EFI_SETUP_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &SetupMode
             );
  if (EFI_ERROR (Status) || (SetupMode != USER_MODE)) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = Cdk2GetUint8Variable (
             EFI_SECURE_BOOT_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &SecureBoot
             );
  if (EFI_ERROR (Status) || (SecureBoot != SECURE_BOOT_MODE_ENABLE)) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = Cdk2GetUint8Variable (
             EFI_SECURE_BOOT_ENABLE_NAME,
             &gEfiSecureBootEnableDisableGuid,
             &SecureBootEnable
             );
  if (EFI_ERROR (Status) || (SecureBootEnable != SECURE_BOOT_ENABLE)) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = Cdk2GetUint8Variable (
             EFI_CUSTOM_MODE_NAME,
             &gEfiCustomModeEnableGuid,
             &CustomMode
             );
  if (EFI_ERROR (Status) || (CustomMode != STANDARD_SECURE_BOOT_MODE)) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = Cdk2GetUint8Variable (
             EFI_VENDOR_KEYS_VARIABLE_NAME,
             &gEfiGlobalVariableGuid,
             &VendorKeys
             );
  if (EFI_ERROR (Status) || (VendorKeys != 0)) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2);
  if (EFI_ERROR (Status)) {
    return EFI_SECURITY_VIOLATION;
  }

  ZeroMem (&Capability, sizeof (Capability));
  Capability.Size = sizeof (Capability);
  Status = Tcg2->GetCapability (Tcg2, &Capability);
  if (EFI_ERROR (Status) || !Capability.TPMPresentFlag) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = Tcg2->GetActivePcrBanks (Tcg2, &ActivePcrBanks);
  if (EFI_ERROR (Status) || ((ActivePcrBanks & EFI_TCG2_BOOT_HASH_ALG_SHA256) == 0)) {
    return EFI_SECURITY_VIOLATION;
  }

  if (FixedPcdGetBool (PcdCdk2AntiTamperRequireTpmPpi) &&
      !Cdk2HasTpm2PhysicalPresenceHob ())
  {
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

STATIC
VOID
Cdk2HandleAntiTamperBootFailure (
  IN EFI_STATUS  Status
  )
{
  DEBUG ((DEBUG_ERROR, "%a: anti-tamper boot policy failed: %r\n", __func__, Status));
  Print (L"\ncdk2 anti-tamper boot policy failed: %r\n", Status);
  Print (L"Refusing to boot until Secure Boot and TPM2 policy are restored.\n");

  if (FixedPcdGetBool (PcdCdk2AntiTamperShutdownOnFailure)) {
    gRT->ResetSystem (EfiResetShutdown, EFI_SECURITY_VIOLATION, 0, NULL);
  }

  CpuDeadLoop ();
}

STATIC
EFI_STATUS
EFIAPI
Cdk2RefreshAllBootOptions (
  IN  CONST EFI_BOOT_MANAGER_LOAD_OPTION *BootOptions,
  IN  CONST UINTN                        BootOptionsCount,
  OUT       EFI_BOOT_MANAGER_LOAD_OPTION **UpdatedBootOptions,
  OUT       UINTN                        *UpdatedBootOptionsCount
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
Cdk2PlatformBootManagerBeforeBoot (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = Cdk2ValidateAntiTamperBootPolicy ();
  if (EFI_ERROR (Status)) {
    Cdk2HandleAntiTamperBootFailure (Status);
    return Status;
  }

  return EFI_SUCCESS;
}

STATIC EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL  mCdk2PlatformBootManagerProtocol = {
  EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL_REVISION2,
  Cdk2RefreshAllBootOptions,
  Cdk2PlatformBootManagerBeforeBoot
};

STATIC
VOID
Cdk2InstallPlatformBootManagerProtocol (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mCdk2PlatformBootManagerHandle != NULL) {
    return;
  }

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mCdk2PlatformBootManagerHandle,
                  &gEdkiiPlatformBootManagerProtocolGuid,
                  &mCdk2PlatformBootManagerProtocol,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "%a: failed to install platform boot policy protocol: %r\n",
      __func__,
      Status
      ));
    mCdk2PlatformBootManagerHandle = NULL;
    if (FixedPcdGetBool (PcdCdk2AntiTamperBoot)) {
      Cdk2HandleAntiTamperBootFailure (Status);
    }
  }
}

STATIC
VOID
SyncEsrtFmpInfo (
  VOID
  )
{
  ESRT_MANAGEMENT_PROTOCOL  *EsrtManagement;
  EFI_STATUS                Status;

  Status = gBS->LocateProtocol (
                  &gEsrtManagementProtocolGuid,
                  NULL,
                  (VOID **)&EsrtManagement
                  );
  if (Status == EFI_NOT_FOUND) {
    return;
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "%a: ESRT management protocol unavailable: %r\n", __func__, Status));
    return;
  }

  Status = EsrtManagement->SyncEsrtFmp ();
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to sync FMP ESRT state: %r\n", __func__, Status));
  }
}

STATIC
BOOLEAN
ShouldScaleBootUiForHiDpi (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput
  )
{
  UINT32  HorizontalResolution;
  UINT32  VerticalResolution;

  if ((GraphicsOutput == NULL) ||
      (GraphicsOutput->Mode == NULL) ||
      (GraphicsOutput->Mode->Info == NULL))
  {
    return FALSE;
  }

  HorizontalResolution = GraphicsOutput->Mode->Info->HorizontalResolution;
  VerticalResolution   = GraphicsOutput->Mode->Info->VerticalResolution;

  return (HorizontalResolution > BOOT_UI_HIDPI_HORIZONTAL_RESOLUTION) &&
         (VerticalResolution > BOOT_UI_HIDPI_VERTICAL_RESOLUTION) &&
         ((HorizontalResolution % 2) == 0) &&
         ((VerticalResolution % 2) == 0);
}

STATIC
EFI_STATUS
GetBootPromptGraphicsOutput (
  OUT EFI_GRAPHICS_OUTPUT_PROTOCOL  **GraphicsOutput
  )
{
  EFI_STATUS  Status;

  if (GraphicsOutput == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *GraphicsOutput = NULL;
  Status          = gBS->HandleProtocol (gST->ConsoleOutHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **)GraphicsOutput);
  if (!EFI_ERROR (Status) && (*GraphicsOutput != NULL)) {
    DEBUG ((
      DEBUG_INFO,
      "%a: ConsoleOut GOP mode=%u res=%ux%u pixel-format=%u\n",
      __func__,
      (*GraphicsOutput)->Mode->Mode,
      (*GraphicsOutput)->Mode->Info->HorizontalResolution,
      (*GraphicsOutput)->Mode->Info->VerticalResolution,
      (*GraphicsOutput)->Mode->Info->PixelFormat
      ));

    if (ShouldScaleBootUiForHiDpi (*GraphicsOutput)) {
      return EFI_SUCCESS;
    }
  } else {
    DEBUG ((DEBUG_INFO, "%a: ConsoleOut GOP unavailable: %r\n", __func__, Status));
  }

  return Status;
}


STATIC
EFI_STATUS
ScaleBitmap2x (
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Source,
  IN  UINTN                          SourceWidth,
  IN  UINTN                          SourceHeight,
  IN  UINTN                          SourceStride,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **Destination
  )
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBitmap;
  UINTN                          Row;
  UINTN                          Column;
  UINTN                          DestinationWidth;

  if ((Source == NULL) || (Destination == NULL) || (SourceWidth == 0) || (SourceHeight == 0) || (SourceStride < SourceWidth)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((SourceWidth > (MAX_UINTN / 2)) || (SourceHeight > (MAX_UINTN / 2))) {
    return EFI_OUT_OF_RESOURCES;
  }

  DestinationWidth = SourceWidth * 2;
  if (DestinationWidth > (MAX_UINTN / (SourceHeight * 2) / sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL))) {
    return EFI_OUT_OF_RESOURCES;
  }

  ScaledBitmap = AllocateZeroPool (DestinationWidth * (SourceHeight * 2) * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
  if (ScaledBitmap == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  for (Row = 0; Row < SourceHeight; Row++) {
    UINTN  DestinationRow0;
    UINTN  DestinationRow1;

    DestinationRow0 = (Row * 2) * DestinationWidth;
    DestinationRow1 = DestinationRow0 + DestinationWidth;
    for (Column = 0; Column < SourceWidth; Column++) {
      EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixel;
      UINTN                          DestinationColumn;

      Pixel             = Source[Row * SourceStride + Column];
      DestinationColumn = Column * 2;
      ScaledBitmap[DestinationRow0 + DestinationColumn]     = Pixel;
      ScaledBitmap[DestinationRow0 + DestinationColumn + 1] = Pixel;
      ScaledBitmap[DestinationRow1 + DestinationColumn]     = Pixel;
      ScaledBitmap[DestinationRow1 + DestinationColumn + 1] = Pixel;
    }
  }

  *Destination = ScaledBitmap;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
DrawBootPromptLine (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput,
  IN CONST CHAR16                  *String,
  IN UINTN                         Column,
  IN UINTN                         Row,
  IN UINTN                         TextScale
  )
{
  EFI_STATUS             Status;
  EFI_HII_FONT_PROTOCOL  *HiiFont;
  EFI_IMAGE_OUTPUT       *Blt;
  EFI_IMAGE_OUTPUT       *ScaledBlt;
  EFI_IMAGE_OUTPUT       *RenderBlt;
  EFI_FONT_DISPLAY_INFO  FontInfo;
  EFI_HII_ROW_INFO       *RowInfoArray;
  UINTN                  RowInfoArraySize;
  UINTN                  GlyphWidth;
  UINTN                  GlyphHeight;
  UINTN                  PointX;
  UINTN                  PointY;
  UINTN                  BitmapWidth;
  UINTN                  BitmapHeight;
  UINTN                  RenderWidth;
  UINTN                  RenderHeight;
  UINTN                  BltWidth;
  UINTN                  BltHeight;
  UINTN                  BltDelta;
  UINTN                  Index;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBitmap;

  if ((GraphicsOutput == NULL) || (String == NULL) || (TextScale == 0) || (TextScale > 2)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiHiiFontProtocolGuid, NULL, (VOID **)&HiiFont);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: HII font protocol unavailable: %r\n", __func__, Status));
    return Status;
  }

  GlyphWidth            = EFI_GLYPH_WIDTH * TextScale;
  GlyphHeight           = EFI_GLYPH_HEIGHT * TextScale;
  PointX                = Column * GlyphWidth;
  PointY                = Row * GlyphHeight;

  Blt = AllocateZeroPool (sizeof (EFI_IMAGE_OUTPUT));
  if (Blt == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  BitmapWidth = (StrLen (String) + 2) * EFI_GLYPH_WIDTH;
  BitmapHeight = EFI_GLYPH_HEIGHT * 2;
  if ((BitmapWidth == 0) || (BitmapHeight == 0)) {
    Status = EFI_INVALID_PARAMETER;
    goto Exit;
  }

  Blt->Width        = (UINT16)BitmapWidth;
  Blt->Height       = (UINT16)BitmapHeight;
  Blt->Image.Bitmap = AllocateZeroPool (BitmapWidth * BitmapHeight * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL));
  if (Blt->Image.Bitmap == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Exit;
  }

  ZeroMem (&FontInfo, sizeof (FontInfo));
  FontInfo.ForegroundColor.Blue     = 0xc0;
  FontInfo.ForegroundColor.Green    = 0xc0;
  FontInfo.ForegroundColor.Red      = 0xc0;
  FontInfo.BackgroundColor.Blue     = 0x00;
  FontInfo.BackgroundColor.Green    = 0x00;
  FontInfo.BackgroundColor.Red      = 0x00;
  FontInfo.FontInfoMask             = EFI_FONT_INFO_SYS_FONT | EFI_FONT_INFO_SYS_SIZE | EFI_FONT_INFO_SYS_STYLE;
  FontInfo.FontInfo.FontSize        = EFI_GLYPH_HEIGHT;
  FontInfo.FontInfo.FontName[0]     = CHAR_NULL;
  RowInfoArray                      = NULL;
  RowInfoArraySize                  = 0;

  Status = HiiFont->StringToImage (
                      HiiFont,
                      EFI_HII_IGNORE_IF_NO_GLYPH | EFI_HII_OUT_FLAG_CLIP | EFI_HII_OUT_FLAG_CLIP_CLEAN_X | EFI_HII_OUT_FLAG_CLIP_CLEAN_Y | EFI_HII_IGNORE_LINE_BREAK,
                      (EFI_STRING)String,
                      &FontInfo,
                      &Blt,
                      0,
                      0,
                      &RowInfoArray,
                      &RowInfoArraySize,
                      NULL
                      );
  if (EFI_ERROR (Status)) {
    goto Exit;
  }

  RenderWidth  = 0;
  RenderHeight = 0;
  for (Index = 0; Index < RowInfoArraySize; Index++) {
    if (RowInfoArray[Index].LineWidth > RenderWidth) {
      RenderWidth = RowInfoArray[Index].LineWidth;
    }

    RenderHeight += RowInfoArray[Index].LineHeight;
  }

  if ((RenderWidth == 0) || (RenderHeight == 0)) {
    Status = EFI_DEVICE_ERROR;
    goto Exit;
  }

  ScaledBlt    = NULL;
  ScaledBitmap = NULL;
  RenderBlt    = Blt;
  BltWidth     = RenderWidth;
  BltHeight    = RenderHeight;
  BltDelta     = Blt->Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);

  if (TextScale == 2) {
    Status = ScaleBitmap2x (Blt->Image.Bitmap, RenderWidth, RenderHeight, Blt->Width, &ScaledBitmap);
    if (EFI_ERROR (Status)) {
      goto Exit;
    }

    ScaledBlt = AllocateZeroPool (sizeof (EFI_IMAGE_OUTPUT));
    if (ScaledBlt == NULL) {
      FreePool (ScaledBitmap);
      Status = EFI_OUT_OF_RESOURCES;
      goto Exit;
    }

    ScaledBlt->Width        = (UINT16)(RenderWidth * 2);
    ScaledBlt->Height       = (UINT16)(RenderHeight * 2);
    ScaledBlt->Image.Bitmap = ScaledBitmap;
    RenderBlt               = ScaledBlt;
    BltWidth                = ScaledBlt->Width;
    BltHeight               = ScaledBlt->Height;
    BltDelta                = ScaledBlt->Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
  }

  Status = GraphicsOutput->Blt (
                             GraphicsOutput,
                             RenderBlt->Image.Bitmap,
                             EfiBltBufferToVideo,
                             0,
                             0,
                             PointX,
                             PointY,
                             BltWidth,
                             BltHeight,
                             BltDelta
                             );
  if (ScaledBlt != NULL) {
    FreePool (ScaledBlt->Image.Bitmap);
    FreePool (ScaledBlt);
  }

Exit:
  if (RowInfoArray != NULL) {
    FreePool (RowInfoArray);
  }

  if ((Blt != NULL) && (Blt->Image.Bitmap != NULL)) {
    FreePool (Blt->Image.Bitmap);
  }

  FreePool (Blt);
  return Status;
}

STATIC
VOID
FormatBootPromptCountdownLine (
  OUT CHAR16  *String,
  IN  UINTN   StringChars,
  IN  UINT16  TimeoutRemain
  )
{
  if ((String == NULL) || (StringChars == 0)) {
    return;
  }

  if ((TimeoutRemain == 0) || (TimeoutRemain == 0xFFFF)) {
    UnicodeSPrint (String, StringChars * sizeof (CHAR16), L"Press ENTER to boot now");
    return;
  }

  if (mLowBatteryBootGuardActive) {
    UnicodeSPrint (
      String,
      StringChars * sizeof (CHAR16),
      L"Shutting down in %u seconds, press ENTER to boot now",
      TimeoutRemain
      );
    return;
  }

  UnicodeSPrint (
    String,
    StringChars * sizeof (CHAR16),
    L"Booting in %u seconds, press ENTER to boot now",
    TimeoutRemain
    );
}

STATIC
CONST CHAR16 *
GetBootPromptSettingsLine (
  IN BOOLEAN  UseEscape
  )
{
  return UseEscape ? L"Press ESC or down for settings" : L"Press F2 or down for settings";
}

STATIC
BOOLEAN
DisplayBootManagerPrompt (
  IN BOOLEAN  UseEscape,
  IN UINT16   TimeoutRemain
  )
{
  EFI_STATUS                    Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput;
  CHAR16                        CountdownLine[64];
  UINTN                         TextScale;

  Status = GetBootPromptGraphicsOutput (&GraphicsOutput);
  if (EFI_ERROR (Status) || (GraphicsOutput == NULL)) {
    return FALSE;
  }

  TextScale = ShouldScaleBootUiForHiDpi (GraphicsOutput) ? 2U : 1U;
  FormatBootPromptCountdownLine (CountdownLine, ARRAY_SIZE (CountdownLine), TimeoutRemain);

  Status = DrawBootPromptLine (
             GraphicsOutput,
             CountdownLine,
             4,
             1,
             TextScale
             );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = DrawBootPromptLine (
             GraphicsOutput,
             GetBootPromptSettingsLine (UseEscape),
             4,
             3,
             TextScale
             );
  return !EFI_ERROR (Status);
}

STATIC
EFI_STATUS
DrawLowBatteryLogo (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput
  )
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Blt;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *LogoBlt;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBlt;
  EFI_STATUS                     Status;
  RETURN_STATUS                  ReturnStatus;
  UINTN                          BmpImageSize;
  UINTN                          BltHeight;
  UINTN                          BltSize;
  UINTN                          BltWidth;
  UINTN                          DestX;
  UINTN                          DestY;
  UINTN                          DrawHeight;
  UINTN                          DrawWidth;
  UINTN                          LogoDelta;
  UINTN                          LogoHeight;
  UINTN                          LogoWidth;
  UINTN                          ScreenHeight;
  UINTN                          ScreenWidth;
  UINTN                          SourceX;
  UINTN                          SourceY;
  VOID                           *BmpImage;

  if ((GraphicsOutput == NULL) || (GraphicsOutput->Mode == NULL) ||
      (GraphicsOutput->Mode->Info == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  BmpImage     = NULL;
  BmpImageSize = 0;
  Blt          = NULL;
  BltSize      = 0;
  BltHeight    = 0;
  BltWidth     = 0;
  LogoBlt      = NULL;
  ScaledBlt    = NULL;

  Status = GetSectionFromAnyFv (
             &mLowBatteryLogoFileGuid,
             EFI_SECTION_RAW,
             0,
             &BmpImage,
             &BmpImageSize
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: low-battery logo unavailable: %r\n", __func__, Status));
    return Status;
  }

  ReturnStatus = TranslateBmpToGopBlt (
                   BmpImage,
                   BmpImageSize,
                   &Blt,
                   &BltSize,
                   &BltHeight,
                   &BltWidth
                   );
  if (RETURN_ERROR (ReturnStatus)) {
    DEBUG ((DEBUG_INFO, "%a: failed to decode low-battery logo: %r\n", __func__, ReturnStatus));
    Status = (EFI_STATUS)ReturnStatus;
    goto Exit;
  }

  LogoBlt    = Blt;
  LogoWidth  = BltWidth;
  LogoHeight = BltHeight;
  LogoDelta  = BltWidth * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);

  if (ShouldScaleBootUiForHiDpi (GraphicsOutput)) {
    Status = ScaleBitmap2x (Blt, BltWidth, BltHeight, BltWidth, &ScaledBlt);
    if (!EFI_ERROR (Status)) {
      LogoBlt    = ScaledBlt;
      LogoWidth  = BltWidth * 2;
      LogoHeight = BltHeight * 2;
      LogoDelta  = LogoWidth * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
    } else {
      DEBUG ((DEBUG_INFO, "%a: failed to scale low-battery logo for HiDPI boot GOP: %r\n", __func__, Status));
      Status = EFI_SUCCESS;
    }
  }

  ScreenWidth  = GraphicsOutput->Mode->Info->HorizontalResolution;
  ScreenHeight = GraphicsOutput->Mode->Info->VerticalResolution;
  DrawWidth    = LogoWidth;
  DrawHeight   = LogoHeight;
  SourceX      = 0;
  SourceY      = 0;
  DestX        = 0;
  DestY        = 0;

  if (DrawWidth > ScreenWidth) {
    SourceX   = (DrawWidth - ScreenWidth) / 2;
    DrawWidth = ScreenWidth;
  } else {
    DestX = (ScreenWidth - DrawWidth) / 2;
  }

  if (DrawHeight > ScreenHeight) {
    SourceY    = (DrawHeight - ScreenHeight) / 2;
    DrawHeight = ScreenHeight;
  } else {
    DestY = (ScreenHeight - DrawHeight) / 2;
  }

  Status = GraphicsOutput->Blt (
                             GraphicsOutput,
                             LogoBlt,
                             EfiBltBufferToVideo,
                             SourceX,
                             SourceY,
                             DestX,
                             DestY,
                             DrawWidth,
                             DrawHeight,
                             LogoDelta
                             );

Exit:
  if (ScaledBlt != NULL) {
    FreePool (ScaledBlt);
  }

  if (Blt != NULL) {
    FreePool (Blt);
  }

  if (BmpImage != NULL) {
    FreePool (BmpImage);
  }

  return Status;
}

STATIC
VOID
PlatformEnableBootLogo (
  VOID
  )
{
  if ((gST == NULL) ||
      (gST->ConOut == NULL) ||
      (gST->ConsoleOutHandle == NULL))
  {
    DEBUG ((
      DEBUG_VERBOSE,
      "%a: boot logo repaint skipped without ConOut\n",
      __func__
      ));
    return;
  }

  BootLogoEnableLogo ();
}

STATIC
VOID
DisplayLowBatteryBootLogo (
  VOID
  )
{
  EFI_STATUS                    Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput;

  if (mLowBatteryBootLogoShown) {
    return;
  }

  Status = GetBootPromptGraphicsOutput (&GraphicsOutput);
  if (EFI_ERROR (Status) || (GraphicsOutput == NULL)) {
    DEBUG ((DEBUG_INFO, "%a: GOP unavailable: %r\n", __func__, Status));
    return;
  }

  if ((gST != NULL) && (gST->ConOut != NULL)) {
    gST->ConOut->ClearScreen (gST->ConOut);
  }

  Status = DrawLowBatteryLogo (GraphicsOutput);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: failed to draw low-battery logo: %r\n", __func__, Status));
    return;
  }

  mLowBatteryBootLogoShown = TRUE;
}

STATIC
VOID
DisplayPlatformBootLogo (
  VOID
  )
{
  EFI_STATUS                    Status;
  EDKII_PLATFORM_LOGO_PROTOCOL  *PlatformLogo;

  if (mLowBatteryBootGuardActive) {
    DisplayLowBatteryBootLogo ();
    return;
  }

  Status = gBS->LocateProtocol (&gEdkiiPlatformLogoProtocolGuid, NULL, (VOID **)&PlatformLogo);
  if (EFI_ERROR (Status)) {
    return;
  }

  if ((gST != NULL) && (gST->ConOut != NULL)) {
    gST->ConOut->ClearScreen (gST->ConOut);
  }

  PlatformEnableBootLogo ();
}

STATIC
BOOLEAN
IsLowBatteryBootGuardRequired (
  VOID
  )
{
  EFI_STATUS                   Status;
  EFI_BATTERY_STATUS_PROTOCOL  *BatteryStatus;
  UINT8                        BatteryPercentage;
  BOOLEAN                      BatteryPresent;
  BOOLEAN                      BatteryCharging;
  BOOLEAN                      BatteryCritical;

  Status = gBS->LocateProtocol (&gEfiBatteryStatusProtocolGuid, NULL, (VOID **)&BatteryStatus);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: battery status protocol unavailable: %r\n", __func__, Status));
    return FALSE;
  }

  Status = BatteryStatus->GetBatteryInfo (
                            BatteryStatus,
                            &BatteryPercentage,
                            &BatteryPresent,
                            &BatteryCharging
                            );
  if (EFI_ERROR (Status) || !BatteryPresent) {
    DEBUG ((DEBUG_INFO, "%a: battery unavailable: %r\n", __func__, Status));
    return FALSE;
  }

  BatteryCritical = FALSE;
  if (BatteryStatus->GetBatteryCritical != NULL) {
    Status = BatteryStatus->GetBatteryCritical (BatteryStatus, &BatteryCritical);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "%a: battery critical state unavailable: %r\n", __func__, Status));
    }
  }

  DEBUG ((
    DEBUG_INFO,
    "%a: battery=%u%% present=%d charging=%d critical=%d\n",
    __func__,
    BatteryPercentage,
    BatteryPresent,
    BatteryCharging,
    BatteryCritical
    ));

  if (BatteryCharging) {
    return FALSE;
  }

  return BatteryCritical;
}

STATIC
VOID
ConfigureLowBatteryBootGuard (
  VOID
  )
{
  mLowBatteryBootGuardActive = IsLowBatteryBootGuardRequired ();
  if (!mLowBatteryBootGuardActive) {
    return;
  }

  DEBUG ((DEBUG_INFO, "%a: using low-battery boot splash\n", __func__));
}

/**
  Return the timeout BDS should use for its boot wait loop.

  @param Timeout  The configured boot timeout.

  @return The timeout to use for the current boot.
**/
UINT16
EFIAPI
PlatformBootManagerGetWaitTimeout (
  IN UINT16  Timeout
  )
{
  if (mLowBatteryBootGuardActive) {
    return LOW_BATTERY_BOOT_TIMEOUT;
  }

  return Timeout;
}

/**
  Signal EndOfDxe event and install SMM Ready to lock protocol.

**/
VOID
InstallReadyToLock (
  VOID
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                Handle;
  EFI_SMM_ACCESS2_PROTOCOL  *SmmAccess;

  DEBUG ((DEBUG_INFO, "InstallReadyToLock  entering......\n"));
  //
  // Inform the SMM infrastructure that we're entering BDS and may run 3rd party code hereafter
  // Since PI1.2.1, we need signal EndOfDxe as ExitPmAuth
  //
  EfiEventGroupSignal (&gEfiEndOfDxeEventGroupGuid);
  DEBUG ((DEBUG_INFO, "All EndOfDxe callbacks have returned successfully\n"));

  //
  // Install DxeSmmReadyToLock protocol in order to lock SMM
  //
  Status = gBS->LocateProtocol (&gEfiSmmAccess2ProtocolGuid, NULL, (VOID **)&SmmAccess);
  if (!EFI_ERROR (Status)) {
    Handle = NULL;
    Status = gBS->InstallProtocolInterface (
                    &Handle,
                    &gEfiDxeSmmReadyToLockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    NULL
                    );
    ASSERT_EFI_ERROR (Status);
  }

  DEBUG ((DEBUG_INFO, "InstallReadyToLock  end\n"));
  return;
}

/**
  Return the index of the load option in the load option array.

  The function consider two load options are equal when the
  OptionType, Attributes, Description, FilePath and OptionalData are equal.

  @param Key    Pointer to the load option to be found.
  @param Array  Pointer to the array of load options to be found.
  @param Count  Number of entries in the Array.

  @retval -1          Key wasn't found in the Array.
  @retval 0 ~ Count-1 The index of the Key in the Array.
**/
INTN
PlatformFindLoadOption (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *Key,
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *Array,
  IN UINTN                               Count
  )
{
  UINTN  Index;

  for (Index = 0; Index < Count; Index++) {
    if ((Key->OptionType == Array[Index].OptionType) &&
        (Key->Attributes == Array[Index].Attributes) &&
        (StrCmp (Key->Description, Array[Index].Description) == 0) &&
        (CompareMem (Key->FilePath, Array[Index].FilePath, GetDevicePathSize (Key->FilePath)) == 0) &&
        (Key->OptionalDataSize == Array[Index].OptionalDataSize) &&
        (CompareMem (Key->OptionalData, Array[Index].OptionalData, Key->OptionalDataSize) == 0))
    {
      return (INTN)Index;
    }
  }

  return -1;
}

/**
  Get the FV device path for the shell file.

  @return   A pointer to device path structure.
**/
EFI_DEVICE_PATH_PROTOCOL *
BdsGetShellFvDevicePath (
  VOID
  )
{
  UINTN                          FvHandleCount;
  EFI_HANDLE                     *FvHandleBuffer;
  UINTN                          Index;
  EFI_STATUS                     Status;
  EFI_FIRMWARE_VOLUME2_PROTOCOL  *Fv;
  UINTN                          Size;
  UINT32                         AuthenticationStatus;
  EFI_DEVICE_PATH_PROTOCOL       *DevicePath;
  EFI_FV_FILETYPE                FoundType;
  EFI_FV_FILE_ATTRIBUTES         FileAttributes;

  Status = EFI_SUCCESS;
  gBS->LocateHandleBuffer (
         ByProtocol,
         &gEfiFirmwareVolume2ProtocolGuid,
         NULL,
         &FvHandleCount,
         &FvHandleBuffer
         );

  for (Index = 0; Index < FvHandleCount; Index++) {
    Size = 0;
    gBS->HandleProtocol (
           FvHandleBuffer[Index],
           &gEfiFirmwareVolume2ProtocolGuid,
           (VOID **)&Fv
           );
    Status = Fv->ReadFile (
                   Fv,
                   &gUefiShellFileGuid,
                   NULL,
                   &Size,
                   &FoundType,
                   &FileAttributes,
                   &AuthenticationStatus
                   );
    if (!EFI_ERROR (Status)) {
      //
      // Found the shell file
      //
      break;
    }
  }

  if (EFI_ERROR (Status)) {
    if (FvHandleCount) {
      FreePool (FvHandleBuffer);
    }

    return NULL;
  }

  DevicePath = DevicePathFromHandle (FvHandleBuffer[Index]);

  if (FvHandleCount) {
    FreePool (FvHandleBuffer);
  }

  return DevicePath;
}

/**
  Register a boot option using a file GUID in the FV.

  @param FileGuid     The file GUID name in FV.
  @param Description  The boot option description.
  @param Attributes   The attributes used for the boot option loading.
**/
VOID
PlatformRegisterFvBootOption (
  EFI_GUID  *FileGuid,
  CHAR16    *Description,
  UINT32    Attributes
  )
{
  EFI_STATUS                         Status;
  UINTN                              OptionIndex;
  EFI_BOOT_MANAGER_LOAD_OPTION       NewOption;
  EFI_BOOT_MANAGER_LOAD_OPTION       *BootOptions;
  UINTN                              BootOptionCount;
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH  FileNode;
  EFI_DEVICE_PATH_PROTOCOL           *DevicePath;

  EfiInitializeFwVolDevicepathNode (&FileNode, FileGuid);
  DevicePath = AppendDevicePathNode (
                 BdsGetShellFvDevicePath (),
                 (EFI_DEVICE_PATH_PROTOCOL *)&FileNode
                 );

  Status = EfiBootManagerInitializeLoadOption (
             &NewOption,
             LoadOptionNumberUnassigned,
             LoadOptionTypeBoot,
             Attributes,
             Description,
             DevicePath,
             NULL,
             0
             );
  if (!EFI_ERROR (Status)) {
    BootOptions = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);

    OptionIndex = PlatformFindLoadOption (&NewOption, BootOptions, BootOptionCount);

    if (OptionIndex == -1) {
      Status = EfiBootManagerAddLoadOptionVariable (&NewOption, (UINTN)-1);
      ASSERT_EFI_ERROR (Status);
    }

    EfiBootManagerFreeLoadOption (&NewOption);
    EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
  }
}

STATIC
BOOLEAN
PlatformBootOptionUsesInternalDisk (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *Node;
  BOOLEAN                   HasHardDrive;

  if ((BootOption == NULL) || (BootOption->FilePath == NULL)) {
    return FALSE;
  }

  HasHardDrive = FALSE;
  for (Node = BootOption->FilePath; !IsDevicePathEnd (Node); Node = NextDevicePathNode (Node)) {
    if ((DevicePathType (Node) == MESSAGING_DEVICE_PATH) &&
        ((DevicePathSubType (Node) == MSG_USB_DP) ||
         (DevicePathSubType (Node) == MSG_USB_CLASS_DP) ||
         (DevicePathSubType (Node) == MSG_USB_WWID_DP)))
    {
      return FALSE;
    }

    if ((DevicePathType (Node) == MEDIA_DEVICE_PATH) &&
        (DevicePathSubType (Node) == MEDIA_HARDDRIVE_DP))
    {
      HasHardDrive = TRUE;
    }
  }

  return HasHardDrive;
}

STATIC
BOOLEAN
PlatformBootOptionUsesStorage (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *Node;

  if ((BootOption == NULL) || (BootOption->FilePath == NULL)) {
    return FALSE;
  }

  for (Node = BootOption->FilePath; !IsDevicePathEnd (Node); Node = NextDevicePathNode (Node)) {
    if (DevicePathType (Node) == MESSAGING_DEVICE_PATH) {
      switch (DevicePathSubType (Node)) {
        case MSG_ATAPI_DP:
        case MSG_SCSI_DP:
        case MSG_USB_DP:
        case MSG_USB_CLASS_DP:
        case MSG_USB_WWID_DP:
        case MSG_SATA_DP:
        case MSG_NVME_NAMESPACE_DP:
        case MSG_UFS_DP:
        case MSG_SD_DP:
        case MSG_EMMC_DP:
          return TRUE;
        default:
          break;
      }
    }

    if ((DevicePathType (Node) == MEDIA_DEVICE_PATH) &&
        ((DevicePathSubType (Node) == MEDIA_HARDDRIVE_DP) ||
         (DevicePathSubType (Node) == MEDIA_CDROM_DP)))
    {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
BOOLEAN
PlatformBootImageIsValid (
  IN CONST VOID  *FileBuffer,
  IN UINTN       FileSize
  )
{
  CONST EFI_IMAGE_DOS_HEADER             *DosHeader;
  CONST EFI_IMAGE_OPTIONAL_HEADER_UNION  *PeHeader;
  UINT32                                 PeOffset;

  if ((FileBuffer == NULL) || (FileSize < sizeof (EFI_IMAGE_DOS_HEADER))) {
    return FALSE;
  }

  DosHeader = (CONST EFI_IMAGE_DOS_HEADER *)FileBuffer;
  if ((DosHeader->e_magic != EFI_IMAGE_DOS_SIGNATURE) ||
      (DosHeader->e_lfanew >= FileSize))
  {
    return FALSE;
  }

  PeOffset = DosHeader->e_lfanew;
  if ((FileSize - PeOffset) < sizeof (EFI_IMAGE_OPTIONAL_HEADER_UNION)) {
    return FALSE;
  }

  PeHeader = (CONST EFI_IMAGE_OPTIONAL_HEADER_UNION *)((CONST UINT8 *)FileBuffer + PeOffset);
  if (PeHeader->Pe32.Signature != EFI_IMAGE_NT_SIGNATURE) {
    return FALSE;
  }

  if ((PeHeader->Pe32.OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) &&
      (PeHeader->Pe32.OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC))
  {
    return FALSE;
  }

  return EFI_IMAGE_MACHINE_TYPE_SUPPORTED (PeHeader->Pe32.FileHeader.Machine) &&
         (PeHeader->Pe32.OptionalHeader.Subsystem == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION);
}

STATIC
BOOLEAN
PlatformBootOptionHasLoadablePath (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption,
  IN CONST CHAR8                         *LogPrefix
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL  *CurFullPath;
  EFI_DEVICE_PATH_PROTOCOL  *PreFullPath;
  VOID                      *FileBuffer;
  UINTN                     FileSize;
  UINT32                    AuthenticationStatus;
  BOOLEAN                   Found;

  if ((BootOption == NULL) || (BootOption->FilePath == NULL)) {
    return FALSE;
  }

  DeviceHandle = NULL;
  Status       = EfiBootManagerConnectDevicePath (BootOption->FilePath, &DeviceHandle);
  if (!EFI_ERROR (Status) && (DeviceHandle != NULL)) {
    gBS->ConnectController (DeviceHandle, NULL, NULL, TRUE);
  }

  Found       = FALSE;
  CurFullPath = NULL;
  do {
    PreFullPath = CurFullPath;
    CurFullPath = EfiBootManagerGetNextLoadOptionDevicePathNoConnectAll (
                    BootOption->FilePath,
                    CurFullPath
                    );

    if (PreFullPath != NULL) {
      FreePool (PreFullPath);
    }

    if (CurFullPath == NULL) {
      break;
    }

    FileSize             = 0;
    AuthenticationStatus = 0;
    FileBuffer           = GetFileBufferByFilePath (
                             TRUE,
                             CurFullPath,
                             &FileSize,
                             &AuthenticationStatus
                             );
    if (FileBuffer != NULL) {
      Found = PlatformBootImageIsValid (FileBuffer, FileSize);
      FreePool (FileBuffer);
      if (Found) {
        break;
      }
    }
  } while (TRUE);

  if (CurFullPath != NULL) {
    FreePool (CurFullPath);
  }

  DEBUG ((
    DEBUG_INFO,
    "%a boot path validation for %s: %a\n",
    (LogPrefix != NULL) ? LogPrefix : "Boot",
    (BootOption->Description != NULL) ? BootOption->Description : L"<unknown>",
    Found ? "found" : "not found"
    ));

  return Found;
}

STATIC
BOOLEAN
PlatformBootOptionHasLoadableInternalDiskPath (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption
  )
{
  if (!PlatformBootOptionUsesInternalDisk (BootOption)) {
    return FALSE;
  }

  return PlatformBootOptionHasLoadablePath (BootOption, "Internal");
}

STATIC
BOOLEAN
PlatformHasUsableInternalBootPath (
  VOID
  )
{
  EFI_STATUS                    Status;
  UINT16                        BootNext;
  UINTN                         DataSize;
  CHAR16                        BootOptionName[16];
  EFI_BOOT_MANAGER_LOAD_OPTION  BootNextOption;
  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOptions;
  UINTN                         BootOptionCount;
  UINTN                         Index;
  BOOLEAN                       UsableInternalBootPath;

  BootOptions            = NULL;
  BootOptionCount        = 0;
  UsableInternalBootPath = FALSE;
  ZeroMem (&BootNextOption, sizeof (BootNextOption));

  //
  // BootNext is an explicit one-shot selection.  Keep it authoritative, but
  // fall back to BootOrder if an internal BootNext is stale.
  //
  DataSize = sizeof (BootNext);
  Status   = gRT->GetVariable (
                    EFI_BOOT_NEXT_VARIABLE_NAME,
                    &gEfiGlobalVariableGuid,
                    NULL,
                    &DataSize,
                    &BootNext
                    );
  if (!EFI_ERROR (Status) && (DataSize == sizeof (BootNext))) {
    UnicodeSPrint (BootOptionName, sizeof (BootOptionName), L"Boot%04x", BootNext);
    Status = EfiBootManagerVariableToLoadOption (BootOptionName, &BootNextOption);
    if (!EFI_ERROR (Status)) {
      if (!PlatformBootOptionUsesInternalDisk (&BootNextOption)) {
        DEBUG ((DEBUG_INFO, "BootNext is removable or non-disk; discovering removable media\n"));
        EfiBootManagerFreeLoadOption (&BootNextOption);
        return FALSE;
      }

      UsableInternalBootPath = PlatformBootOptionHasLoadableInternalDiskPath (&BootNextOption);
      EfiBootManagerFreeLoadOption (&BootNextOption);
      if (UsableInternalBootPath) {
        return TRUE;
      }

      DEBUG ((DEBUG_INFO, "BootNext internal boot path is unavailable; checking BootOrder\n"));
    } else {
      DEBUG ((DEBUG_INFO, "BootNext option %04x is unavailable: %r\n", BootNext, Status));
    }
  }

  BootOptions = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);
  for (Index = 0; Index < BootOptionCount; Index++) {
    if ((BootOptions[Index].Attributes & LOAD_OPTION_ACTIVE) == 0) {
      continue;
    }

    if ((BootOptions[Index].Attributes & LOAD_OPTION_CATEGORY) != LOAD_OPTION_CATEGORY_BOOT) {
      continue;
    }

    if (PlatformBootOptionHasLoadableInternalDiskPath (&BootOptions[Index])) {
      UsableInternalBootPath = TRUE;
      break;
    }
  }

  if (!UsableInternalBootPath) {
    DEBUG ((DEBUG_INFO, "No usable internal boot path found\n"));
  }

  EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
  return UsableInternalBootPath;
}

STATIC
BOOLEAN
PlatformBootOptionHasLoadableStoragePath (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption
  )
{
  if (!PlatformBootOptionUsesStorage (BootOption)) {
    return FALSE;
  }

  return PlatformBootOptionHasLoadablePath (BootOption, "Storage");
}

STATIC
BOOLEAN
PlatformHasUsableStorageBootPath (
  VOID
  )
{
  EFI_STATUS                    Status;
  UINT16                        BootNext;
  UINTN                         DataSize;
  CHAR16                        BootOptionName[16];
  EFI_BOOT_MANAGER_LOAD_OPTION  BootNextOption;
  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOptions;
  UINTN                         BootOptionCount;
  UINTN                         Index;
  BOOLEAN                       UsableStorageBootPath;

  BootOptions           = NULL;
  UsableStorageBootPath = FALSE;
  ZeroMem (&BootNextOption, sizeof (BootNextOption));

  DataSize = sizeof (BootNext);
  Status   = gRT->GetVariable (
                    EFI_BOOT_NEXT_VARIABLE_NAME,
                    &gEfiGlobalVariableGuid,
                    NULL,
                    &DataSize,
                    &BootNext
                    );
  if (!EFI_ERROR (Status) && (DataSize == sizeof (BootNext))) {
    UnicodeSPrint (BootOptionName, sizeof (BootOptionName), L"Boot%04x", BootNext);
    Status = EfiBootManagerVariableToLoadOption (BootOptionName, &BootNextOption);
    if (!EFI_ERROR (Status)) {
      if (PlatformBootOptionUsesStorage (&BootNextOption)) {
        UsableStorageBootPath = PlatformBootOptionHasLoadableStoragePath (&BootNextOption);
        if (UsableStorageBootPath) {
          EfiBootManagerFreeLoadOption (&BootNextOption);
          return TRUE;
        }

        DEBUG ((DEBUG_INFO, "BootNext storage path is unavailable; checking BootOrder\n"));
        // Fall through to BootOrder when BootNext is stale.
      }

      EfiBootManagerFreeLoadOption (&BootNextOption);
    } else {
      DEBUG ((DEBUG_INFO, "BootNext option %04x is unavailable: %r\n", BootNext, Status));
    }
  }

  BootOptions = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);

  for (Index = 0; Index < BootOptionCount; Index++) {
    if ((BootOptions[Index].Attributes & LOAD_OPTION_ACTIVE) == 0) {
      continue;
    }

    if ((BootOptions[Index].Attributes & LOAD_OPTION_CATEGORY) != LOAD_OPTION_CATEGORY_BOOT) {
      continue;
    }

    if (PlatformBootOptionHasLoadableStoragePath (&BootOptions[Index])) {
      UsableStorageBootPath = TRUE;
      break;
    }
  }

  if (!UsableStorageBootPath) {
    DEBUG ((DEBUG_INFO, "No usable storage boot path found\n"));
  }

  EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
  return UsableStorageBootPath;
}

STATIC
EFI_STATUS
PlatformValidateLinuxEfiApplicationDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  )
{
  EFI_STATUS                 Status;
  EFI_STATUS                 UnloadStatus;
  EFI_HANDLE                 ImageHandle;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;

  if (DevicePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ImageHandle = NULL;
  LoadedImage = NULL;
  Status      = gBS->LoadImage (
                       TRUE,
                       gImageHandle,
                       DevicePath,
                       NULL,
                       0,
                       &ImageHandle
                       );
  if (EFI_ERROR (Status)) {
    if ((Status == EFI_SECURITY_VIOLATION) && (ImageHandle != NULL)) {
      gBS->UnloadImage (ImageHandle);
    }

    return Status;
  }

  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage
                  );
  if (!EFI_ERROR (Status) && (LoadedImage->ImageCodeType != EfiLoaderCode)) {
    Status = EFI_UNSUPPORTED;
  }

  UnloadStatus = gBS->UnloadImage (ImageHandle);
  if (!EFI_ERROR (Status) && EFI_ERROR (UnloadStatus)) {
    Status = UnloadStatus;
  }

  return Status;
}

STATIC
EFI_STATUS
PlatformBuildLinuxEfiDevicePathFromBootOption (
  IN  CONST EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption,
  IN  CONST CHAR16                        *LinuxPath,
  OUT EFI_DEVICE_PATH_PROTOCOL            **DevicePath
  )
{
  EFI_STATUS                Status;
  EFI_DEVICE_PATH_PROTOCOL  *BootDevicePath;
  EFI_DEVICE_PATH_PROTOCOL  *RemainingDevicePath;
  EFI_HANDLE                DeviceHandle;

  if ((BootOption == NULL) || (LinuxPath == NULL) || (DevicePath == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *DevicePath = NULL;
  if (!PlatformBootOptionUsesInternalDisk (BootOption)) {
    return EFI_NOT_FOUND;
  }

  BootDevicePath = DuplicateDevicePath (BootOption->FilePath);
  if (BootDevicePath == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = EfiBootManagerConnectDevicePath (BootDevicePath, NULL);
  if (!EFI_ERROR (Status)) {
    RemainingDevicePath = BootDevicePath;
    Status = gBS->LocateDevicePath (
                    &gEfiSimpleFileSystemProtocolGuid,
                    &RemainingDevicePath,
                    &DeviceHandle
                    );
    if (!EFI_ERROR (Status)) {
      *DevicePath = FileDevicePath (DeviceHandle, LinuxPath);
      Status      = (*DevicePath == NULL) ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
    }
  }

  FreePool (BootDevicePath);
  return Status;
}

STATIC
EFI_STATUS
PlatformFindLinuxEfiApplicationFromBootOptions (
  IN  CONST CHAR16              *LinuxPath,
  OUT EFI_DEVICE_PATH_PROTOCOL  **DevicePath
  )
{
  EFI_STATUS                    Status;
  EFI_STATUS                    LastStatus;
  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOptions;
  EFI_DEVICE_PATH_PROTOCOL      *Candidate;
  UINTN                         BootOptionCount;
  UINTN                         Index;

  if ((LinuxPath == NULL) || (DevicePath == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *DevicePath     = NULL;
  BootOptions     = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);
  LastStatus      = EFI_NOT_FOUND;

  for (Index = 0; Index < BootOptionCount; Index++) {
    if ((BootOptions[Index].Attributes & LOAD_OPTION_ACTIVE) == 0) {
      continue;
    }

    Candidate = NULL;
    Status    = PlatformBuildLinuxEfiDevicePathFromBootOption (
                  &BootOptions[Index],
                  LinuxPath,
                  &Candidate
                  );
    if (EFI_ERROR (Status)) {
      LastStatus = Status;
      continue;
    }

    Status = PlatformValidateLinuxEfiApplicationDevicePath (Candidate);
    if (!EFI_ERROR (Status)) {
      *DevicePath = Candidate;
      EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
      return EFI_SUCCESS;
    }

    LastStatus = Status;
    FreePool (Candidate);
  }

  EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
  return LastStatus;
}

STATIC
EFI_STATUS
PlatformFindLinuxEfiApplicationFromFileSystems (
  IN  CONST CHAR16              *LinuxPath,
  OUT EFI_DEVICE_PATH_PROTOCOL  **DevicePath
  )
{
  EFI_STATUS                Status;
  EFI_STATUS                LastStatus;
  EFI_HANDLE                *Handles;
  EFI_DEVICE_PATH_PROTOCOL  *Candidate;
  UINTN                     HandleCount;
  UINTN                     Index;

  if ((LinuxPath == NULL) || (DevicePath == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *DevicePath = NULL;
  Handles     = NULL;
  HandleCount = 0;
  Status      = gBS->LocateHandleBuffer (
                       ByProtocol,
                       &gEfiSimpleFileSystemProtocolGuid,
                       NULL,
                       &HandleCount,
                       &Handles
                       );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  LastStatus = EFI_NOT_FOUND;
  for (Index = 0; Index < HandleCount; Index++) {
    Candidate = FileDevicePath (Handles[Index], LinuxPath);
    if (Candidate == NULL) {
      LastStatus = EFI_OUT_OF_RESOURCES;
      continue;
    }

    Status = PlatformValidateLinuxEfiApplicationDevicePath (Candidate);
    if (!EFI_ERROR (Status)) {
      *DevicePath = Candidate;
      FreePool (Handles);
      return EFI_SUCCESS;
    }

    LastStatus = Status;
    FreePool (Candidate);
  }

  FreePool (Handles);
  return LastStatus;
}

STATIC
EFI_STATUS
PlatformFindLinuxEfiApplicationDevicePath (
  IN  CONST CHAR16              *LinuxPath,
  OUT EFI_DEVICE_PATH_PROTOCOL  **DevicePath
  )
{
  EFI_STATUS  Status;
  EFI_STATUS  BootOptionStatus;

  if ((LinuxPath == NULL) || (DevicePath == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *DevicePath      = NULL;
  BootOptionStatus = PlatformFindLinuxEfiApplicationFromBootOptions (
                       LinuxPath,
                       DevicePath
                       );
  if (!EFI_ERROR (BootOptionStatus)) {
    return EFI_SUCCESS;
  }

  Status = PlatformFindLinuxEfiApplicationFromFileSystems (
             LinuxPath,
             DevicePath
             );
  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  return (BootOptionStatus != EFI_NOT_FOUND) ? BootOptionStatus : Status;
}

STATIC
VOID
PlatformRegisterLinuxEfiApplicationBootOption (
  VOID
  )
{
  EFI_STATUS                    Status;
  INTN                          OptionIndex;
  EFI_BOOT_MANAGER_LOAD_OPTION  NewOption;
  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOptions;
  EFI_DEVICE_PATH_PROTOCOL      *DevicePath;
  CONST CHAR16                  *Description;
  CONST CHAR16                  *LinuxPath;
  UINTN                         BootOptionCount;

  if (!FeaturePcdGet (PcdLinuxEfiApplicationBoot)) {
    return;
  }

  LinuxPath   = (CONST CHAR16 *)PcdGetPtr (PcdLinuxEfiApplicationPath);
  Description = (CONST CHAR16 *)PcdGetPtr (PcdLinuxEfiApplicationDescription);

  Status = PlatformLinuxEfiBootValidatePath (LinuxPath);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: invalid Linux EFI application path: %r\n", __func__, Status));
    return;
  }

  Status = PlatformLinuxEfiBootValidateDescription (Description);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: invalid Linux EFI application description: %r\n", __func__, Status));
    return;
  }

  DevicePath = NULL;
  Status     = PlatformFindLinuxEfiApplicationDevicePath (LinuxPath, &DevicePath);
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_INFO,
      "%a: Linux EFI application %s unavailable: %r; using normal boot fallback\n",
      __func__,
      LinuxPath,
      Status
      ));
    return;
  }

  Status = EfiBootManagerInitializeLoadOption (
             &NewOption,
             LoadOptionNumberUnassigned,
             LoadOptionTypeBoot,
             LOAD_OPTION_ACTIVE,
             (CHAR16 *)Description,
             DevicePath,
             NULL,
             0
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to initialize Linux EFI boot option: %r\n", __func__, Status));
    FreePool (DevicePath);
    return;
  }

  BootOptions = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);
  OptionIndex = PlatformFindLoadOption (&NewOption, BootOptions, BootOptionCount);
  if (OptionIndex == -1) {
    Status = EfiBootManagerAddLoadOptionVariable (&NewOption, 0);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a: failed to register Linux EFI boot option: %r\n", __func__, Status));
    } else {
      DEBUG ((DEBUG_INFO, "%a: registered Linux EFI application boot option %s\n", __func__, LinuxPath));
    }
  }

  EfiBootManagerFreeLoadOption (&NewOption);
  EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
  FreePool (DevicePath);
}

STATIC
BOOLEAN
PlatformPciControllerIsUsb (
  IN CONST UINT8  ClassCode[3]
  )
{
  return (ClassCode[2] == PCI_CLASS_SERIAL) &&
         (ClassCode[1] == PCI_CLASS_SERIAL_USB);
}

STATIC
BOOLEAN
PlatformPciControllerIsSdMmc (
  IN CONST UINT8  ClassCode[3]
  )
{
  return (ClassCode[2] == PCI_CLASS_SYSTEM_PERIPHERAL) &&
         (ClassCode[1] == PCI_SUBCLASS_SD_HOST_CONTROLLER) &&
         ((ClassCode[0] == 0x00) || (ClassCode[0] == 0x01));
}

STATIC
BOOLEAN
PlatformPciControllerIsInternalStorage (
  IN CONST UINT8  ClassCode[3]
  )
{
  if (ClassCode[2] != PCI_CLASS_MASS_STORAGE) {
    return FALSE;
  }

  return (BOOLEAN)(
                  (ClassCode[1] != PCI_CLASS_MASS_STORAGE_FLOPPY) &&
                  (ClassCode[1] != PCI_CLASS_MASS_STORAGE_IPI)
                  );
}

STATIC
BOOLEAN
PlatformPciControllerIsNetwork (
  IN CONST UINT8  ClassCode[3]
  )
{
  return (ClassCode[2] == PCI_CLASS_NETWORK);
}

STATIC
CONST CHAR8 *
PlatformBootDiscoveryName (
  IN PLATFORM_BOOT_DISCOVERY_TYPE  DiscoveryType
  )
{
  switch (DiscoveryType) {
    case PlatformBootDiscoveryInternalStorage:
      return "internal-storage";
    case PlatformBootDiscoveryUsbMassStorage:
      return "usb-mass-storage";
    case PlatformBootDiscoveryRemovableMedia:
      return "removable-media";
    case PlatformBootDiscoveryNetwork:
      return "network";
    default:
      return "unknown";
  }
}

STATIC
BOOLEAN
PlatformConnectPciStorage (
  IN PLATFORM_BOOT_DISCOVERY_TYPE  DiscoveryType
  )
{
  EFI_STATUS           Status;
  EFI_HANDLE           *Handles;
  EFI_PCI_IO_PROTOCOL  *PciIo;
  UINTN                HandleCount;
  UINTN                Index;
  UINTN                Retry;
  BOOLEAN              UsableBootPath;
  UINT8                ClassCode[3];

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_INFO,
      "No PCI handles available for %a discovery\n",
      PlatformBootDiscoveryName (DiscoveryType)
      ));
    EfiBootManagerRefreshAllBootOption ();
    switch (DiscoveryType) {
      case PlatformBootDiscoveryInternalStorage:
        return PlatformHasUsableInternalBootPath ();
      case PlatformBootDiscoveryUsbMassStorage:
      case PlatformBootDiscoveryRemovableMedia:
        return PlatformHasUsableStorageBootPath ();
      default:
        return FALSE;
    }
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (Handles[Index], &gEfiPciIoProtocolGuid, (VOID **)&PciIo);
    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0x09, sizeof (ClassCode), ClassCode);
    if (EFI_ERROR (Status)) {
      continue;
    }

    if (DiscoveryType == PlatformBootDiscoveryInternalStorage) {
      if (!PlatformPciControllerIsInternalStorage (ClassCode)) {
        continue;
      }

      DEBUG ((DEBUG_INFO, "Connecting internal storage paths on PCI controller\n"));
      gBS->ConnectController (
             Handles[Index],
             NULL,
             NULL,
             TRUE
             );
      continue;
    }

    if (DiscoveryType == PlatformBootDiscoveryNetwork) {
      if (!PlatformPciControllerIsNetwork (ClassCode)) {
        continue;
      }

      DEBUG ((DEBUG_INFO, "Connecting network boot paths on PCI controller\n"));
      gBS->ConnectController (
             Handles[Index],
             NULL,
             NULL,
             TRUE
             );
      continue;
    }

    if ((DiscoveryType == PlatformBootDiscoveryUsbMassStorage) ||
        (DiscoveryType == PlatformBootDiscoveryRemovableMedia))
    {
      if (!PlatformPciControllerIsUsb (ClassCode)) {
        if (DiscoveryType == PlatformBootDiscoveryUsbMassStorage) {
          continue;
        }
      } else {
        DEBUG ((DEBUG_INFO, "Connecting USB mass-storage paths on PCI controller\n"));
        gBS->ConnectController (
               Handles[Index],
               NULL,
               (EFI_DEVICE_PATH_PROTOCOL *)&mUsbMassStorageDevicePath,
               TRUE
               );
        continue;
      }
    }

    if (DiscoveryType != PlatformBootDiscoveryRemovableMedia) {
      continue;
    }

    if (!PlatformPciControllerIsSdMmc (ClassCode)) {
      continue;
    }

    DEBUG ((DEBUG_INFO, "Connecting SD/MMC paths on PCI controller\n"));
    gBS->ConnectController (
           Handles[Index],
           NULL,
           NULL,
           TRUE
           );
  }

  FreePool (Handles);

  if (DiscoveryType == PlatformBootDiscoveryNetwork) {
    EfiBootManagerRefreshAllBootOption ();
    return TRUE;
  }

  for (Retry = 0; Retry <= PLATFORM_REMOVABLE_REFRESH_RETRIES; Retry++) {
    EfiBootManagerRefreshAllBootOption ();

    if (DiscoveryType == PlatformBootDiscoveryInternalStorage) {
      UsableBootPath = PlatformHasUsableInternalBootPath ();
    } else {
      UsableBootPath = PlatformHasUsableStorageBootPath ();
    }

    if (UsableBootPath) {
      return TRUE;
    }

    if (Retry < PLATFORM_REMOVABLE_REFRESH_RETRIES) {
      gBS->Stall (PLATFORM_REMOVABLE_REFRESH_STALL_US);
    }
  }

  return FALSE;
}

STATIC
BOOLEAN
PlatformConnectInternalStorage (
  VOID
  )
{
  return PlatformConnectPciStorage (PlatformBootDiscoveryInternalStorage);
}

STATIC
BOOLEAN
PlatformConnectUsbMassStorage (
  VOID
  )
{
  return PlatformConnectPciStorage (PlatformBootDiscoveryUsbMassStorage);
}

STATIC
BOOLEAN
PlatformConnectRemovableMedia (
  VOID
  )
{
  return PlatformConnectPciStorage (PlatformBootDiscoveryRemovableMedia);
}

STATIC
BOOLEAN
PlatformConnectNetworkBoot (
  VOID
  )
{
  return PlatformConnectPciStorage (PlatformBootDiscoveryNetwork);
}

/**
  Do the platform specific action before the console is connected.

  Such as:
    Update console variable;
    Register new Driver#### or Boot####;
    Signal ReadyToLock event.
**/
VOID
EFIAPI
PlatformBootManagerBeforeConsole (
  VOID
  )
{
  EFI_STATUS                    Status;
  EFI_INPUT_KEY                 Enter;
  EFI_INPUT_KEY                 CustomKey;
  EFI_INPUT_KEY                 Down;
  EFI_BOOT_MANAGER_LOAD_OPTION  BootOption;
  EDKII_PLATFORM_LOGO_PROTOCOL  *PlatformLogo;
  BOOLEAN                       ConsoleInitialized;

  Cdk2InstallPlatformBootManagerProtocol ();

  //
  // Register ENTER as CONTINUE key
  //
  Enter.ScanCode    = SCAN_NULL;
  Enter.UnicodeChar = CHAR_CARRIAGE_RETURN;
  EfiBootManagerRegisterContinueKeyOption (0, &Enter, NULL);

  if (FixedPcdGetBool (PcdBootManagerEscape)) {
    //
    // Map Esc to Boot Manager Menu
    //
    CustomKey.ScanCode    = SCAN_ESC;
    CustomKey.UnicodeChar = CHAR_NULL;
  } else {
    //
    // Map Esc to Boot Manager Menu
    //
    CustomKey.ScanCode    = SCAN_F2;
    CustomKey.UnicodeChar = CHAR_NULL;
  }

  EfiBootManagerGetBootManagerMenu (&BootOption);
  EfiBootManagerAddKeyOptionVariable (NULL, (UINT16)BootOption.OptionNumber, 0, &CustomKey, NULL);

  //
  // Also add Down key to Boot Manager Menu since some serial terminals don't support F2 key.
  //
  Down.ScanCode    = SCAN_DOWN;
  Down.UnicodeChar = CHAR_NULL;
  EfiBootManagerGetBootManagerMenu (&BootOption);
  EfiBootManagerAddKeyOptionVariable (NULL, (UINT16)BootOption.OptionNumber, 0, &Down, NULL);

  //
  // Process update capsules that don't contain embedded drivers.
  //
  ConsoleInitialized = FALSE;
  if (GetBootModeHob () == BOOT_ON_FLASH_UPDATE) {
    // TODO: when enabling capsule support for laptops, add a battery check here
    PlatformConsoleInit ();
    ConsoleInitialized = TRUE;

    Status = gBS->LocateProtocol (&gEdkiiPlatformLogoProtocolGuid, NULL, (VOID **)&PlatformLogo);
    if (!EFI_ERROR (Status) && (gST != NULL) && (gST->ConOut != NULL)) {
      gST->ConOut->ClearScreen (gST->ConOut);
      PlatformEnableBootLogo ();
    }

    Status = ProcessCapsules ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a(): ProcessCapsule() failed with: %r\n", __func__, Status));
    }
  }

  //
  // Install ready to lock.
  // This needs to be done before option rom dispatched.
  //
  InstallReadyToLock ();

  //
  // Dispatch deferred images after EndOfDxe event and ReadyToLock installation.
  //
  EfiBootManagerDispatchDeferredImages ();

  if (!ConsoleInitialized) {
    PlatformConsoleInit ();
  }
}

/**
  Do the platform specific action after the console is connected.

  Such as:
    Dynamically switch output mode;
    Signal console ready platform customized event;
    Run diagnostics like memory testing;
    Connect certain devices;
    Dispatch additional option roms.
**/
VOID
EFIAPI
PlatformBootManagerAfterConsole (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT16      BootTimeOut;

  ConfigureLowBatteryBootGuard ();

  //
  // Ensure TCG2 physical presence variables are initialized for the OPAL BlockSID UI.
  //
  Tcg2PhysicalPresenceLibProcessRequest (NULL);

  //
  // Connecting removable media can perturb the memory map used for S4 resume.
  //
  if (GetBootModeHob () != BOOT_ON_S4_RESUME) {
    if (FeaturePcdGet (PcdConnectAllDevices)) {
      EfiBootManagerConnectAll ();
      EfiBootManagerRefreshAllBootOption ();
    } else if (!PlatformHasUsableInternalBootPath ()) {
      DEBUG ((
        DEBUG_INFO,
        "No usable internal boot path; discovering internal storage\n"
        ));
      PlatformConnectInternalStorage ();

      if (!PlatformHasUsableInternalBootPath ()) {
        DEBUG ((
          DEBUG_INFO,
          "No usable internal boot path; discovering USB mass-storage fallback\n"
          ));
        if (!PlatformConnectUsbMassStorage ()) {
          DEBUG ((DEBUG_INFO, "No usable USB mass-storage boot path; discovering removable media\n"));
          if (!PlatformConnectRemovableMedia ()) {
            DEBUG ((DEBUG_INFO, "No usable removable boot path; discovering network boot paths\n"));
            PlatformConnectNetworkBoot ();
          }
        }
      }
    } else {
      DEBUG ((
        DEBUG_INFO,
        "Skipping global device discovery; internal boot path is available\n"
        ));
    }
  }

  //
  // Active BOOT_ON_FLASH_UPDATE mode means that at least one capsule has been
  // discovered by a bootloader and passed for further processing into EDK which
  // created EFI_HOB_TYPE_UEFI_CAPSULE HOB(s).
  //
  // Process update capsules that weren't processed on the first call to
  // ProcessCapsules() in PlatformBootManagerBeforeConsole().
  //
  if (GetBootModeHob () == BOOT_ON_FLASH_UPDATE) {
    // TODO: when enabling capsule support for laptops, add a battery check here
    Status = ProcessCapsules ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a(): ProcessCapsule() failed with: %r\n", __func__, Status));
    }

    //
    // Reset the system to disable SMI handler in order to exclude the
    // possibility of it being used outside of the firmware.
    //
    // In practice, this will rarely execute because even the first
    // ProcessCapsules() invocation might do a reset if all capsules were
    // processed and at least one of them needed a reset.  This is just to catch
    // a case when this doesn't happen which is possible on error.
    //
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  }

  SyncEsrtFmpInfo ();

  //
  // Process TPM PPI request
  //
  Status=TcgPhysicalPresenceLibProcessRequest (); // Check for TPM1.2 First
  if (EFI_ERROR (Status)) {
    Tcg2PhysicalPresenceLibProcessRequest (NULL); //Check for TPM2.0
  }

  DisplayPlatformBootLogo ();

  PlatformRegisterLinuxEfiApplicationBootOption ();

  //
  // Register UEFI Shell
  //
  PlatformRegisterFvBootOption (&gUefiShellFileGuid, L"UEFI Shell", LOAD_OPTION_ACTIVE);

  BootTimeOut = PlatformBootManagerGetWaitTimeout (PcdGet16 (PcdPlatformBootTimeOut));
  if (BootTimeOut == 0) {
    return;
  }

  if (FixedPcdGetBool (PcdBootManagerEscape)) {
    if (!DisplayBootManagerPrompt (TRUE, BootTimeOut)) {
      if (mLowBatteryBootGuardActive) {
        Print (
          L"\n"
          L"    Battery critically low.\n"
          L"    Shutting down in %u seconds, press ENTER to boot directly.\n"
          L"    Esc or Down      to enter Boot Manager Menu.\n"
          L"\n",
          BootTimeOut
          );
      } else {
        Print (
          L"\n"
          L"    Esc or Down      to enter Boot Manager Menu.\n"
          L"    ENTER            to boot directly.\n"
          L"\n"
          );
      }
    }
  } else {
    if (!DisplayBootManagerPrompt (FALSE, BootTimeOut)) {
      if (mLowBatteryBootGuardActive) {
        Print (
          L"\n"
          L"    Battery critically low.\n"
          L"    Shutting down in %u seconds, press ENTER to boot directly.\n"
          L"    F2 or Down      to enter Boot Manager Menu.\n"
          L"\n",
          BootTimeOut
          );
      } else {
        Print (
          L"\n"
          L"    F2 or Down      to enter Boot Manager Menu.\n"
          L"    ENTER           to boot directly.\n"
          L"\n"
          );
      }
    }
  }
}

/**
  This function is called each second during the boot manager waits the timeout.

  @param TimeoutRemain  The remaining timeout.
**/
VOID
EFIAPI
PlatformBootManagerWaitCallback (
  UINT16  TimeoutRemain
  )
{
  if (mLowBatteryBootGuardActive) {
    if ((TimeoutRemain != 0) && (TimeoutRemain != 0xFFFF)) {
      DisplayLowBatteryBootLogo ();
      DisplayBootManagerPrompt (FixedPcdGetBool (PcdBootManagerEscape), TimeoutRemain);
      return;
    }

    if (TimeoutRemain == 0) {
      DEBUG ((DEBUG_INFO, "%a: low-battery boot splash timeout, shutting down\n", __func__));
      gRT->ResetSystem (EfiResetShutdown, EFI_SUCCESS, 0, NULL);
    }

    return;
  }

  if ((TimeoutRemain != 0) && (TimeoutRemain != 0xFFFF)) {
    DisplayBootManagerPrompt (FixedPcdGetBool (PcdBootManagerEscape), TimeoutRemain);
  }

  /* Clear text from screen once timeout expires */
  if (TimeoutRemain == 0) {
    if ((gST != NULL) && (gST->ConOut != NULL)) {
      gST->ConOut->ClearScreen (gST->ConOut);
    }

    PlatformEnableBootLogo ();
  }
  return;
}

/**
  This function is called after the boot manager timeout wait exits and before
  boot options are launched.
**/
VOID
EFIAPI
PlatformBootManagerAfterBootWait (
  VOID
  )
{
  if (!mLowBatteryBootGuardActive) {
    return;
  }

  DEBUG ((DEBUG_INFO, "%a: restoring boot logo after low-battery override\n", __func__));

  mLowBatteryBootGuardActive = FALSE;
  mLowBatteryBootLogoShown   = FALSE;

  DisplayPlatformBootLogo ();
}

/**
  The function is called when no boot option could be launched,
  including platform recovery options and options pointing to applications
  built into firmware volumes.

  If this function returns, BDS attempts to enter an infinite loop.
**/
VOID
EFIAPI
PlatformBootManagerUnableToBoot (
  VOID
  )
{
  return;
}
