/** @file
  This file include all platform action which can be customized
  by IBV/OEM.

Copyright (c) 2015 - 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PlatformBootManager.h"
#include "PlatformConsole.h"
#include <Guid/EventGroup.h>
#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/GlobalVariable.h>
#include <IndustryStandard/Pci.h>
#include <IndustryStandard/Usb.h>
#include <Library/BmpSupportLib.h>
#include <Library/BootKeyAuthLib.h>
#include <Library/BootKeyCredentialStoreLib.h>
#include <Library/BootKeyPlatformSecurityLib.h>
#include <Library/BootKeyPowerSafetyLib.h>
#include <Library/BootKeyProvisionLib.h>
#include <Library/Tcg2PhysicalPresenceLib.h>
#include <Library/TimerLib.h>
#include <Protocol/BatteryStatus.h>
#include <Protocol/EsrtManagement.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/PciIo.h>

#define PLATFORM_USB_MASS_STORAGE_CLASS  0x08

typedef struct {
  USB_CLASS_DEVICE_PATH       UsbClass;
  EFI_DEVICE_PATH_PROTOCOL    End;
} USB_MASS_STORAGE_DEVICE_PATH;

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

#define LOW_BATTERY_BOOT_TIMEOUT             10
#define BOOT_KEY_FAILURE_STALL_US            250000
#define BOOT_UI_HIDPI_HORIZONTAL_RESOLUTION  1920
#define BOOT_UI_HIDPI_VERTICAL_RESOLUTION    1080

STATIC EFI_GUID  mLowBatteryLogoFileGuid = {
  0xbe6e1243, 0x682c, 0x4186, { 0x81, 0x51, 0x44, 0x8d, 0x48, 0xaf, 0xe3, 0x41 }
};

STATIC BOOLEAN  mLowBatteryBootGuardActive;
STATIC BOOLEAN  mLowBatteryBootLogoShown;
STATIC BOOLEAN  mBootKeyLowBatteryTimerActive;
STATIC UINT64   mBootKeyLowBatteryLastCounter;
STATIC UINT64   mBootKeyLowBatteryElapsedNs;

STATIC
BOOLEAN
PlatformBootKeyVariableEquals (
  IN CHAR16    *Name,
  IN EFI_GUID  *Guid,
  IN UINT32    ExpectedAttributes,
  IN UINT8     ExpectedValue
  )
{
  UINT32      Attributes;
  UINT8       Value;
  UINTN       Size;
  EFI_STATUS  Status;

  Attributes = 0;
  Value      = 0;
  Size       = sizeof (Value);
  Status     = gRT->GetVariable (Name, Guid, &Attributes, &Size, &Value);
  return (Status == EFI_SUCCESS) && (Size == sizeof (Value)) &&
         (Attributes == ExpectedAttributes) && (Value == ExpectedValue);
}

STATIC
BOOLEAN
PlatformBootKeySecureBootEnabled (
  VOID
  )
{
  return PlatformBootKeyVariableEquals (
           EFI_SETUP_MODE_NAME,
           &gEfiGlobalVariableGuid,
           EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
           0
           ) &&
         PlatformBootKeyVariableEquals (
           EFI_SECURE_BOOT_MODE_NAME,
           &gEfiGlobalVariableGuid,
           EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
           1
           ) &&
         PlatformBootKeyVariableEquals (
           EFI_SECURE_BOOT_ENABLE_NAME,
           &gEfiSecureBootEnableDisableGuid,
           EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
           1
           ) &&
         PlatformBootKeyVariableEquals (
           EFI_CUSTOM_MODE_NAME,
           &gEfiCustomModeEnableGuid,
           EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
           0
           );
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

      Pixel                                                 = Source[Row * SourceStride + Column];
      DestinationColumn                                     = Column * 2;
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
  EFI_STATUS                     Status;
  EFI_HII_FONT_PROTOCOL          *HiiFont;
  EFI_IMAGE_OUTPUT               *Blt;
  EFI_IMAGE_OUTPUT               *ScaledBlt;
  EFI_IMAGE_OUTPUT               *RenderBlt;
  EFI_FONT_DISPLAY_INFO          FontInfo;
  EFI_HII_ROW_INFO               *RowInfoArray;
  UINTN                          RowInfoArraySize;
  UINTN                          GlyphWidth;
  UINTN                          GlyphHeight;
  UINTN                          PointX;
  UINTN                          PointY;
  UINTN                          BitmapWidth;
  UINTN                          BitmapHeight;
  UINTN                          RenderWidth;
  UINTN                          RenderHeight;
  UINTN                          BltWidth;
  UINTN                          BltHeight;
  UINTN                          BltDelta;
  UINTN                          Index;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBitmap;

  if ((GraphicsOutput == NULL) || (String == NULL) || (TextScale == 0) || (TextScale > 2)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiHiiFontProtocolGuid, NULL, (VOID **)&HiiFont);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: HII font protocol unavailable: %r\n", __func__, Status));
    return Status;
  }

  GlyphWidth  = EFI_GLYPH_WIDTH * TextScale;
  GlyphHeight = EFI_GLYPH_HEIGHT * TextScale;
  PointX      = Column * GlyphWidth;
  PointY      = Row * GlyphHeight;

  Blt = AllocateZeroPool (sizeof (EFI_IMAGE_OUTPUT));
  if (Blt == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  BitmapWidth  = (StrLen (String) + 2) * EFI_GLYPH_WIDTH;
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
  FontInfo.ForegroundColor.Blue  = 0xc0;
  FontInfo.ForegroundColor.Green = 0xc0;
  FontInfo.ForegroundColor.Red   = 0xc0;
  FontInfo.BackgroundColor.Blue  = 0x00;
  FontInfo.BackgroundColor.Green = 0x00;
  FontInfo.BackgroundColor.Red   = 0x00;
  FontInfo.FontInfoMask          = EFI_FONT_INFO_SYS_FONT | EFI_FONT_INFO_SYS_SIZE | EFI_FONT_INFO_SYS_STYLE;
  FontInfo.FontInfo.FontSize     = EFI_GLYPH_HEIGHT;
  FontInfo.FontInfo.FontName[0]  = CHAR_NULL;
  RowInfoArray                   = NULL;
  RowInfoArraySize               = 0;

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

  BootLogoEnableLogo ();
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
EFIAPI
PlatformBootKeyWaitCallback (
  VOID
  )
{
  UINT64  CounterEnd;
  UINT64  CounterStart;
  UINT64  CurrentCounter;
  UINT64  ElapsedTicks;

  if (!IsLowBatteryBootGuardRequired ()) {
    mBootKeyLowBatteryTimerActive = FALSE;
    return;
  }

  CurrentCounter = GetPerformanceCounter ();
  if (!mBootKeyLowBatteryTimerActive) {
    mBootKeyLowBatteryTimerActive = TRUE;
    mBootKeyLowBatteryLastCounter = CurrentCounter;
    mBootKeyLowBatteryElapsedNs   = 0;
    return;
  }

  GetPerformanceCounterProperties (&CounterStart, &CounterEnd);
  if (CounterStart < CounterEnd) {
    ElapsedTicks = (CurrentCounter >= mBootKeyLowBatteryLastCounter) ?
                   CurrentCounter - mBootKeyLowBatteryLastCounter :
                   (CounterEnd - mBootKeyLowBatteryLastCounter) +
                   (CurrentCounter - CounterStart) + 1;
  } else {
    ElapsedTicks = (CurrentCounter <= mBootKeyLowBatteryLastCounter) ?
                   mBootKeyLowBatteryLastCounter - CurrentCounter :
                   (mBootKeyLowBatteryLastCounter - CounterEnd) +
                   (CounterStart - CurrentCounter) + 1;
  }

  mBootKeyLowBatteryLastCounter = CurrentCounter;
  mBootKeyLowBatteryElapsedNs  += GetTimeInNanoSecond (ElapsedTicks);
  if (mBootKeyLowBatteryElapsedNs >=
      (LOW_BATTERY_BOOT_TIMEOUT * 1000000000ULL))
  {
    DEBUG ((DEBUG_INFO, "%a: critical battery timeout, shutting down\n", __func__));
    gRT->ResetSystem (EfiResetShutdown, EFI_SUCCESS, 0, NULL);
  }
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

  @retval EFI_SUCCESS  EndOfDxe was signaled and SMM was locked, or this build
                       does not expect SMM and the platform does not expose it.
  @return               Error returned while locating SMM or installing the
                        ReadyToLock protocol.

**/
EFI_STATUS
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
  Status = EfiEventGroupSignal (&gEfiEndOfDxeEventGroupGuid);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to signal EndOfDxe: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "All EndOfDxe callbacks have returned successfully\n"));

  //
  // Install DxeSmmReadyToLock protocol in order to lock SMM
  //
  Status = gBS->LocateProtocol (&gEfiSmmAccess2ProtocolGuid, NULL, (VOID **)&SmmAccess);
  if (Status == EFI_NOT_FOUND) {
    if (FixedPcdGetBool (PcdBootKeySmmExpected)) {
      DEBUG ((DEBUG_ERROR, "SMM is required but SmmAccess2 is unavailable\n"));
      return EFI_SECURITY_VIOLATION;
    }

    DEBUG ((DEBUG_INFO, "SMM is unavailable; no ReadyToLock protocol is required\n"));
    return EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &Handle,
                  &gEfiDxeSmmReadyToLockProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!SmmAccess->LockState || SmmAccess->OpenState) {
    DEBUG ((DEBUG_ERROR, "ReadyToLock did not close and lock SMRAM\n"));
    return EFI_SECURITY_VIOLATION;
  }

  DEBUG ((DEBUG_INFO, "InstallReadyToLock  end\n"));
  return EFI_SUCCESS;
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
PlatformSelectedBootOptionUsesInternalDisk (
  VOID
  )
{
  EFI_STATUS                    Status;
  UINT16                        BootNext;
  UINTN                         DataSize;
  CHAR16                        BootOptionName[16];
  EFI_BOOT_MANAGER_LOAD_OPTION  BootNextOption;
  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOptions;
  EFI_BOOT_MANAGER_LOAD_OPTION  *SelectedOption;
  UINTN                         BootOptionCount;
  UINTN                         Index;
  BOOLEAN                       HaveBootNext;
  BOOLEAN                       UsesInternalDisk;

  BootOptions      = NULL;
  BootOptionCount  = 0;
  SelectedOption   = NULL;
  HaveBootNext     = FALSE;
  UsesInternalDisk = FALSE;
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
      SelectedOption = &BootNextOption;
      HaveBootNext   = TRUE;
    }
  }

  if (!HaveBootNext) {
    BootOptions = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);
    for (Index = 0; Index < BootOptionCount; Index++) {
      if ((BootOptions[Index].Attributes & LOAD_OPTION_ACTIVE) != 0) {
        SelectedOption = &BootOptions[Index];
        break;
      }
    }
  }

  if (SelectedOption != NULL) {
    UsesInternalDisk = PlatformBootOptionUsesInternalDisk (SelectedOption);
    DEBUG ((
      DEBUG_INFO,
      "Selected boot path is %a an internal disk\n",
      UsesInternalDisk ? "" : "not"
      ));
  } else {
    DEBUG ((DEBUG_INFO, "No active boot option selected\n"));
  }

  if (HaveBootNext) {
    EfiBootManagerFreeLoadOption (&BootNextOption);
  }

  EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
  return UsesInternalDisk;
}

STATIC
VOID
PlatformConnectRemovableMedia (
  VOID
  )
{
  EFI_STATUS           Status;
  EFI_HANDLE           *Handles;
  EFI_PCI_IO_PROTOCOL  *PciIo;
  UINTN                HandleCount;
  UINTN                Index;
  UINT8                ClassCode[3];

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiPciIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "No PCI handles available for removable-media discovery\n"));
    return;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (Handles[Index], &gEfiPciIoProtocolGuid, (VOID **)&PciIo);
    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0x09, sizeof (ClassCode), ClassCode);
    if (EFI_ERROR (Status) ||
        (ClassCode[2] != PCI_CLASS_SERIAL) ||
        (ClassCode[1] != PCI_CLASS_SERIAL_USB))
    {
      continue;
    }

    DEBUG ((DEBUG_INFO, "Connecting USB mass-storage paths on PCI controller\n"));
    gBS->ConnectController (
           Handles[Index],
           NULL,
           (EFI_DEVICE_PATH_PROTOCOL *)&mUsbMassStorageDevicePath,
           TRUE
           );
  }

  FreePool (Handles);
  EfiBootManagerRefreshAllBootOption ();
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
  BOOLEAN                       AuthenticationRequired;
  BOOLEAN                       FactoryProvisioningRequired;
  BOOLEAN                       ReadyToLockInstalled;

  AuthenticationRequired      = BootKeyAuthenticationRequired ();
  FactoryProvisioningRequired = BootKeyFactoryProvisioningRequired ();
  ReadyToLockInstalled        = FALSE;

  //
  // Close the EndOfDxe boundary before waiting on any external authenticator
  // input. The platform verifier separately checks the coreboot-owned SMM
  // boundary directly in hardware. Authenticate before capsule processing,
  // deferred-image dispatch, Driver#### execution, console connection, or
  // general device discovery. The statically linked authenticator may prepare
  // only its minimal trusted FIDO transport path.
  //
  if (AuthenticationRequired || FactoryProvisioningRequired) {
    Status = BootKeyPowerSafetyArm ();
    if (Status != EFI_SUCCESS) {
      DEBUG ((
        DEBUG_ERROR,
        "Boot-key independent power safety could not be established: %r\n",
        Status
        ));
      BootKeyAbortCredentialStore ();
      do {
        gRT->ResetSystem (EfiResetShutdown, EFI_DEVICE_ERROR, 0, NULL);
        gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
      } while (TRUE);
    }

    Status = BootKeyVerifyPlatformSecurityBoundary ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Boot-key platform boundary is not protected: %r\n", Status));
      BootKeyAbortCredentialStore ();
      do {
        PlatformBootKeyWaitCallback ();
        gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
      } while (TRUE);
    }

    if (!PlatformBootKeySecureBootEnabled ()) {
      DEBUG ((DEBUG_ERROR, "Boot-key gate requires active Secure Boot.\n"));
      BootKeyAbortCredentialStore ();
      do {
        PlatformBootKeyWaitCallback ();
        gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
      } while (TRUE);
    }

    Status = InstallReadyToLock ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Boot-key gate could not establish ReadyToLock: %r\n", Status));
      BootKeyAbortCredentialStore ();
      do {
        PlatformBootKeyWaitCallback ();
        gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
      } while (TRUE);
    }

    ReadyToLockInstalled = TRUE;
    Status               = BootKeyPrepareCredentialStore (FactoryProvisioningRequired);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Boot-key credential store is not protected: %r\n", Status));
      BootKeyAbortCredentialStore ();
      do {
        PlatformBootKeyWaitCallback ();
        gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
      } while (TRUE);
    }

    mBootKeyLowBatteryTimerActive = FALSE;
    if (AuthenticationRequired) {
      BootKeyRequireAuthentication (PlatformBootKeyWaitCallback);

      Status = BootKeyCloseCredentialStore ();
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "Boot-key credential write window did not close: %r\n", Status));
        BootKeyAbortCredentialStore ();
        do {
          PlatformBootKeyWaitCallback ();
          gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
        } while (TRUE);
      }

      Status = BootKeyPowerSafetyDisarm ();
      if (Status != EFI_SUCCESS) {
        DEBUG ((
          DEBUG_ERROR,
          "Boot-key independent power safety could not be removed: %r\n",
          Status
          ));
        BootKeyAbortCredentialStore ();
        do {
          gRT->ResetSystem (EfiResetShutdown, EFI_DEVICE_ERROR, 0, NULL);
          gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
        } while (TRUE);
      }
    }
  }

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
      BootLogoEnableLogo ();
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
  if (!ReadyToLockInstalled) {
    Status = InstallReadyToLock ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Boot could not establish ReadyToLock: %r\n", Status));
      do {
        PlatformBootKeyWaitCallback ();
        gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
      } while (TRUE);
    }
  }

  //
  // Factory provisioning deliberately runs at the same closed hardware and
  // PCR 6 write-window boundary as the production gate. A provisioning image
  // is never a
  // general-purpose boot image: whether provisioning succeeds or fails, power
  // the machine off so production firmware must be programmed before use.
  //
  if (FactoryProvisioningRequired) {
    Status = BootKeyProvisionFactorySet ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "BOOT_KEY_PROVISION_FAILED: %r\n", Status));
      BootKeyAbortCredentialStore ();
    } else {
      Status = BootKeyCloseCredentialStore ();
      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_ERROR, "BOOT_KEY_PROVISION_CLOSE_FAILED: %r\n", Status));
        BootKeyAbortCredentialStore ();
      } else {
        DEBUG ((DEBUG_INFO, "BOOT_KEY_PROVISION_COMPLETE\n"));
      }
    }

    do {
      gRT->ResetSystem (EfiResetShutdown, Status, 0, NULL);
      gBS->Stall (BOOT_KEY_FAILURE_STALL_US);
    } while (TRUE);
  }

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
  // A boot-key image disables the platform hierarchy before external input.
  // TPM Clear, PCR allocation, and other platform-authorized maintenance must
  // therefore use separately signed recovery firmware instead of the normal
  // OS-requested PPI path.
  //
  if (!FixedPcdGetBool (PcdBootKeyModeEnabled)) {
    //
    // Ensure TCG2 physical presence variables are initialized for the OPAL
    // BlockSID UI.
    //
    Tcg2PhysicalPresenceLibProcessRequest (NULL);
  }

  //
  // Connecting removable media can perturb the memory map used for S4 resume.
  //
  if (GetBootModeHob () != BOOT_ON_S4_RESUME) {
    if (FeaturePcdGet (PcdConnectAllDevices)) {
      EfiBootManagerConnectAll ();
      EfiBootManagerRefreshAllBootOption ();
    } else if (!PlatformSelectedBootOptionUsesInternalDisk ()) {
      DEBUG ((
        DEBUG_INFO,
        "Selected boot path is removable or unavailable; discovering removable media\n"
        ));
      PlatformConnectRemovableMedia ();
    } else {
      DEBUG ((
        DEBUG_INFO,
        "Skipping global device discovery; connecting the selected boot path on demand\n"
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
  // Process TPM PPI requests only when platform-authorized maintenance is
  // available in this image.
  //
  if (!FixedPcdGetBool (PcdBootKeyModeEnabled)) {
    Status = TcgPhysicalPresenceLibProcessRequest (); // Check for TPM1.2 First
    if (EFI_ERROR (Status)) {
      Tcg2PhysicalPresenceLibProcessRequest (NULL); // Check for TPM2.0
    }
  }

  DisplayPlatformBootLogo ();

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
    gST->ConOut->ClearScreen (gST->ConOut);
    BootLogoEnableLogo ();
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
