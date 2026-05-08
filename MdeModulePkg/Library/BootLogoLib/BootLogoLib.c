/** @file
  This library is only intended to be used by PlatformBootManagerLib
  to show progress bar and LOGO.

Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2016, Microsoft Corporation<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/PlatformLogo.h>
#include <Protocol/BootLogo.h>
#include <Protocol/BootLogo2.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PcdLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

STATIC
VOID
GetHiDpiLogoTransform (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput,
  OUT UINTN                         *DisplayScale,
  OUT UINTN                         *BgrtScale,
  OUT UINTN                         *BgrtOffsetX,
  OUT UINTN                         *BgrtOffsetY
  )
{
  UINT32  HorizontalResolution;
  UINT32  PhysicalHorizontalResolution;
  UINT32  PhysicalVerticalResolution;
  UINT32  VerticalResolution;

  *DisplayScale = 1;
  *BgrtScale    = 1;
  *BgrtOffsetX  = 0;
  *BgrtOffsetY  = 0;

  if ((GraphicsOutput == NULL) ||
      (GraphicsOutput->Mode == NULL) ||
      (GraphicsOutput->Mode->Info == NULL) ||
      !FeaturePcdGet (PcdPayloadFbHiDpiSupport))
  {
    return;
  }

  HorizontalResolution         = GraphicsOutput->Mode->Info->HorizontalResolution;
  VerticalResolution           = GraphicsOutput->Mode->Info->VerticalResolution;
  PhysicalHorizontalResolution = PcdGet32 (PcdVideoHorizontalResolution);
  PhysicalVerticalResolution   = PcdGet32 (PcdVideoVerticalResolution);

  if ((PhysicalHorizontalResolution == 0) || (PhysicalVerticalResolution == 0)) {
    PhysicalHorizontalResolution = HorizontalResolution;
    PhysicalVerticalResolution   = VerticalResolution;
  }

  if ((PhysicalHorizontalResolution <= PcdGet32 (PcdPayloadFbHiDpiScaleThresholdHorizontal)) ||
      (PhysicalVerticalResolution <= PcdGet32 (PcdPayloadFbHiDpiScaleThresholdVertical)) ||
      ((PhysicalHorizontalResolution % 2) != 0) ||
      ((PhysicalVerticalResolution % 2) != 0))
  {
    return;
  }

  //
  // Physical GOP mode: pre-scale the logo before drawing and report that same
  // physical-sized bitmap through BGRT.
  //
  if (GraphicsOutput->Mode->FrameBufferBase != 0) {
    if ((HorizontalResolution == PhysicalHorizontalResolution) &&
        (VerticalResolution == PhysicalVerticalResolution))
    {
      *DisplayScale = 2;
    }

    return;
  }

  //
  // UefiPayloadPkg's HiDPI GOP mode is logical-sized and PixelBltOnly. The GOP
  // scales BLTs into the physical framebuffer, so do not pre-scale for drawing.
  // BGRT, however, is consumed by the OS in physical panel coordinates, so report
  // a physical-sized bitmap and translate coordinates back into that space.
  //
  if ((GraphicsOutput->Mode->Info->PixelFormat == PixelBltOnly) &&
      (HorizontalResolution <= (MAX_UINT32 / 2)) &&
      (VerticalResolution <= (MAX_UINT32 / 2)) &&
      (PhysicalHorizontalResolution >= (HorizontalResolution * 2)) &&
      (PhysicalVerticalResolution >= (VerticalResolution * 2)))
  {
    *BgrtScale   = 2;
    *BgrtOffsetX = (PhysicalHorizontalResolution - (HorizontalResolution * 2)) / 2;
    *BgrtOffsetY = (PhysicalVerticalResolution - (VerticalResolution * 2)) / 2;
  }
}

STATIC
EFI_STATUS
ScaleLogoBlt2x (
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Source,
  IN  UINTN                          SourceWidth,
  IN  UINTN                          SourceHeight,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **Destination
  )
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBitmap;
  UINTN                          DestinationWidth;
  UINTN                          Row;
  UINTN                          Column;

  if ((Source == NULL) || (Destination == NULL) || (SourceWidth == 0) || (SourceHeight == 0)) {
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

      Pixel             = Source[Row * SourceWidth + Column];
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

/**
  Show LOGO returned from Edkii Platform Logo protocol on all consoles.

  @retval EFI_SUCCESS     Logo was displayed.
  @retval EFI_UNSUPPORTED Logo was not found or cannot be displayed.
**/
EFI_STATUS
EFIAPI
BootLogoEnableLogo (
  VOID
  )
{
  EFI_STATUS                             Status;
  EDKII_PLATFORM_LOGO_PROTOCOL           *PlatformLogo;
  EDKII_PLATFORM_LOGO_DISPLAY_ATTRIBUTE  Attribute;
  INTN                                   OffsetX;
  INTN                                   OffsetY;
  UINT32                                 SizeOfX;
  UINT32                                 SizeOfY;
  INTN                                   DestX;
  INTN                                   DestY;
  UINT32                                 Instance;
  EFI_IMAGE_INPUT                        Image;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL          *Blt;
  EFI_GRAPHICS_OUTPUT_PROTOCOL           *GraphicsOutput;
  EFI_BOOT_LOGO_PROTOCOL                 *BootLogo;
  EDKII_BOOT_LOGO2_PROTOCOL              *BootLogo2;
  UINTN                                  NumberOfLogos;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL          *LogoBlt;
  UINTN                                  LogoDestX;
  UINTN                                  LogoDestY;
  UINTN                                  LogoHeight;
  UINTN                                  LogoWidth;
  UINTN                                  NewDestX;
  UINTN                                  NewDestY;
  UINTN                                  BufferSize;
  UINTN                                  DisplayScale;
  UINTN                                  BgrtScale;
  UINTN                                  BgrtOffsetX;
  UINTN                                  BgrtOffsetY;

  Status = gBS->LocateProtocol (&gEdkiiPlatformLogoProtocolGuid, NULL, (VOID **)&PlatformLogo);
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  //
  // Try to open GOP first
  //
  Status = gBS->HandleProtocol (gST->ConsoleOutHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **)&GraphicsOutput);
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  //
  // Try to open Boot Logo Protocol.
  //
  Status = gBS->LocateProtocol (&gEfiBootLogoProtocolGuid, NULL, (VOID **)&BootLogo);
  if (EFI_ERROR (Status)) {
    BootLogo = NULL;
  }

  //
  // Try to open Boot Logo 2 Protocol.
  //
  Status = gBS->LocateProtocol (&gEdkiiBootLogo2ProtocolGuid, NULL, (VOID **)&BootLogo2);
  if (EFI_ERROR (Status)) {
    BootLogo2 = NULL;
  }

  //
  // Erase Cursor from screen
  //
  gST->ConOut->EnableCursor (gST->ConOut, FALSE);

  SizeOfX = GraphicsOutput->Mode->Info->HorizontalResolution;
  SizeOfY = GraphicsOutput->Mode->Info->VerticalResolution;
  GetHiDpiLogoTransform (GraphicsOutput, &DisplayScale, &BgrtScale, &BgrtOffsetX, &BgrtOffsetY);

  Blt           = NULL;
  NumberOfLogos = 0;
  LogoDestX     = 0;
  LogoDestY     = 0;
  LogoHeight    = 0;
  LogoWidth     = 0;
  NewDestX      = 0;
  NewDestY      = 0;
  Instance      = 0;
  DestX         = 0;
  DestY         = 0;
  while (TRUE) {
    //
    // Get image from PlatformLogo protocol.
    //
    Status = PlatformLogo->GetImage (
                             PlatformLogo,
                             &Instance,
                             &Image,
                             &Attribute,
                             &OffsetX,
                             &OffsetY
                             );
    if (EFI_ERROR (Status)) {
      break;
    }

    if (Blt != NULL) {
      FreePool (Blt);
    }

    Blt = Image.Bitmap;

    if (DisplayScale == 2) {
      EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBlt;

      ScaledBlt = NULL;
      Status    = ScaleLogoBlt2x (Blt, Image.Width, Image.Height, &ScaledBlt);
      if (!EFI_ERROR (Status)) {
        FreePool (Blt);
        Blt          = ScaledBlt;
        Image.Bitmap = ScaledBlt;
        Image.Width *= 2;
        Image.Height *= 2;
        OffsetX *= 2;
        OffsetY *= 2;
      } else {
        DEBUG ((DEBUG_INFO, "%a: failed to scale logo for HiDPI boot GOP: %r\n", __func__, Status));
        Status = EFI_SUCCESS;
      }
    }

    //
    // Calculate the display position according to Attribute.
    //
    switch (Attribute) {
      case EdkiiPlatformLogoDisplayAttributeLeftTop:
        DestX = 0;
        DestY = 0;
        break;
      case EdkiiPlatformLogoDisplayAttributeCenterTop:
        DestX = (SizeOfX - Image.Width) / 2;
        DestY = 0;
        break;
      case EdkiiPlatformLogoDisplayAttributeRightTop:
        DestX = SizeOfX - Image.Width;
        DestY = 0;
        break;

      case EdkiiPlatformLogoDisplayAttributeCenterLeft:
        DestX = 0;
        DestY = (SizeOfY - Image.Height) / 2;
        break;
      case EdkiiPlatformLogoDisplayAttributeCenter:
        DestX = (SizeOfX - Image.Width) / 2;
        DestY = (SizeOfY - Image.Height) / 2;
        break;
      case EdkiiPlatformLogoDisplayAttributeCenterRight:
        DestX = SizeOfX - Image.Width;
        DestY = (SizeOfY - Image.Height) / 2;
        break;

      case EdkiiPlatformLogoDisplayAttributeLeftBottom:
        DestX = 0;
        DestY = SizeOfY - Image.Height;
        break;
      case EdkiiPlatformLogoDisplayAttributeCenterBottom:
        DestX = (SizeOfX - Image.Width) / 2;
        DestY = SizeOfY - Image.Height;
        break;
      case EdkiiPlatformLogoDisplayAttributeRightBottom:
        DestX = SizeOfX - Image.Width;
        DestY = SizeOfY - Image.Height;
        break;

      default:
        ASSERT (FALSE);
        continue;
        break;
    }

    DestX += OffsetX;
    DestY += OffsetY;

    if ((DestX >= 0) && (DestY >= 0)) {
      Status = GraphicsOutput->Blt (
                                 GraphicsOutput,
                                 Blt,
                                 EfiBltBufferToVideo,
                                 0,
                                 0,
                                 (UINTN)DestX,
                                 (UINTN)DestY,
                                 Image.Width,
                                 Image.Height,
                                 Image.Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                                 );

      //
      // Report displayed Logo information.
      //
      if (!EFI_ERROR (Status)) {
        NumberOfLogos++;

        if (NumberOfLogos == 1) {
          //
          // The first Logo.
          //
          LogoDestX  = (UINTN)DestX;
          LogoDestY  = (UINTN)DestY;
          LogoWidth  = Image.Width;
          LogoHeight = Image.Height;
        } else {
          //
          // Merge new logo with old one.
          //
          NewDestX   = MIN ((UINTN)DestX, LogoDestX);
          NewDestY   = MIN ((UINTN)DestY, LogoDestY);
          LogoWidth  = MAX ((UINTN)DestX + Image.Width, LogoDestX + LogoWidth) - NewDestX;
          LogoHeight = MAX ((UINTN)DestY + Image.Height, LogoDestY + LogoHeight) - NewDestY;

          LogoDestX = NewDestX;
          LogoDestY = NewDestY;
        }
      }
    }
  }

  if (((BootLogo == NULL) && (BootLogo2 == NULL)) || (NumberOfLogos == 0)) {
    //
    // No logo displayed.
    //
    if (Blt != NULL) {
      FreePool (Blt);
    }

    return Status;
  }

  //
  // Advertise displayed Logo information.
  //
  if (NumberOfLogos == 1) {
    //
    // Only one logo displayed, use its Blt buffer directly for BootLogo protocol.
    //
    LogoBlt = Blt;
    Status  = EFI_SUCCESS;
  } else {
    //
    // More than one Logo displayed, get merged BltBuffer using VideoToBuffer operation.
    //
    if (Blt != NULL) {
      FreePool (Blt);
    }

    //
    // Ensure the LogoHeight * LogoWidth * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL) doesn't overflow
    //
    if (LogoHeight > MAX_UINTN / LogoWidth / sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)) {
      return EFI_UNSUPPORTED;
    }

    BufferSize = LogoWidth * LogoHeight * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);

    LogoBlt = AllocatePool (BufferSize);
    if (LogoBlt == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Status = GraphicsOutput->Blt (
                               GraphicsOutput,
                               LogoBlt,
                               EfiBltVideoToBltBuffer,
                               LogoDestX,
                               LogoDestY,
                               0,
                               0,
                               LogoWidth,
                               LogoHeight,
                               LogoWidth * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                               );
  }

  if (!EFI_ERROR (Status)) {
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BgrtLogoBlt;
    UINTN                          BgrtLogoDestX;
    UINTN                          BgrtLogoDestY;
    UINTN                          BgrtLogoWidth;
    UINTN                          BgrtLogoHeight;

    BgrtLogoBlt    = LogoBlt;
    BgrtLogoDestX  = LogoDestX * BgrtScale + BgrtOffsetX;
    BgrtLogoDestY  = LogoDestY * BgrtScale + BgrtOffsetY;
    BgrtLogoWidth  = LogoWidth * BgrtScale;
    BgrtLogoHeight = LogoHeight * BgrtScale;

    if (BgrtScale > 1) {
      //
      // GOP scaling starts from integer logical coordinates. For odd-sized
      // centered logos that loses the half-pixel before scaling, which can put
      // the reported physical BGRT offset one pixel away from exact center.
      // Plymouth only trusts centered desktop BGRT offsets on an exact match.
      //
      if ((SizeOfX >= LogoWidth) && (LogoDestX == ((SizeOfX - LogoWidth) / 2))) {
        BgrtLogoDestX = (((SizeOfX * BgrtScale) - BgrtLogoWidth) / 2) + BgrtOffsetX;
      }

      if ((SizeOfY >= LogoHeight) && (LogoDestY == ((SizeOfY - LogoHeight) / 2))) {
        BgrtLogoDestY = (((SizeOfY * BgrtScale) - BgrtLogoHeight) / 2) + BgrtOffsetY;
      }
    }

    if (BgrtScale == 2) {
      EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBlt;

      ScaledBlt = NULL;
      Status    = ScaleLogoBlt2x (LogoBlt, LogoWidth, LogoHeight, &ScaledBlt);
      if (!EFI_ERROR (Status)) {
        BgrtLogoBlt = ScaledBlt;
      } else {
        DEBUG ((DEBUG_INFO, "%a: failed to scale BGRT logo for HiDPI boot GOP: %r\n", __func__, Status));
        Status         = EFI_SUCCESS;
        BgrtLogoDestX  = LogoDestX;
        BgrtLogoDestY  = LogoDestY;
        BgrtLogoWidth  = LogoWidth;
        BgrtLogoHeight = LogoHeight;
      }
    }

    //
    // Attempt to register logo with Boot Logo 2 Protocol first
    //
    if (BootLogo2 != NULL) {
      Status = BootLogo2->SetBootLogo (
                            BootLogo2,
                            BgrtLogoBlt,
                            BgrtLogoDestX,
                            BgrtLogoDestY,
                            BgrtLogoWidth,
                            BgrtLogoHeight
                            );
    }

    //
    // If Boot Logo 2 Protocol is not available or registration with Boot Logo 2
    // Protocol failed, then attempt to register logo with Boot Logo Protocol
    //
    if (EFI_ERROR (Status) && (BootLogo != NULL)) {
      Status = BootLogo->SetBootLogo (
                           BootLogo,
                           BgrtLogoBlt,
                           BgrtLogoDestX,
                           BgrtLogoDestY,
                           BgrtLogoWidth,
                           BgrtLogoHeight
                           );
    }

    //
    // Status of this function is EFI_SUCCESS even if registration with Boot
    // Logo 2 Protocol or Boot Logo Protocol fails.
    //
    Status = EFI_SUCCESS;

    if (BgrtLogoBlt != LogoBlt) {
      FreePool (BgrtLogoBlt);
    }
  }

  FreePool (LogoBlt);

  return Status;
}

/**
  Use SystemTable Conout to turn on video based Simple Text Out consoles. The
  Simple Text Out screens will now be synced up with all non video output devices

  @retval EFI_SUCCESS     GOP devices are back in text mode and synced up.

**/
EFI_STATUS
EFIAPI
BootLogoDisableLogo (
  VOID
  )
{
  //
  // Enable Cursor on Screen
  //
  gST->ConOut->EnableCursor (gST->ConOut, TRUE);
  return EFI_SUCCESS;
}

/**

  Update progress bar with title above it. It only works in Graphics mode.

  @param TitleForeground Foreground color for Title.
  @param TitleBackground Background color for Title.
  @param Title           Title above progress bar.
  @param ProgressColor   Progress bar color.
  @param Progress        Progress (0-100)
  @param PreviousValue   The previous value of the progress.

  @retval  EFI_STATUS       Success update the progress bar

**/
EFI_STATUS
EFIAPI
BootLogoUpdateProgress (
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL  TitleForeground,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL  TitleBackground,
  IN CHAR16                         *Title,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL  ProgressColor,
  IN UINTN                          Progress,
  IN UINTN                          PreviousValue
  )
{
  EFI_STATUS                     Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL   *GraphicsOutput;
  UINT32                         SizeOfX;
  UINT32                         SizeOfY;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Color;
  UINTN                          BlockHeight;
  UINTN                          BlockWidth;
  UINTN                          BlockNum;
  UINTN                          PosX;
  UINTN                          PosY;
  UINTN                          Index;

  if (Progress > 100) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->HandleProtocol (gST->ConsoleOutHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **)&GraphicsOutput);
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  SizeOfX = GraphicsOutput->Mode->Info->HorizontalResolution;
  SizeOfY = GraphicsOutput->Mode->Info->VerticalResolution;

  BlockWidth  = SizeOfX / 100;
  BlockHeight = SizeOfY / 50;

  BlockNum = Progress;

  PosX = 0;
  PosY = SizeOfY * 48 / 50;

  if (BlockNum == 0) {
    //
    // Clear progress area
    //
    SetMem (&Color, sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL), 0x0);

    Status = GraphicsOutput->Blt (
                               GraphicsOutput,
                               &Color,
                               EfiBltVideoFill,
                               0,
                               0,
                               0,
                               PosY - EFI_GLYPH_HEIGHT - 1,
                               SizeOfX,
                               SizeOfY - (PosY - EFI_GLYPH_HEIGHT - 1),
                               SizeOfX * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                               );
  }

  //
  // Show progress by drawing blocks
  //
  for (Index = PreviousValue; Index < BlockNum; Index++) {
    PosX   = Index * BlockWidth;
    Status = GraphicsOutput->Blt (
                               GraphicsOutput,
                               &ProgressColor,
                               EfiBltVideoFill,
                               0,
                               0,
                               PosX,
                               PosY,
                               BlockWidth - 1,
                               BlockHeight,
                               (BlockWidth) * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                               );
  }

  PrintXY (
    (SizeOfX - StrLen (Title) * EFI_GLYPH_WIDTH) / 2,
    PosY - EFI_GLYPH_HEIGHT - 1,
    &TitleForeground,
    &TitleBackground,
    Title
    );

  return EFI_SUCCESS;
}
