/** @file
  Implementation for a generic GOP driver.

Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent


**/

#include "GraphicsOutput.h"

#include <Guid/EventGroup.h>

#include <Library/PcdLib.h>
#include <Library/SafeIntLib.h>
#include <Protocol/BootLogo2.h>

#define GRAPHICS_OUTPUT_MODE_PHYSICAL  0
#define GRAPHICS_OUTPUT_MODE_HIDPI     1
#define GRAPHICS_OUTPUT_HIDPI_HORIZONTAL_RESOLUTION  1920
#define GRAPHICS_OUTPUT_HIDPI_VERTICAL_RESOLUTION    1080

CONST ACPI_ADR_DEVICE_PATH  mGraphicsOutputAdrNode = {
  {
    ACPI_DEVICE_PATH,
    ACPI_ADR_DP,
    { sizeof (ACPI_ADR_DEVICE_PATH), 0 },
  },
  ACPI_DISPLAY_ADR (1, 0, 0, 1, 0, ACPI_ADR_DISPLAY_TYPE_VGA, 0, 0)
};

EFI_PEI_GRAPHICS_DEVICE_INFO_HOB  mDefaultGraphicsDeviceInfo = {
  MAX_UINT16, MAX_UINT16, MAX_UINT16, MAX_UINT16, MAX_UINT8, MAX_UINT8
};

//
// The driver should only start on one graphics controller.
// So a global flag is used to remember that the driver is already started.
//
BOOLEAN  mDriverStarted = FALSE;

/**
  Return TRUE if the framebuffer is wider than the configured cap aspect and can
  be cropped to a centered viewport with left/right black bars.

  @param[in]  HorizontalResolution  Physical framebuffer width.
  @param[in]  VerticalResolution    Physical framebuffer height.
  @param[in]  CapAspectWidth        Maximum viewport aspect numerator.
  @param[in]  CapAspectHeight       Maximum viewport aspect denominator.
  @param[out] ViewportWidth         Cropped viewport width.

  @retval TRUE   A centered capped viewport can be created.
  @retval FALSE  No horizontal crop should be applied.
**/
STATIC
BOOLEAN
TryGetWideAspectCappedViewportWidth (
  IN  UINT32  HorizontalResolution,
  IN  UINT32  VerticalResolution,
  IN  UINT32  CapAspectWidth,
  IN  UINT32  CapAspectHeight,
  OUT UINT32  *ViewportWidth
  )
{
  UINT64  CandidateWidth;

  if ((ViewportWidth == NULL) ||
      (HorizontalResolution == 0) ||
      (VerticalResolution == 0) ||
      (CapAspectWidth == 0) ||
      (CapAspectHeight == 0))
  {
    return FALSE;
  }

  if (((UINT64)HorizontalResolution * CapAspectHeight) <= ((UINT64)VerticalResolution * CapAspectWidth)) {
    return FALSE;
  }

  CandidateWidth = ((UINT64)VerticalResolution * CapAspectWidth) / CapAspectHeight;
  CandidateWidth &= ~1ULL;
  if ((CandidateWidth == 0) || (CandidateWidth >= HorizontalResolution)) {
    return FALSE;
  }

  *ViewportWidth = (UINT32)CandidateWidth;
  return TRUE;
}

STATIC
BOOLEAN
IsHiDpiFramebuffer (
  IN UINT32  HorizontalResolution,
  IN UINT32  VerticalResolution
  )
{
  return (HorizontalResolution > GRAPHICS_OUTPUT_HIDPI_HORIZONTAL_RESOLUTION) &&
         (VerticalResolution > GRAPHICS_OUTPUT_HIDPI_VERTICAL_RESOLUTION);
}

/**
  Returns information for an available graphics mode that the graphics device
  and the set of active video output devices supports.

  @param  This                  The EFI_GRAPHICS_OUTPUT_PROTOCOL instance.
  @param  ModeNumber            The mode number to return information on.
  @param  SizeOfInfo            A pointer to the size, in bytes, of the Info buffer.
  @param  Info                  A pointer to callee allocated buffer that returns information about ModeNumber.

  @retval EFI_SUCCESS           Valid mode information was returned.
  @retval EFI_DEVICE_ERROR      A hardware error occurred trying to retrieve the video mode.
  @retval EFI_INVALID_PARAMETER ModeNumber is not valid.

**/
EFI_STATUS
EFIAPI
GraphicsOutputQueryMode (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL          *This,
  IN  UINT32                                ModeNumber,
  OUT UINTN                                 *SizeOfInfo,
  OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  **Info
  )
{
  GRAPHICS_OUTPUT_PRIVATE_DATA                *Private;
  CONST EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  *ModeInfo;

  if ((This == NULL) || (Info == NULL) || (SizeOfInfo == NULL) || (ModeNumber >= This->Mode->MaxMode)) {
    return EFI_INVALID_PARAMETER;
  }

  Private = GRAPHICS_OUTPUT_PRIVATE_FROM_THIS (This);

  ModeInfo = NULL;
  if (ModeNumber == GRAPHICS_OUTPUT_MODE_PHYSICAL) {
    ModeInfo = &Private->PhysicalModeInfo;
  } else if ((ModeNumber == GRAPHICS_OUTPUT_MODE_HIDPI) && Private->HasHiDpiMode) {
    ModeInfo = &Private->LogicalModeInfo;
  }

  if (ModeInfo == NULL) {
    return EFI_UNSUPPORTED;
  }

  *SizeOfInfo = sizeof (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION);
  *Info       = AllocateCopyPool (*SizeOfInfo, ModeInfo);
  return (*Info != NULL) ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}

/**
  Set the video device into the specified mode.

  @param  This        The EFI_GRAPHICS_OUTPUT_PROTOCOL instance.
  @param  ModeNumber  Abstraction that defines the current video mode.
  @param  ClearScreen TRUE to clear the screen to black in physical mode.

  @retval EFI_SUCCESS           The graphics mode specified by ModeNumber was selected.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
  @retval EFI_UNSUPPORTED       ModeNumber is not supported by this device.

**/
static EFI_STATUS
GraphicsOutputSetModeInternal (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *This,
  IN UINT32                        ModeNumber,
  IN BOOLEAN                       ClearScreen
  )
{
  GRAPHICS_OUTPUT_PRIVATE_DATA                *Private;
  CONST EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  *ModeInfo;
  UINT32                                      Scale;

  Private = GRAPHICS_OUTPUT_PRIVATE_FROM_THIS (This);

  ModeInfo = NULL;
  Scale    = 1;
  if (ModeNumber == GRAPHICS_OUTPUT_MODE_PHYSICAL) {
    ModeInfo = &Private->PhysicalModeInfo;
    Scale    = 1;
  } else if ((ModeNumber == GRAPHICS_OUTPUT_MODE_HIDPI) && Private->HasHiDpiMode) {
    ModeInfo = &Private->LogicalModeInfo;
    Scale    = Private->LogicalModeScale;
  }

  if (ModeInfo == NULL) {
    return EFI_UNSUPPORTED;
  }

  This->Mode->Mode       = ModeNumber;
  This->Mode->Info       = (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *)ModeInfo;
  This->Mode->SizeOfInfo = sizeof (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION);

  if (ModeNumber == GRAPHICS_OUTPUT_MODE_PHYSICAL) {
    This->Mode->FrameBufferBase = Private->PhysicalFrameBufferBase;
    This->Mode->FrameBufferSize = Private->PhysicalFrameBufferSize;
  } else {
    This->Mode->FrameBufferBase = 0;
    This->Mode->FrameBufferSize = 0;
  }

  Private->FrameBufferScale = Scale;

  if (ClearScreen) {
    RETURN_STATUS                  Status;
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Black;

    Black.Blue     = 0;
    Black.Green    = 0;
    Black.Red      = 0;
    Black.Reserved = 0;

    Status = FrameBufferBlt (
               Private->FrameBufferBltLibConfigure,
               &Black,
               EfiBltVideoFill,
               0,
               0,
               0,
               0,
               Private->PhysicalModeInfo.HorizontalResolution,
               Private->PhysicalModeInfo.VerticalResolution,
               0
               );
    return RETURN_ERROR (Status) ? EFI_DEVICE_ERROR : EFI_SUCCESS;
  }

  return EFI_SUCCESS;
}

/**
  Redraw the registered boot logo into the current graphics mode.

  BootLogoLib registers the physical BGRT image with BootLogo2.  When this
  driver drops the software HiDPI GOP mode at ReadyToBoot, redraw that same
  image so the handed-off framebuffer still matches the BGRT coordinates.

  @param  GraphicsOutput  The Graphics Output Protocol instance.

**/
static VOID
RestoreBootLogo (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput
  )
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Logo;
  EDKII_BOOT_LOGO2_PROTOCOL      *BootLogo;
  EFI_STATUS                     Status;
  UINTN                          DestinationX;
  UINTN                          DestinationY;
  UINTN                          Height;
  UINTN                          Width;

  if ((GraphicsOutput == NULL) ||
      (GraphicsOutput->Mode == NULL) ||
      (GraphicsOutput->Mode->Info == NULL))
  {
    return;
  }

  Status = gBS->LocateProtocol (
                  &gEdkiiBootLogo2ProtocolGuid,
                  NULL,
                  (VOID **)&BootLogo
                  );
  if (EFI_ERROR (Status) || (BootLogo == NULL)) {
    return;
  }

  Logo         = NULL;
  DestinationX = 0;
  DestinationY = 0;
  Width        = 0;
  Height       = 0;
  Status       = BootLogo->GetBootLogo (
                             BootLogo,
                             &Logo,
                             &DestinationX,
                             &DestinationY,
                             &Width,
                             &Height
                             );
  if (EFI_ERROR (Status) || (Logo == NULL) || (Width == 0) || (Height == 0)) {
    return;
  }

  if ((DestinationX > GraphicsOutput->Mode->Info->HorizontalResolution) ||
      (DestinationY > GraphicsOutput->Mode->Info->VerticalResolution) ||
      (Width > (GraphicsOutput->Mode->Info->HorizontalResolution - DestinationX)) ||
      (Height > (GraphicsOutput->Mode->Info->VerticalResolution - DestinationY)) ||
      (Width > (MAX_UINTN / sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL))))
  {
    DEBUG ((DEBUG_VERBOSE, "[%a]: boot logo does not fit current GOP mode\n", gEfiCallerBaseName));
    return;
  }

  Status = GraphicsOutput->Blt (
                             GraphicsOutput,
                             Logo,
                             EfiBltBufferToVideo,
                             0,
                             0,
                             DestinationX,
                             DestinationY,
                             Width,
                             Height,
                             Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_VERBOSE, "[%a]: boot logo restore failed: %r\n", gEfiCallerBaseName, Status));
  }
}

/**
  Set the video device into the specified mode and clears the visible portions of
  the output display to black.

  @param  This              The EFI_GRAPHICS_OUTPUT_PROTOCOL instance.
  @param  ModeNumber        Abstraction that defines the current video mode.

  @retval EFI_SUCCESS       The graphics mode specified by ModeNumber was selected.
  @retval EFI_DEVICE_ERROR  The device had an error and could not complete the request.
  @retval EFI_UNSUPPORTED   ModeNumber is not supported by this device.

**/
EFI_STATUS
EFIAPI
GraphicsOutputSetMode (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL  *This,
  IN  UINT32                        ModeNumber
  )
{
  if ((This == NULL) || (ModeNumber >= This->Mode->MaxMode)) {
    return EFI_UNSUPPORTED;
  }

  return GraphicsOutputSetModeInternal (This, ModeNumber, TRUE);
}

/**
  ReadyToBoot notification.

  Switch back to a mode that provides a direct framebuffer before launching the
  OS (e.g. for users that write directly to the framebuffer).

  @param  Event    The event signaled.
  @param  Context  The event context.

**/
static VOID
EFIAPI
GraphicsOutputReadyToBoot (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  GRAPHICS_OUTPUT_PRIVATE_DATA  *Private;
  EFI_STATUS                    Status;

  (VOID)Event;

  Private = (GRAPHICS_OUTPUT_PRIVATE_DATA *)Context;
  if ((Private == NULL) || !Private->HasHiDpiMode) {
    return;
  }

  if (Private->GraphicsOutput.Mode->Mode == GRAPHICS_OUTPUT_MODE_HIDPI) {
    //
    // Switch back to a mode that provides a direct framebuffer before
    // launching the OS (e.g. for efifb or other direct-writes users).
    //
    Status = GraphicsOutputSetModeInternal (&Private->GraphicsOutput, GRAPHICS_OUTPUT_MODE_PHYSICAL, FALSE);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_VERBOSE, "[%a]: physical GOP restore failed: %r\n", gEfiCallerBaseName, Status));
      return;
    }

    RestoreBootLogo (&Private->GraphicsOutput);

    //
    // Restore the physical-mode resolution PCDs so late DXE text/graphics code
    // sees the real framebuffer geometry after the HiDPI GOP mode is dropped.
    //
    Status = PcdSet32S (PcdVideoHorizontalResolution, Private->PhysicalModeInfo.HorizontalResolution);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_VERBOSE, "[%a]: PcdVideoHorizontalResolution update failed: %r\n", gEfiCallerBaseName, Status));
    }

    Status = PcdSet32S (PcdVideoVerticalResolution, Private->PhysicalModeInfo.VerticalResolution);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_VERBOSE, "[%a]: PcdVideoVerticalResolution update failed: %r\n", gEfiCallerBaseName, Status));
    }

    Status = PcdSet32S (PcdSetupVideoHorizontalResolution, Private->PhysicalModeInfo.HorizontalResolution);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_VERBOSE, "[%a]: PcdSetupVideoHorizontalResolution update failed: %r\n", gEfiCallerBaseName, Status));
    }

    Status = PcdSet32S (PcdSetupVideoVerticalResolution, Private->PhysicalModeInfo.VerticalResolution);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_VERBOSE, "[%a]: PcdSetupVideoVerticalResolution update failed: %r\n", gEfiCallerBaseName, Status));
    }
  }
}

/**
  Scale a BLT buffer by 2x.

  @param  Src            Pointer to the source buffer.
  @param  SrcWidth       Source buffer width in pixels.
  @param  SrcHeight      Source buffer height in pixels.
  @param  SrcDeltaBytes  Source buffer stride in bytes.
  @param  Dst            Pointer to the destination buffer.

  @retval EFI_SUCCESS           The buffer was scaled successfully.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.

**/
static EFI_STATUS
ScaleBltBuffer2x (
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Src,
  IN  UINTN                          SrcWidth,
  IN  UINTN                          SrcHeight,
  IN  UINTN                          SrcDeltaBytes,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Dst
  )
{
  UINTN  Row;
  UINTN  Col;

  if ((Src == NULL) || (Dst == NULL) || (SrcWidth == 0) || (SrcHeight == 0) || (SrcDeltaBytes == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Row = 0; Row < SrcHeight; Row++) {
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *SrcRow;
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *DstRow0;
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *DstRow1;

    SrcRow  = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)((UINT8 *)Src + Row * SrcDeltaBytes);
    DstRow0 = Dst + (Row * 2) * (SrcWidth * 2);
    DstRow1 = DstRow0 + (SrcWidth * 2);

    for (Col = 0; Col < SrcWidth; Col++) {
      EFI_GRAPHICS_OUTPUT_BLT_PIXEL  P;
      UINTN                          DstX;

      P    = SrcRow[Col];
      DstX = Col * 2;

      DstRow0[DstX]     = P;
      DstRow0[DstX + 1] = P;
      DstRow1[DstX]     = P;
      DstRow1[DstX + 1] = P;
    }
  }

  return EFI_SUCCESS;
}

/**
  Downscale a BLT buffer by 2x.

  @param  Src            Pointer to the source buffer.
  @param  SrcWidth       Source buffer width in pixels.
  @param  SrcHeight      Source buffer height in pixels.
  @param  SrcDeltaBytes  Source buffer stride in bytes.
  @param  Dst            Pointer to the destination buffer.
  @param  DstWidth       Destination buffer width in pixels.
  @param  DstHeight      Destination buffer height in pixels.
  @param  DstDeltaBytes  Destination buffer stride in bytes.

  @retval EFI_SUCCESS           The buffer was downscaled successfully.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.

**/
static EFI_STATUS
DownscaleBltBuffer2x (
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Src,
  IN  UINTN                          SrcWidth,
  IN  UINTN                          SrcHeight,
  IN  UINTN                          SrcDeltaBytes,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Dst,
  IN  UINTN                          DstWidth,
  IN  UINTN                          DstHeight,
  IN  UINTN                          DstDeltaBytes
  )
{
  UINTN  Row;
  UINTN  Col;

  if ((Src == NULL) || (Dst == NULL) || (DstWidth == 0) || (DstHeight == 0) ||
      (SrcDeltaBytes == 0) || (DstDeltaBytes == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  if ((SrcWidth < DstWidth * 2) || (SrcHeight < DstHeight * 2)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Row = 0; Row < DstHeight; Row++) {
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *DstRow;
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *SrcRow;

    DstRow = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)((UINT8 *)Dst + Row * DstDeltaBytes);
    SrcRow = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)((UINT8 *)Src + (Row * 2) * SrcDeltaBytes);

    for (Col = 0; Col < DstWidth; Col++) {
      DstRow[Col] = SrcRow[Col * 2];
    }
  }

  return EFI_SUCCESS;
}

/**
  Check the caller's BLT buffer stride and advance to the first transferred pixel.

  The GOP protocol does not provide the length of the caller's buffer. Check
  that each touched row fits the supplied stride and address arithmetic.

  @param[in,out] BltBuffer  Caller buffer, advanced to the requested pixel.
  @param[in]     X          First column in the caller's buffer.
  @param[in]     Y          First row in the caller's buffer.
  @param[in]     Width      Number of pixels to transfer per row.
  @param[in]     Height     Number of rows to transfer.
  @param[in,out] Delta      Number of bytes between rows.

  @retval RETURN_SUCCESS            Buffer addressing is representable.
  @retval RETURN_INVALID_PARAMETER  Invalid stride or buffer coordinates.
**/
STATIC
RETURN_STATUS
GetBltBufferOrigin (
  IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **BltBuffer,
  IN     UINTN                          X,
  IN     UINTN                          Y,
  IN     UINTN                          Width,
  IN     UINTN                          Height,
  IN OUT UINTN                          *Delta
  )
{
  UINTN  RowEnd;
  UINTN  FirstByte;
  UINTN  LastRow;
  UINTN  End;

  if (RETURN_ERROR (SafeUintnAdd (X, Width, &RowEnd)) ||
      RETURN_ERROR (SafeUintnMult (RowEnd, sizeof (**BltBuffer), &RowEnd)))
  {
    return RETURN_INVALID_PARAMETER;
  }

  if (*Delta == 0) {
    if ((X != 0) || (Y != 0)) {
      return RETURN_INVALID_PARAMETER;
    }

    *Delta = RowEnd;
  }

  if ((RowEnd > *Delta) ||
      RETURN_ERROR (SafeUintnMult (Y, *Delta, &FirstByte)) ||
      RETURN_ERROR (SafeUintnAdd (FirstByte, X * sizeof (**BltBuffer), &FirstByte)) ||
      RETURN_ERROR (SafeUintnAdd (Y, Height - 1, &LastRow)) ||
      RETURN_ERROR (SafeUintnMult (LastRow, *Delta, &End)) ||
      RETURN_ERROR (SafeUintnAdd (End, RowEnd, &End)) ||
      RETURN_ERROR (SafeUintnAdd ((UINTN)*BltBuffer, End, &End)))
  {
    return RETURN_INVALID_PARAMETER;
  }

  *BltBuffer = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)((UINT8 *)*BltBuffer + FirstByte);
  return RETURN_SUCCESS;
}

/**
  Blt a rectangle of pixels on the graphics screen. Blt stands for BLock Transfer.

  @param  This         Protocol instance pointer.
  @param  BltBuffer    The data to transfer to the graphics screen.
                       Size is at least Width*Height*sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL).
  @param  BltOperation The operation to perform when copying BltBuffer on to the graphics screen.
  @param  SourceX      The X coordinate of source for the BltOperation.
  @param  SourceY      The Y coordinate of source for the BltOperation.
  @param  DestinationX The X coordinate of destination for the BltOperation.
  @param  DestinationY The Y coordinate of destination for the BltOperation.
  @param  Width        The width of a rectangle in the blt rectangle in pixels.
  @param  Height       The height of a rectangle in the blt rectangle in pixels.
  @param  Delta        Not used for EfiBltVideoFill or the EfiBltVideoToVideo operation.
                       If a Delta of zero is used, the entire BltBuffer is being operated on.
                       If a subrectangle of the BltBuffer is being used then Delta
                       represents the number of bytes in a row of the BltBuffer.

  @retval EFI_SUCCESS           BltBuffer was drawn to the graphics screen.
  @retval EFI_INVALID_PARAMETER BltOperation is not valid.
  @retval EFI_DEVICE_ERROR      The device had an error and could not complete the request.

**/
EFI_STATUS
EFIAPI
GraphicsOutputBlt (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL       *This,
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BltBuffer  OPTIONAL,
  IN  EFI_GRAPHICS_OUTPUT_BLT_OPERATION  BltOperation,
  IN  UINTN                              SourceX,
  IN  UINTN                              SourceY,
  IN  UINTN                              DestinationX,
  IN  UINTN                              DestinationY,
  IN  UINTN                              Width,
  IN  UINTN                              Height,
  IN  UINTN                              Delta         OPTIONAL
  )
{
  RETURN_STATUS                               Status;
  EFI_TPL                                     Tpl;
  GRAPHICS_OUTPUT_PRIVATE_DATA                *Private;
  CONST EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  *ModeInfo;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL               *Temp;
  UINTN                                       Scale;
  UINTN                                       OffsetX;
  UINTN                                       OffsetY;
  UINTN                                       TempStride;
  UINTN                                       TempSize;
  BOOLEAN                                     SourceVideo;
  BOOLEAN                                     DestinationVideo;
  BOOLEAN                                     TransferBuffer;

  Private  = GRAPHICS_OUTPUT_PRIVATE_FROM_THIS (This);
  ModeInfo = This->Mode->Info;
  if ((ModeInfo == NULL) || (BltOperation >= EfiGraphicsOutputBltOperationMax) ||
      (Width == 0) || (Height == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  SourceVideo      = (BltOperation == EfiBltVideoToBltBuffer) || (BltOperation == EfiBltVideoToVideo);
  DestinationVideo = BltOperation != EfiBltVideoToBltBuffer;
  TransferBuffer   = (BltOperation == EfiBltVideoToBltBuffer) || (BltOperation == EfiBltBufferToVideo);
  if ((BltOperation != EfiBltVideoToVideo) && (BltBuffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Width > ModeInfo->HorizontalResolution) || (Height > ModeInfo->VerticalResolution) ||
      (SourceVideo &&
       ((SourceX > ModeInfo->HorizontalResolution - Width) ||
        (SourceY > ModeInfo->VerticalResolution - Height))) ||
      (DestinationVideo &&
       ((DestinationX > ModeInfo->HorizontalResolution - Width) ||
        (DestinationY > ModeInfo->VerticalResolution - Height))))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (TransferBuffer) {
    Status = GetBltBufferOrigin (
               &BltBuffer,
               SourceVideo ? DestinationX : SourceX,
               SourceVideo ? DestinationY : SourceY,
               Width,
               Height,
               &Delta
               );
    if (RETURN_ERROR (Status)) {
      return EFI_INVALID_PARAMETER;
    }
  }

  Scale = Private->FrameBufferScale;
  if ((Scale != 1) && (Scale != 2)) {
    return EFI_UNSUPPORTED;
  }

  OffsetX      = (This->Mode->Mode == GRAPHICS_OUTPUT_MODE_PHYSICAL) ? 0 : Private->ViewportOffsetX;
  OffsetY      = (This->Mode->Mode == GRAPHICS_OUTPUT_MODE_PHYSICAL) ? 0 : Private->ViewportOffsetY;
  SourceX      = SourceVideo ? SourceX * Scale + OffsetX : 0;
  SourceY      = SourceVideo ? SourceY * Scale + OffsetY : 0;
  DestinationX = DestinationVideo ? DestinationX * Scale + OffsetX : 0;
  DestinationY = DestinationVideo ? DestinationY * Scale + OffsetY : 0;

  Temp       = NULL;
  TempStride = 0;
  if ((Scale == 2) && TransferBuffer) {
    if (RETURN_ERROR (SafeUintnMult (Width * Scale, sizeof (*Temp), &TempStride)) ||
        RETURN_ERROR (SafeUintnMult (Height * Scale, TempStride, &TempSize)))
    {
      return EFI_INVALID_PARAMETER;
    }

    Temp = AllocatePool (TempSize);
    if (Temp == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    if (BltOperation == EfiBltBufferToVideo) {
      ScaleBltBuffer2x (BltBuffer, Width, Height, Delta, Temp);
    }
  }

  //
  // Serialize access to the frame buffer with cursor timer callbacks.
  //
  Tpl    = gBS->RaiseTPL (TPL_NOTIFY);
  Status = FrameBufferBlt (
             Private->FrameBufferBltLibConfigure,
             (Temp == NULL) ? BltBuffer : Temp,
             BltOperation,
             SourceX,
             SourceY,
             DestinationX,
             DestinationY,
             Width * Scale,
             Height * Scale,
             (Temp == NULL) ? Delta : TempStride
             );
  gBS->RestoreTPL (Tpl);

  if (Temp != NULL) {
    if (!RETURN_ERROR (Status) && SourceVideo) {
      DownscaleBltBuffer2x (Temp, Width * Scale, Height * Scale, TempStride, BltBuffer, Width, Height, Delta);
    }

    FreePool (Temp);
  }

  return Status;

}

CONST GRAPHICS_OUTPUT_PRIVATE_DATA  mGraphicsOutputInstanceTemplate = {
  GRAPHICS_OUTPUT_PRIVATE_DATA_SIGNATURE,          // Signature
  NULL,                                            // GraphicsOutputHandle
  {
    GraphicsOutputQueryMode,
    GraphicsOutputSetMode,
    GraphicsOutputBlt,
    NULL                                           // Mode
  },
  {
    1,                                             // MaxMode
    0,                                             // Mode
    NULL,                                          // Info
    sizeof (EFI_GRAPHICS_OUTPUT_MODE_INFORMATION), // SizeOfInfo
    0,                                             // FrameBufferBase
    0                                              // FrameBufferSize
  },
  { 0 },                                           // LogicalModeInfo
  { 0 },                                           // PhysicalModeInfo
  0,                                               // FrameBufferScale
  0,                                               // LogicalModeScale
  0,                                               // ViewportOffsetX
  0,                                               // ViewportOffsetY
  0,                                               // ViewportWidth
  0,                                               // ViewportHeight
  FALSE,                                           // HasHiDpiMode
  NULL,                                            // ReadyToBootEvent
  0,                                               // PhysicalFrameBufferBase
  0,                                               // PhysicalFrameBufferSize
  NULL,                                            // DevicePath
  NULL,                                            // PciIo
  0,                                               // PciAttributes
  NULL,                                            // FrameBufferBltLibConfigure
  0                                                // FrameBufferBltLibConfigureSize
};

/**
  Test whether the Controller can be managed by the driver.

  @param  This                 Driver Binding protocol instance pointer.
  @param  Controller           The PCI controller.
  @param  RemainingDevicePath  Optional parameter use to pick a specific child
                               device to start.

  @retval EFI_SUCCESS          The driver can manage the video device.
  @retval other                The driver cannot manage the video device.
**/
EFI_STATUS
EFIAPI
GraphicsOutputDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   Controller,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
  )
{
  EFI_STATUS                Status;
  EFI_PCI_IO_PROTOCOL       *PciIo;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;

  //
  // Since there is only one GraphicsInfo HOB, the driver only manages one video device.
  //
  if (mDriverStarted) {
    return EFI_ALREADY_STARTED;
  }

  //
  // Test the PCI I/O Protocol
  //
  Status = gBS->OpenProtocol (
                  Controller,
                  &gEfiPciIoProtocolGuid,
                  (VOID **)&PciIo,
                  This->DriverBindingHandle,
                  Controller,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (Status == EFI_ALREADY_STARTED) {
    Status = EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  gBS->CloseProtocol (
         Controller,
         &gEfiPciIoProtocolGuid,
         This->DriverBindingHandle,
         Controller
         );

  //
  // Test the DevicePath protocol
  //
  Status = gBS->OpenProtocol (
                  Controller,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **)&DevicePath,
                  This->DriverBindingHandle,
                  Controller,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (Status == EFI_ALREADY_STARTED) {
    Status = EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  gBS->CloseProtocol (
         Controller,
         &gEfiDevicePathProtocolGuid,
         This->DriverBindingHandle,
         Controller
         );

  if ((RemainingDevicePath == NULL) ||
      IsDevicePathEnd (RemainingDevicePath) ||
      (CompareMem (RemainingDevicePath, &mGraphicsOutputAdrNode, sizeof (mGraphicsOutputAdrNode)) == 0))
  {
    return EFI_SUCCESS;
  } else {
    return EFI_INVALID_PARAMETER;
  }
}

/**
  Start the video controller.

  @param  This                 Driver Binding protocol instance pointer.
  @param  ControllerHandle     The PCI controller.
  @param  RemainingDevicePath  Optional parameter use to pick a specific child
                               device to start.

  @retval EFI_SUCCESS          The driver starts to manage the video device.
  @retval other                The driver cannot manage the video device.
**/
EFI_STATUS
EFIAPI
GraphicsOutputDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   Controller,
  IN EFI_DEVICE_PATH_PROTOCOL     *RemainingDevicePath
  )
{
  EFI_STATUS                         Status;
  RETURN_STATUS                      ReturnStatus;
  GRAPHICS_OUTPUT_PRIVATE_DATA       *Private;
  EFI_PCI_IO_PROTOCOL                *PciIo;
  EFI_DEVICE_PATH                    *PciDevicePath;
  PCI_TYPE00                         Pci;
  UINT8                              Index;
  EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR  *Resources;
  VOID                               *HobStart;
  EFI_PEI_GRAPHICS_INFO_HOB          *GraphicsInfo;
  EFI_PEI_GRAPHICS_DEVICE_INFO_HOB   *DeviceInfo;
  EFI_PHYSICAL_ADDRESS               FrameBufferBase;
  UINT32                             ViewportWidth;

  FrameBufferBase = 0;

  HobStart = GetFirstGuidHob (&gEfiGraphicsInfoHobGuid);
  ASSERT ((HobStart != NULL) && (GET_GUID_HOB_DATA_SIZE (HobStart) == sizeof (EFI_PEI_GRAPHICS_INFO_HOB)));
  GraphicsInfo = (EFI_PEI_GRAPHICS_INFO_HOB *)(GET_GUID_HOB_DATA (HobStart));

  HobStart = GetFirstGuidHob (&gEfiGraphicsDeviceInfoHobGuid);
  if ((HobStart == NULL) || (GET_GUID_HOB_DATA_SIZE (HobStart) < sizeof (*DeviceInfo))) {
    //
    // Use default device infomation when the device info HOB doesn't exist
    //
    DeviceInfo = &mDefaultGraphicsDeviceInfo;
    DEBUG ((DEBUG_INFO, "[%a]: GraphicsDeviceInfo HOB doesn't exist!\n", gEfiCallerBaseName));
  } else {
    DeviceInfo = (EFI_PEI_GRAPHICS_DEVICE_INFO_HOB *)(GET_GUID_HOB_DATA (HobStart));
    DEBUG ((
      DEBUG_INFO,
      "[%a]: GraphicsDeviceInfo HOB:\n"
      "  VendorId = %04x, DeviceId = %04x,\n"
      "  RevisionId = %02x, BarIndex = %x,\n"
      "  SubsystemVendorId = %04x, SubsystemId = %04x\n",
      gEfiCallerBaseName,
      DeviceInfo->VendorId,
      DeviceInfo->DeviceId,
      DeviceInfo->RevisionId,
      DeviceInfo->BarIndex,
      DeviceInfo->SubsystemVendorId,
      DeviceInfo->SubsystemId
      ));
  }

  //
  // Open the PCI I/O Protocol
  //
  Status = gBS->OpenProtocol (
                  Controller,
                  &gEfiPciIoProtocolGuid,
                  (VOID **)&PciIo,
                  This->DriverBindingHandle,
                  Controller,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (Status == EFI_ALREADY_STARTED) {
    Status = EFI_SUCCESS;
  }

  ASSERT_EFI_ERROR (Status);

  Status = gBS->OpenProtocol (
                  Controller,
                  &gEfiDevicePathProtocolGuid,
                  (VOID **)&PciDevicePath,
                  This->DriverBindingHandle,
                  Controller,
                  EFI_OPEN_PROTOCOL_BY_DRIVER
                  );
  if (Status == EFI_ALREADY_STARTED) {
    Status = EFI_SUCCESS;
  }

  ASSERT_EFI_ERROR (Status);

  //
  // Read the PCI Class Code from the PCI Device
  //
  Status = PciIo->Pci.Read (PciIo, EfiPciIoWidthUint8, 0, sizeof (Pci), &Pci);
  if (!EFI_ERROR (Status)) {
    if (!IS_PCI_DISPLAY (&Pci) || (
                                   ((DeviceInfo->VendorId != MAX_UINT16) && (DeviceInfo->VendorId != Pci.Hdr.VendorId)) ||
                                   ((DeviceInfo->DeviceId != MAX_UINT16) && (DeviceInfo->DeviceId != Pci.Hdr.DeviceId)) ||
                                   ((DeviceInfo->RevisionId != MAX_UINT8) && (DeviceInfo->RevisionId != Pci.Hdr.RevisionID)) ||
                                   ((DeviceInfo->SubsystemVendorId != MAX_UINT16) && (DeviceInfo->SubsystemVendorId != Pci.Device.SubsystemVendorID)) ||
                                   ((DeviceInfo->SubsystemId != MAX_UINT16) && (DeviceInfo->SubsystemId != Pci.Device.SubsystemID))
                                   )
        )
    {
      //
      // It's not a video device, or device infomation doesn't match.
      //
      Status = EFI_UNSUPPORTED;
    } else {
      //
      // If it's a video device and device information matches, use the BarIndex
      // from device information, or any BAR if BarIndex is not specified
      // whose size >= the frame buffer size from GraphicsInfo HOB.
      // Store the new frame buffer base.
      //
      for (Index = 0; Index < MAX_PCI_BAR; Index++) {
        if ((DeviceInfo->BarIndex != MAX_UINT8) && (DeviceInfo->BarIndex != Index)) {
          continue;
        }

        Status = PciIo->GetBarAttributes (PciIo, Index, NULL, (VOID **)&Resources);
        if (!EFI_ERROR (Status)) {
          DEBUG ((
            DEBUG_INFO,
            "[%a]: BAR[%d]: Base = %lx, Length = %lx\n",
            gEfiCallerBaseName,
            Index,
            Resources->AddrRangeMin,
            Resources->AddrLen
            ));
          if ((Resources->Desc == ACPI_ADDRESS_SPACE_DESCRIPTOR) &&
              (Resources->Len == (UINT16)(sizeof (EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR) - 3)) &&
              (Resources->ResType == ACPI_ADDRESS_SPACE_TYPE_MEM) &&
              (Resources->AddrLen >= GraphicsInfo->FrameBufferSize)
              )
          {
            if (FrameBufferBase == 0) {
              FrameBufferBase = Resources->AddrRangeMin;
            }

            if (DeviceInfo->BarIndex == MAX_UINT8) {
              if (  (GraphicsInfo->FrameBufferBase >= Resources->AddrRangeMin)
                 && (GraphicsInfo->FrameBufferBase - Resources->AddrRangeMin <=
                     Resources->AddrLen - GraphicsInfo->FrameBufferSize))
              {
                FrameBufferBase = GraphicsInfo->FrameBufferBase;
                break;
              }
            } else {
              break;
            }
          }
        }
      }

      if (Index == MAX_PCI_BAR) {
        Status = EFI_UNSUPPORTED;
      } else {
        DEBUG ((DEBUG_INFO, "[%a]: ... matched!\n", gEfiCallerBaseName));
      }
    }
  }

  if (EFI_ERROR (Status)) {
    goto CloseProtocols;
  }

  if ((RemainingDevicePath != NULL) && IsDevicePathEnd (RemainingDevicePath)) {
    return EFI_SUCCESS;
  }

  Private = AllocateCopyPool (sizeof (mGraphicsOutputInstanceTemplate), &mGraphicsOutputInstanceTemplate);
  if (Private == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto CloseProtocols;
  }

  Private->PhysicalFrameBufferBase = FrameBufferBase;
  Private->PhysicalFrameBufferSize = GraphicsInfo->FrameBufferSize;

  CopyMem (&Private->PhysicalModeInfo, &GraphicsInfo->GraphicsMode, sizeof (Private->PhysicalModeInfo));
  CopyMem (&Private->LogicalModeInfo, &Private->PhysicalModeInfo, sizeof (Private->LogicalModeInfo));

  Private->ViewportOffsetX = 0;
  Private->ViewportOffsetY = 0;
  Private->ViewportWidth   = Private->PhysicalModeInfo.HorizontalResolution;
  Private->ViewportHeight  = Private->PhysicalModeInfo.VerticalResolution;
  Private->HasHiDpiMode     = FALSE;
  Private->FrameBufferScale = 1;
  Private->LogicalModeScale = 1;

  if (FeaturePcdGet (PcdPayloadFbHiDpiWideAspectCapSupport) &&
      TryGetWideAspectCappedViewportWidth (
        Private->PhysicalModeInfo.HorizontalResolution,
        Private->PhysicalModeInfo.VerticalResolution,
        PcdGet32 (PcdPayloadFbHiDpiWideAspectCapWidth),
        PcdGet32 (PcdPayloadFbHiDpiWideAspectCapHeight),
        &ViewportWidth
        ))
  {
    Private->ViewportWidth   = ViewportWidth;
    Private->ViewportOffsetX = (Private->PhysicalModeInfo.HorizontalResolution - ViewportWidth) / 2;
  }

  if (IsHiDpiFramebuffer (
        Private->PhysicalModeInfo.HorizontalResolution,
        Private->PhysicalModeInfo.VerticalResolution
        ) &&
      ((Private->PhysicalModeInfo.HorizontalResolution % 2) == 0) &&
      ((Private->PhysicalModeInfo.VerticalResolution % 2) == 0))
  {
    Private->HasHiDpiMode                         = TRUE;
    Private->LogicalModeScale                      = 2;
    Private->LogicalModeInfo.HorizontalResolution = Private->ViewportWidth / 2;
    Private->LogicalModeInfo.VerticalResolution   = Private->ViewportHeight / 2;
    Private->LogicalModeInfo.PixelsPerScanLine    = Private->LogicalModeInfo.HorizontalResolution;
    Private->LogicalModeInfo.PixelFormat          = PixelBltOnly;
    ZeroMem (&Private->LogicalModeInfo.PixelInformation, sizeof (Private->LogicalModeInfo.PixelInformation));

    DEBUG ((
      DEBUG_INFO,
      "[%a]: Enabling GOP 2x framebuffer scaling (physical %ux%u, logical %ux%u)\n",
      gEfiCallerBaseName,
      Private->PhysicalModeInfo.HorizontalResolution,
      Private->PhysicalModeInfo.VerticalResolution,
      Private->LogicalModeInfo.HorizontalResolution,
      Private->LogicalModeInfo.VerticalResolution
      ));

    if (Private->ViewportOffsetX != 0) {
      DEBUG ((
        DEBUG_INFO,
        "[%a]: Centering HiDPI viewport at +%u, viewport %ux%u inside physical %ux%u\n",
        gEfiCallerBaseName,
        Private->ViewportOffsetX,
        Private->ViewportWidth,
        Private->ViewportHeight,
        Private->PhysicalModeInfo.HorizontalResolution,
        Private->PhysicalModeInfo.VerticalResolution
        ));
    }
  }

  if (!Private->HasHiDpiMode && (Private->ViewportOffsetX != 0)) {
    Private->HasHiDpiMode                          = TRUE;
    Private->LogicalModeScale                     = 1;
    Private->LogicalModeInfo.HorizontalResolution = Private->ViewportWidth;
    Private->LogicalModeInfo.VerticalResolution   = Private->ViewportHeight;
    Private->LogicalModeInfo.PixelsPerScanLine    = Private->LogicalModeInfo.HorizontalResolution;
    Private->LogicalModeInfo.PixelFormat          = PixelBltOnly;
    ZeroMem (&Private->LogicalModeInfo.PixelInformation, sizeof (Private->LogicalModeInfo.PixelInformation));

    DEBUG ((
      DEBUG_INFO,
      "[%a]: Enabling centered viewport mode (physical %ux%u, logical %ux%u, offset +%u)\n",
      gEfiCallerBaseName,
      Private->PhysicalModeInfo.HorizontalResolution,
      Private->PhysicalModeInfo.VerticalResolution,
      Private->LogicalModeInfo.HorizontalResolution,
      Private->LogicalModeInfo.VerticalResolution,
      Private->ViewportOffsetX
      ));
  }

  Private->GraphicsOutputMode.MaxMode = Private->HasHiDpiMode ? 2 : 1;

  //
  // Fix up Mode pointer in GraphicsOutput
  //
  Private->GraphicsOutput.Mode = &Private->GraphicsOutputMode;

  Status = GraphicsOutputSetModeInternal (
             &Private->GraphicsOutput,
             GRAPHICS_OUTPUT_MODE_PHYSICAL,
             FALSE
             );
  if (EFI_ERROR (Status)) {
    goto FreeMemory;
  }

  //
  // Set attributes
  //
  Status = PciIo->Attributes (
                    PciIo,
                    EfiPciIoAttributeOperationGet,
                    0,
                    &Private->PciAttributes
                    );
  if (!EFI_ERROR (Status)) {
    Status = PciIo->Attributes (
                      PciIo,
                      EfiPciIoAttributeOperationEnable,
                      EFI_PCI_DEVICE_ENABLE,
                      NULL
                      );
  }

  if (EFI_ERROR (Status)) {
    goto FreeMemory;
  }

  //
  // Create the FrameBufferBltLib configuration.
  //
  ReturnStatus = FrameBufferBltConfigure (
                   (VOID *)(UINTN)Private->PhysicalFrameBufferBase,
                   &Private->PhysicalModeInfo,
                   Private->FrameBufferBltLibConfigure,
                   &Private->FrameBufferBltLibConfigureSize
                   );
  if (ReturnStatus == RETURN_BUFFER_TOO_SMALL) {
    Private->FrameBufferBltLibConfigure = AllocatePool (Private->FrameBufferBltLibConfigureSize);
    if (Private->FrameBufferBltLibConfigure != NULL) {
      ReturnStatus = FrameBufferBltConfigure (
                       (VOID *)(UINTN)Private->PhysicalFrameBufferBase,
                       &Private->PhysicalModeInfo,
                       Private->FrameBufferBltLibConfigure,
                       &Private->FrameBufferBltLibConfigureSize
                       );
    }
  }

  if (RETURN_ERROR (ReturnStatus)) {
    Status = EFI_OUT_OF_RESOURCES;
    goto RestorePciAttributes;
  }

  Private->DevicePath = AppendDevicePathNode (PciDevicePath, (EFI_DEVICE_PATH_PROTOCOL *)&mGraphicsOutputAdrNode);
  if (Private->DevicePath == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto RestorePciAttributes;
  }

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Private->GraphicsOutputHandle,
                  &gEfiGraphicsOutputProtocolGuid,
                  &Private->GraphicsOutput,
                  &gEfiDevicePathProtocolGuid,
                  Private->DevicePath,
                  NULL
                  );

  if (!EFI_ERROR (Status)) {
    if (Private->HasHiDpiMode) {
      Status = gBS->CreateEventEx (
                      EVT_NOTIFY_SIGNAL,
                      TPL_NOTIFY,
                      GraphicsOutputReadyToBoot,
                      Private,
                      &gEfiEventReadyToBootGuid,
                      &Private->ReadyToBootEvent
                      );
      if (EFI_ERROR (Status)) {
        gBS->UninstallMultipleProtocolInterfaces (
               Private->GraphicsOutputHandle,
               &gEfiGraphicsOutputProtocolGuid,
               &Private->GraphicsOutput,
               &gEfiDevicePathProtocolGuid,
               Private->DevicePath,
               NULL
               );
        goto RestorePciAttributes;
      }
    }

    Status = gBS->OpenProtocol (
                    Controller,
                    &gEfiPciIoProtocolGuid,
                    (VOID **)&Private->PciIo,
                    This->DriverBindingHandle,
                    Private->GraphicsOutputHandle,
                    EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER
                    );
    if (!EFI_ERROR (Status)) {
      mDriverStarted = TRUE;
    } else {
      if (Private->ReadyToBootEvent != NULL) {
        gBS->CloseEvent (Private->ReadyToBootEvent);
        Private->ReadyToBootEvent = NULL;
      }

      gBS->UninstallMultipleProtocolInterfaces (
             Private->GraphicsOutputHandle,
             &gEfiGraphicsOutputProtocolGuid,
             &Private->GraphicsOutput,
             &gEfiDevicePathProtocolGuid,
             Private->DevicePath,
             NULL
             );
    }
  }

RestorePciAttributes:
  if (EFI_ERROR (Status)) {
    //
    // Restore original PCI attributes
    //
    PciIo->Attributes (
             PciIo,
             EfiPciIoAttributeOperationSet,
             Private->PciAttributes,
             NULL
             );
  }

FreeMemory:
  if (EFI_ERROR (Status)) {
    if (Private != NULL) {
      if (Private->DevicePath != NULL) {
        FreePool (Private->DevicePath);
      }

      if (Private->FrameBufferBltLibConfigure != NULL) {
        FreePool (Private->FrameBufferBltLibConfigure);
      }

      FreePool (Private);
    }
  }

CloseProtocols:
  if (EFI_ERROR (Status)) {
    //
    // Close the PCI I/O Protocol
    //
    gBS->CloseProtocol (
           Controller,
           &gEfiDevicePathProtocolGuid,
           This->DriverBindingHandle,
           Controller
           );

    //
    // Close the PCI I/O Protocol
    //
    gBS->CloseProtocol (
           Controller,
           &gEfiPciIoProtocolGuid,
           This->DriverBindingHandle,
           Controller
           );
  }

  return Status;
}

/**
  Stop the video controller.

  @param  This                 Driver Binding protocol instance pointer.
  @param  Controller           The PCI controller.
  @param  NumberOfChildren     The number of child device handles in ChildHandleBuffer.
  @param  ChildHandleBuffer    An array of child handles to be freed. May be NULL
                               if NumberOfChildren is 0.

  @retval EFI_SUCCESS          The device was stopped.
  @retval EFI_DEVICE_ERROR     The device could not be stopped due to a device error.
**/
EFI_STATUS
EFIAPI
GraphicsOutputDriverBindingStop (
  IN EFI_DRIVER_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                   Controller,
  IN UINTN                        NumberOfChildren,
  IN EFI_HANDLE                   *ChildHandleBuffer
  )
{
  EFI_STATUS                    Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop;
  GRAPHICS_OUTPUT_PRIVATE_DATA  *Private;

  if (NumberOfChildren == 0) {
    //
    // Close the PCI I/O Protocol
    //
    Status = gBS->CloseProtocol (
                    Controller,
                    &gEfiPciIoProtocolGuid,
                    This->DriverBindingHandle,
                    Controller
                    );
    ASSERT_EFI_ERROR (Status);

    Status = gBS->CloseProtocol (
                    Controller,
                    &gEfiDevicePathProtocolGuid,
                    This->DriverBindingHandle,
                    Controller
                    );
    ASSERT_EFI_ERROR (Status);
    return EFI_SUCCESS;
  }

  ASSERT (NumberOfChildren == 1);
  Status = gBS->OpenProtocol (
                  ChildHandleBuffer[0],
                  &gEfiGraphicsOutputProtocolGuid,
                  (VOID **)&Gop,
                  This->DriverBindingHandle,
                  ChildHandleBuffer[0],
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Private = GRAPHICS_OUTPUT_PRIVATE_FROM_THIS (Gop);

  if (Private->ReadyToBootEvent != NULL) {
    gBS->CloseEvent (Private->ReadyToBootEvent);
    Private->ReadyToBootEvent = NULL;
  }

  Status = gBS->CloseProtocol (
                  Controller,
                  &gEfiPciIoProtocolGuid,
                  This->DriverBindingHandle,
                  Private->GraphicsOutputHandle
                  );
  ASSERT_EFI_ERROR (Status);
  //
  // Remove the GOP protocol interface from the system
  //
  Status = gBS->UninstallMultipleProtocolInterfaces (
                  Private->GraphicsOutputHandle,
                  &gEfiGraphicsOutputProtocolGuid,
                  &Private->GraphicsOutput,
                  &gEfiDevicePathProtocolGuid,
                  Private->DevicePath,
                  NULL
                  );
  if (!EFI_ERROR (Status)) {
    //
    // Restore original PCI attributes
    //
    Status = Private->PciIo->Attributes (
                               Private->PciIo,
                               EfiPciIoAttributeOperationSet,
                               Private->PciAttributes,
                               NULL
                               );
    ASSERT_EFI_ERROR (Status);

    FreePool (Private->DevicePath);
    FreePool (Private->FrameBufferBltLibConfigure);
    mDriverStarted = FALSE;
  } else {
    Status = gBS->OpenProtocol (
                    Controller,
                    &gEfiPciIoProtocolGuid,
                    (VOID **)&Private->PciIo,
                    This->DriverBindingHandle,
                    Private->GraphicsOutputHandle,
                    EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER
                    );
    ASSERT_EFI_ERROR (Status);
  }

  return Status;
}

EFI_DRIVER_BINDING_PROTOCOL  mGraphicsOutputDriverBinding = {
  GraphicsOutputDriverBindingSupported,
  GraphicsOutputDriverBindingStart,
  GraphicsOutputDriverBindingStop,
  0x10,
  NULL,
  NULL
};

/**
  The Entry Point for GraphicsOutput driver.

  It installs DriverBinding, ComponentName and ComponentName2 protocol if there is
  GraphicsInfo HOB passed from Graphics PEIM.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
InitializeGraphicsOutput (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  VOID        *HobStart;

  HobStart = GetFirstGuidHob (&gEfiGraphicsInfoHobGuid);

  if ((HobStart == NULL) || (GET_GUID_HOB_DATA_SIZE (HobStart) < sizeof (EFI_PEI_GRAPHICS_INFO_HOB))) {
    return EFI_NOT_FOUND;
  }

  Status = EfiLibInstallDriverBindingComponentName2 (
             ImageHandle,
             SystemTable,
             &mGraphicsOutputDriverBinding,
             ImageHandle,
             &mGraphicsOutputComponentName,
             &mGraphicsOutputComponentName2
             );
  ASSERT_EFI_ERROR (Status);

  return Status;
}
