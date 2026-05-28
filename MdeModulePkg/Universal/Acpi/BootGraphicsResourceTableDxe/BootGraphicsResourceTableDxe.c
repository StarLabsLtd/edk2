/** @file
  This module install ACPI Boot Graphics Resource Table (BGRT).

  Copyright (c) 2011 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2016, Microsoft Corporation<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>

#include <IndustryStandard/Acpi.h>

#include <Protocol/AcpiTable.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/BootLogo.h>
#include <Protocol/BootLogo2.h>

#include <Guid/EventGroup.h>
#include <Guid/DisplayNativeResolution.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/SafeIntLib.h>
#include <Library/BmpSupportLib.h>

/**
  Update information of logo image drawn on screen.

  @param[in] This          The pointer to the Boot Logo protocol 2 instance.
  @param[in] BltBuffer     The BLT buffer for logo drawn on screen. If BltBuffer
                           is set to NULL, it indicates that logo image is no
                           longer on the screen.
  @param[in] DestinationX  X coordinate of destination for the BltBuffer.
  @param[in] DestinationY  Y coordinate of destination for the BltBuffer.
  @param[in] Width         Width of rectangle in BltBuffer in pixels.
  @param[in] Height        Hight of rectangle in BltBuffer in pixels.

  @retval EFI_SUCCESS            The boot logo information was updated.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.
  @retval EFI_OUT_OF_RESOURCES   The logo information was not updated due to
                                 insufficient memory resources.
**/
EFI_STATUS
EFIAPI
SetBootLogo (
  IN EFI_BOOT_LOGO_PROTOCOL         *This,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BltBuffer       OPTIONAL,
  IN UINTN                          DestinationX,
  IN UINTN                          DestinationY,
  IN UINTN                          Width,
  IN UINTN                          Height
  );

/**
  Update information of logo image drawn on screen.

  @param[in] This          The pointer to the Boot Logo protocol 2 instance.
  @param[in] BltBuffer     The BLT buffer for logo drawn on screen. If BltBuffer
                           is set to NULL, it indicates that logo image is no
                           longer on the screen.
  @param[in] DestinationX  X coordinate of destination for the BltBuffer.
  @param[in] DestinationY  Y coordinate of destination for the BltBuffer.
  @param[in] Width         Width of rectangle in BltBuffer in pixels.
  @param[in] Height        Hight of rectangle in BltBuffer in pixels.

  @retval EFI_SUCCESS            The boot logo information was updated.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.
  @retval EFI_OUT_OF_RESOURCES   The logo information was not updated due to
                                 insufficient memory resources.
**/
EFI_STATUS
EFIAPI
SetBootLogo2 (
  IN EDKII_BOOT_LOGO2_PROTOCOL      *This,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BltBuffer       OPTIONAL,
  IN UINTN                          DestinationX,
  IN UINTN                          DestinationY,
  IN UINTN                          Width,
  IN UINTN                          Height
  );

/**
  Get the location of the boot logo on the screen.

  @param[in]  This          The pointer to the Boot Logo Protocol 2 instance
  @param[out] BltBuffer     Returns pointer to the GOP BLT buffer that was
                            previously registered with SetBootLogo2(). The
                            buffer returned must not be modified or freed.
  @param[out] DestinationX  Returns the X start position of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().
  @param[out] DestinationY  Returns the Y start position of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().
  @param[out] Width         Returns the width of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().
  @param[out] Height        Returns the height of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().

  @retval EFI_SUCCESS            The location of the boot logo was returned.
  @retval EFI_NOT_READY          The boot logo has not been set.
  @retval EFI_INVALID_PARAMETER  BltBuffer is NULL.
  @retval EFI_INVALID_PARAMETER  DestinationX is NULL.
  @retval EFI_INVALID_PARAMETER  DestinationY is NULL.
  @retval EFI_INVALID_PARAMETER  Width is NULL.
  @retval EFI_INVALID_PARAMETER  Height is NULL.
**/
EFI_STATUS
EFIAPI
GetBootLogo2 (
  IN  EDKII_BOOT_LOGO2_PROTOCOL      *This,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **BltBuffer,
  OUT UINTN                          *DestinationX,
  OUT UINTN                          *DestinationY,
  OUT UINTN                          *Width,
  OUT UINTN                          *Height
  );

//
// Boot Logo Protocol Handle
//
EFI_HANDLE  mBootLogoHandle = NULL;

//
// Boot Logo Protocol Instance
//
EFI_BOOT_LOGO_PROTOCOL  mBootLogoProtocolTemplate = {
  SetBootLogo
};

///
/// Boot Logo 2 Protocol instance
///
EDKII_BOOT_LOGO2_PROTOCOL  mBootLogo2ProtocolTemplate = {
  SetBootLogo2,
  GetBootLogo2
};

EFI_EVENT                      mBootGraphicsReadyToBootEvent;
UINTN                          mBootGraphicsResourceTableKey = 0;
BOOLEAN                        mIsLogoValid                  = FALSE;
EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *mLogoBltBuffer               = NULL;
UINTN                          mLogoDestX                    = 0;
UINTN                          mLogoDestY                    = 0;
UINTN                          mLogoWidth                    = 0;
UINTN                          mLogoHeight                   = 0;
BOOLEAN                        mAcpiBgrtInstalled            = FALSE;
BOOLEAN                        mAcpiBgrtStatusChanged        = FALSE;
BOOLEAN                        mAcpiBgrtBufferChanged        = FALSE;

//
// ACPI Boot Graphics Resource Table template
//
EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE  mBootGraphicsResourceTableTemplate = {
  {
    EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE_SIGNATURE,
    sizeof (EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE),
    EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE_REVISION, // Revision
    0x00,                                               // Checksum will be updated at runtime
    //
    // It is expected that these values will be updated at EntryPoint.
    //
    { 0x00 },   // OEM ID is a 6 bytes long field
    0x00,       // OEM Table ID(8 bytes long)
    0x00,       // OEM Revision
    0x00,       // Creator ID
    0x00,       // Creator Revision
  },
  EFI_ACPI_5_0_BGRT_VERSION,         // Version
  EFI_ACPI_5_0_BGRT_STATUS_VALID,    // Status
  EFI_ACPI_5_0_BGRT_IMAGE_TYPE_BMP,  // Image Type
  0,                                 // Image Address
  0,                                 // Image Offset X
  0                                  // Image Offset Y
};

typedef struct {
  UINTN    Scale;
  UINTN    FramebufferWidth;
  UINTN    FramebufferHeight;
  UINTN    NativeWidth;
  UINTN    NativeHeight;
} BGRT_NATIVE_RESOLUTION_SCALE;

/**
  Scale a BLT buffer by an integer factor.

  @param[in]  Source       Source BLT buffer.
  @param[in]  SourceWidth  Source width in pixels.
  @param[in]  SourceHeight Source height in pixels.
  @param[in]  Scale        Integer scale factor.
  @param[out] Destination  Allocated scaled BLT buffer.
  @param[out] ScaledWidth  Scaled width in pixels.
  @param[out] ScaledHeight Scaled height in pixels.

  @retval EFI_SUCCESS           The buffer was scaled.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
  @retval EFI_OUT_OF_RESOURCES  The scaled buffer could not be allocated.
**/
STATIC
EFI_STATUS
ScaleBltBufferInteger (
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Source,
  IN  UINTN                          SourceWidth,
  IN  UINTN                          SourceHeight,
  IN  UINTN                          Scale,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **Destination,
  OUT UINTN                          *ScaledWidth,
  OUT UINTN                          *ScaledHeight
  )
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBuffer;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixel;
  EFI_STATUS                     Status;
  UINTN                          BufferSize;
  UINTN                          Column;
  UINTN                          DestinationHeight;
  UINTN                          DestinationWidth;
  UINTN                          PixelCount;
  UINTN                          Row;
  UINTN                          ScaleColumn;
  UINTN                          ScaleRow;
  UINT32                         Result32;

  if ((Source == NULL) || (Destination == NULL) || (ScaledWidth == NULL) ||
      (ScaledHeight == NULL) || (SourceWidth == 0) || (SourceHeight == 0) ||
      (Scale <= 1))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = SafeUintnMult (SourceWidth, Scale, &DestinationWidth);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SafeUintnMult (SourceHeight, Scale, &DestinationHeight);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SafeUintnToUint32 (DestinationWidth, &Result32);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SafeUintnToUint32 (DestinationHeight, &Result32);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SafeUintnMult (DestinationWidth, DestinationHeight, &PixelCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SafeUintnMult (
             PixelCount,
             sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL),
             &BufferSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ScaledBuffer = AllocateZeroPool (BufferSize);
  if (ScaledBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  for (Row = 0; Row < SourceHeight; Row++) {
    for (Column = 0; Column < SourceWidth; Column++) {
      Pixel = Source[Row * SourceWidth + Column];
      for (ScaleRow = 0; ScaleRow < Scale; ScaleRow++) {
        for (ScaleColumn = 0; ScaleColumn < Scale; ScaleColumn++) {
          ScaledBuffer[((Row * Scale + ScaleRow) * DestinationWidth) + (Column * Scale + ScaleColumn)] = Pixel;
        }
      }
    }
  }

  *Destination  = ScaledBuffer;
  *ScaledWidth  = DestinationWidth;
  *ScaledHeight = DestinationHeight;
  return EFI_SUCCESS;
}

/**
  Get the integer scale between the current firmware framebuffer and the native
  display resolution, if the bootloader supplied one.

  @param[out] NativeScale  Native-resolution scale information.

  @retval TRUE   A same-aspect integer native scale is available.
  @retval FALSE  Native resolution is unavailable or not an exact scale.
**/
STATIC
BOOLEAN
GetNativeResolutionScale (
  OUT BGRT_NATIVE_RESOLUTION_SCALE  *NativeScale
  )
{
  EDKII_DISPLAY_NATIVE_RESOLUTION  *NativeResolution;
  EFI_GRAPHICS_OUTPUT_PROTOCOL     *GraphicsOutput;
  EFI_HOB_GUID_TYPE                *GuidHob;
  EFI_STATUS                       Status;
  UINT32                           HorizontalResolution;
  UINT32                           HorizontalScale;
  UINT32                           VerticalResolution;
  UINT32                           VerticalScale;

  if (NativeScale == NULL) {
    return FALSE;
  }

  ZeroMem (NativeScale, sizeof (*NativeScale));
  NativeScale->Scale = 1;
  GuidHob = GetFirstGuidHob (&gEdkiiDisplayNativeResolutionGuid);
  if ((GuidHob == NULL) ||
      (GET_GUID_HOB_DATA_SIZE (GuidHob) < sizeof (EDKII_DISPLAY_NATIVE_RESOLUTION)))
  {
    return FALSE;
  }

  NativeResolution = (EDKII_DISPLAY_NATIVE_RESOLUTION *)GET_GUID_HOB_DATA (GuidHob);
  Status           = gBS->LocateProtocol (
                            &gEfiGraphicsOutputProtocolGuid,
                            NULL,
                            (VOID **)&GraphicsOutput
                            );
  if (EFI_ERROR (Status) ||
      (GraphicsOutput == NULL) ||
      (GraphicsOutput->Mode == NULL) ||
      (GraphicsOutput->Mode->Info == NULL))
  {
    return FALSE;
  }

  HorizontalResolution = GraphicsOutput->Mode->Info->HorizontalResolution;
  VerticalResolution   = GraphicsOutput->Mode->Info->VerticalResolution;
  if ((HorizontalResolution == 0) || (VerticalResolution == 0) ||
      (NativeResolution->HorizontalResolution <= HorizontalResolution) ||
      (NativeResolution->VerticalResolution <= VerticalResolution) ||
      ((NativeResolution->HorizontalResolution % HorizontalResolution) != 0) ||
      ((NativeResolution->VerticalResolution % VerticalResolution) != 0))
  {
    return FALSE;
  }

  HorizontalScale = NativeResolution->HorizontalResolution / HorizontalResolution;
  VerticalScale   = NativeResolution->VerticalResolution / VerticalResolution;
  if ((HorizontalScale <= 1) || (HorizontalScale != VerticalScale)) {
    return FALSE;
  }

  NativeScale->Scale             = HorizontalScale;
  NativeScale->FramebufferWidth  = HorizontalResolution;
  NativeScale->FramebufferHeight = VerticalResolution;
  NativeScale->NativeWidth       = NativeResolution->HorizontalResolution;
  NativeScale->NativeHeight      = NativeResolution->VerticalResolution;
  return TRUE;
}

/**
  Scale a BGRT offset into native display coordinates.

  If the source coordinate is centered in the firmware framebuffer, recenter in
  the native coordinate space instead of multiplying the truncated source offset.

  @param[in]  Destination       Source destination coordinate.
  @param[in]  SourceExtent      Source logo extent.
  @param[in]  ScaledExtent      Scaled logo extent.
  @param[in]  FramebufferExtent Source framebuffer extent.
  @param[in]  NativeExtent      Native display extent.
  @param[in]  Scale             Integer scale factor.
  @param[out] ScaledDestination Scaled destination coordinate.

  @retval EFI_SUCCESS           The offset was scaled.
  @retval EFI_INVALID_PARAMETER One or more parameters are invalid.
  @retval EFI_UNSUPPORTED       The scaled logo does not fit the native extent.
  @retval other                 The offset could not be scaled.
**/
STATIC
EFI_STATUS
ScaleBgrtDestination (
  IN  UINTN  Destination,
  IN  UINTN  SourceExtent,
  IN  UINTN  ScaledExtent,
  IN  UINTN  FramebufferExtent,
  IN  UINTN  NativeExtent,
  IN  UINTN  Scale,
  OUT UINTN  *ScaledDestination
  )
{
  if ((ScaledDestination == NULL) || (SourceExtent == 0) ||
      (ScaledExtent == 0) || (FramebufferExtent < SourceExtent) ||
      (NativeExtent < ScaledExtent) || (Scale <= 1))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (Destination == ((FramebufferExtent - SourceExtent) / 2)) {
    *ScaledDestination = (NativeExtent - ScaledExtent) / 2;
    return EFI_SUCCESS;
  }

  return SafeUintnMult (Destination, Scale, ScaledDestination);
}

/**
  Scale the BGRT logo and offsets into native display coordinates.

  @param[in,out] BltBuffer    Logo BLT buffer.
  @param[in,out] DestinationX Logo destination X.
  @param[in,out] DestinationY Logo destination Y.
  @param[in,out] Width        Logo width.
  @param[in,out] Height       Logo height.

  @retval EFI_SUCCESS      The logo was scaled.
  @retval EFI_NOT_FOUND    No native scale is available.
  @retval other            The logo could not be scaled.
**/
STATIC
EFI_STATUS
ScaleBgrtLogoToNativeResolution (
  IN OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **BltBuffer,
  IN OUT UINTN                          *DestinationX,
  IN OUT UINTN                          *DestinationY,
  IN OUT UINTN                          *Width,
  IN OUT UINTN                          *Height
  )
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBuffer;
  BGRT_NATIVE_RESOLUTION_SCALE   NativeScale;
  EFI_STATUS                     Status;
  UINTN                          ScaledDestinationX;
  UINTN                          ScaledDestinationY;
  UINTN                          ScaledHeight;
  UINTN                          ScaledWidth;

  if ((BltBuffer == NULL) || (*BltBuffer == NULL) || (DestinationX == NULL) ||
      (DestinationY == NULL) || (Width == NULL) || (Height == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (!GetNativeResolutionScale (&NativeScale)) {
    return EFI_NOT_FOUND;
  }

  ScaledBuffer = NULL;
  Status       = ScaleBltBufferInteger (
                   *BltBuffer,
                   *Width,
                   *Height,
                   NativeScale.Scale,
                   &ScaledBuffer,
                   &ScaledWidth,
                   &ScaledHeight
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ScaleBgrtDestination (
             *DestinationX,
             *Width,
             ScaledWidth,
             NativeScale.FramebufferWidth,
             NativeScale.NativeWidth,
             NativeScale.Scale,
             &ScaledDestinationX
             );
  if (EFI_ERROR (Status)) {
    FreePool (ScaledBuffer);
    return Status;
  }

  Status = ScaleBgrtDestination (
             *DestinationY,
             *Height,
             ScaledHeight,
             NativeScale.FramebufferHeight,
             NativeScale.NativeHeight,
             NativeScale.Scale,
             &ScaledDestinationY
             );
  if (EFI_ERROR (Status)) {
    FreePool (ScaledBuffer);
    return Status;
  }

  DEBUG ((
    DEBUG_INFO,
    "%a: scaled BGRT logo by %u from %ux%u @ %u,%u to %ux%u @ %u,%u\n",
    __func__,
    (UINT32)NativeScale.Scale,
    (UINT32)*Width,
    (UINT32)*Height,
    (UINT32)*DestinationX,
    (UINT32)*DestinationY,
    (UINT32)ScaledWidth,
    (UINT32)ScaledHeight,
    (UINT32)ScaledDestinationX,
    (UINT32)ScaledDestinationY
    ));

  *BltBuffer    = ScaledBuffer;
  *DestinationX = ScaledDestinationX;
  *DestinationY = ScaledDestinationY;
  *Width        = ScaledWidth;
  *Height       = ScaledHeight;
  return EFI_SUCCESS;
}

/**
  Update information of logo image drawn on screen.

  @param  This           The pointer to the Boot Logo protocol instance.
  @param  BltBuffer      The BLT buffer for logo drawn on screen. If BltBuffer
                         is set to NULL, it indicates that logo image is no
                         longer on the screen.
  @param  DestinationX   X coordinate of destination for the BltBuffer.
  @param  DestinationY   Y coordinate of destination for the BltBuffer.
  @param  Width          Width of rectangle in BltBuffer in pixels.
  @param  Height         Hight of rectangle in BltBuffer in pixels.

  @retval EFI_SUCCESS             The boot logo information was updated.
  @retval EFI_INVALID_PARAMETER   One of the parameters has an invalid value.
  @retval EFI_OUT_OF_RESOURCES    The logo information was not updated due to
                                  insufficient memory resources.

**/
EFI_STATUS
EFIAPI
SetBootLogo (
  IN EFI_BOOT_LOGO_PROTOCOL         *This,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BltBuffer       OPTIONAL,
  IN UINTN                          DestinationX,
  IN UINTN                          DestinationY,
  IN UINTN                          Width,
  IN UINTN                          Height
  )
{
  //
  // Call same service in Boot Logo 2 Protocol
  //
  return SetBootLogo2 (
           &mBootLogo2ProtocolTemplate,
           BltBuffer,
           DestinationX,
           DestinationY,
           Width,
           Height
           );
}

/**
  Update information of logo image drawn on screen.

  @param[in] This          The pointer to the Boot Logo protocol 2 instance.
  @param[in] BltBuffer     The BLT buffer for logo drawn on screen. If BltBuffer
                           is set to NULL, it indicates that logo image is no
                           longer on the screen.
  @param[in] DestinationX  X coordinate of destination for the BltBuffer.
  @param[in] DestinationY  Y coordinate of destination for the BltBuffer.
  @param[in] Width         Width of rectangle in BltBuffer in pixels.
  @param[in] Height        Hight of rectangle in BltBuffer in pixels.

  @retval EFI_SUCCESS            The boot logo information was updated.
  @retval EFI_INVALID_PARAMETER  One of the parameters has an invalid value.
  @retval EFI_OUT_OF_RESOURCES   The logo information was not updated due to
                                 insufficient memory resources.
**/
EFI_STATUS
EFIAPI
SetBootLogo2 (
  IN EDKII_BOOT_LOGO2_PROTOCOL      *This,
  IN EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BltBuffer       OPTIONAL,
  IN UINTN                          DestinationX,
  IN UINTN                          DestinationY,
  IN UINTN                          Width,
  IN UINTN                          Height
  )
{
  EFI_STATUS  Status;
  UINTN       BufferSize;
  UINT32      Result32;

  if (BltBuffer == NULL) {
    mIsLogoValid           = FALSE;
    mAcpiBgrtStatusChanged = TRUE;
    return EFI_SUCCESS;
  }

  //
  // Width and height are not allowed to be zero.
  //
  if ((Width == 0) || (Height == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Verify destination, width, and height do not overflow 32-bit values.
  // The Boot Graphics Resource Table only has 32-bit fields for these values.
  //
  Status = SafeUintnToUint32 (DestinationX, &Result32);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = SafeUintnToUint32 (DestinationY, &Result32);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = SafeUintnToUint32 (Width, &Result32);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = SafeUintnToUint32 (Height, &Result32);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Ensure the Height * Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL) does
  // not overflow UINTN
  //
  Status = SafeUintnMult (
             Width,
             Height,
             &BufferSize
             );
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  Status = SafeUintnMult (
             BufferSize,
             sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL),
             &BufferSize
             );
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  //
  // Update state
  //
  mAcpiBgrtBufferChanged = TRUE;

  //
  // Free old logo buffer
  //
  if (mLogoBltBuffer != NULL) {
    FreePool (mLogoBltBuffer);
    mLogoBltBuffer = NULL;
  }

  //
  // Allocate new logo buffer
  //
  mLogoBltBuffer = AllocateCopyPool (BufferSize, BltBuffer);
  if (mLogoBltBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  mLogoDestX   = DestinationX;
  mLogoDestY   = DestinationY;
  mLogoWidth   = Width;
  mLogoHeight  = Height;
  mIsLogoValid = TRUE;

  return EFI_SUCCESS;
}

/**
  Get the location of the boot logo on the screen.

  @param[in]  This          The pointer to the Boot Logo Protocol 2 instance
  @param[out] BltBuffer     Returns pointer to the GOP BLT buffer that was
                            previously registered with SetBootLogo2(). The
                            buffer returned must not be modified or freed.
  @param[out] DestinationX  Returns the X start position of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().
  @param[out] DestinationY  Returns the Y start position of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().
  @param[out] Width         Returns the width of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().
  @param[out] Height        Returns the height of the GOP BLT buffer
                            that was previously registered with SetBootLogo2().

  @retval EFI_SUCCESS            The location of the boot logo was returned.
  @retval EFI_NOT_READY          The boot logo has not been set.
  @retval EFI_INVALID_PARAMETER  BltBuffer is NULL.
  @retval EFI_INVALID_PARAMETER  DestinationX is NULL.
  @retval EFI_INVALID_PARAMETER  DestinationY is NULL.
  @retval EFI_INVALID_PARAMETER  Width is NULL.
  @retval EFI_INVALID_PARAMETER  Height is NULL.
**/
EFI_STATUS
EFIAPI
GetBootLogo2 (
  IN  EDKII_BOOT_LOGO2_PROTOCOL      *This,
  OUT EFI_GRAPHICS_OUTPUT_BLT_PIXEL  **BltBuffer,
  OUT UINTN                          *DestinationX,
  OUT UINTN                          *DestinationY,
  OUT UINTN                          *Width,
  OUT UINTN                          *Height
  )
{
  //
  // If the boot logo has not been set with SetBootLogo() or SetBootLogo() was
  // called with a NULL BltBuffer then the boot logo is not valid and
  // EFI_NOT_READY is returned.
  //
  if (mLogoBltBuffer == NULL) {
    DEBUG ((DEBUG_ERROR, "Request to get boot logo location before boot logo has been set.\n"));
    return EFI_NOT_READY;
  }

  //
  // Make sure none of the boot logo location parameters are NULL.
  //
  if ((BltBuffer == NULL) || (DestinationX == NULL) || (DestinationY == NULL) ||
      (Width == NULL) || (Height == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Boot logo is valid.  Return values from module globals.
  //
  *BltBuffer    = mLogoBltBuffer;
  *DestinationX = mLogoDestX;
  *DestinationY = mLogoDestY;
  *Width        = mLogoWidth;
  *Height       = mLogoHeight;

  return EFI_SUCCESS;
}

/**
  Notify function for event group EFI_EVENT_GROUP_READY_TO_BOOT. This is used to
  install the Boot Graphics Resource Table.

  @param[in]  Event   The Event that is being processed.
  @param[in]  Context The Event Context.

**/
VOID
EFIAPI
BgrtReadyToBootEventNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS                     Status;
  EFI_ACPI_TABLE_PROTOCOL        *AcpiTableProtocol;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *BgrtLogoBltBuffer;
  VOID                           *ImageBuffer;
  UINT32                         BmpSize;
  UINTN                          BgrtLogoDestX;
  UINTN                          BgrtLogoDestY;
  UINTN                          BgrtLogoHeight;
  UINTN                          BgrtLogoWidth;

  //
  // Get ACPI Table protocol.
  //
  Status = gBS->LocateProtocol (
                  &gEfiAcpiTableProtocolGuid,
                  NULL,
                  (VOID **)&AcpiTableProtocol
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  //
  // Check whether Boot Graphics Resource Table is already installed.
  //
  if (mAcpiBgrtInstalled) {
    if (!mAcpiBgrtStatusChanged && !mAcpiBgrtBufferChanged) {
      //
      // Nothing has changed
      //
      return;
    } else {
      //
      // If BGRT data change happens, then uninstall orignal AcpiTable first
      //
      Status = AcpiTableProtocol->UninstallAcpiTable (
                                    AcpiTableProtocol,
                                    mBootGraphicsResourceTableKey
                                    );
      if (EFI_ERROR (Status)) {
        return;
      }
    }
  } else {
    //
    // Check whether Logo exists
    //
    if (mLogoBltBuffer == NULL) {
      return;
    }
  }

  if (mAcpiBgrtBufferChanged) {
    BgrtLogoBltBuffer = mLogoBltBuffer;
    BgrtLogoDestX     = mLogoDestX;
    BgrtLogoDestY     = mLogoDestY;
    BgrtLogoWidth     = mLogoWidth;
    BgrtLogoHeight    = mLogoHeight;
    Status            = ScaleBgrtLogoToNativeResolution (
                          &BgrtLogoBltBuffer,
                          &BgrtLogoDestX,
                          &BgrtLogoDestY,
                          &BgrtLogoWidth,
                          &BgrtLogoHeight
                          );
    if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
      DEBUG ((DEBUG_INFO, "%a: failed to scale BGRT logo to native resolution: %r\n", __func__, Status));
      BgrtLogoBltBuffer = mLogoBltBuffer;
      BgrtLogoDestX     = mLogoDestX;
      BgrtLogoDestY     = mLogoDestY;
      BgrtLogoWidth     = mLogoWidth;
      BgrtLogoHeight    = mLogoHeight;
    }

    //
    // Free the old BMP image buffer
    //
    ImageBuffer = (UINT8 *)(UINTN)mBootGraphicsResourceTableTemplate.ImageAddress;
    if (ImageBuffer != NULL) {
      FreePool (ImageBuffer);
    }

    //
    // Convert GOP Blt buffer to BMP image.  Pass in ImageBuffer set to NULL
    // so the BMP image is allocated by TranslateGopBltToBmp().
    //
    ImageBuffer = NULL;
    Status      = TranslateGopBltToBmp (
                    BgrtLogoBltBuffer,
                    (UINT32)BgrtLogoHeight,
                    (UINT32)BgrtLogoWidth,
                    &ImageBuffer,
                    &BmpSize
                    );
    if (BgrtLogoBltBuffer != mLogoBltBuffer) {
      FreePool (BgrtLogoBltBuffer);
    }

    if (EFI_ERROR (Status)) {
      return;
    }

    //
    // Free the logo buffer
    //
    FreePool (mLogoBltBuffer);
    mLogoBltBuffer = NULL;

    //
    // Update BMP image fields of the Boot Graphics Resource Table
    //
    mBootGraphicsResourceTableTemplate.ImageAddress = (UINT64)(UINTN)ImageBuffer;
    mBootGraphicsResourceTableTemplate.ImageOffsetX = (UINT32)BgrtLogoDestX;
    mBootGraphicsResourceTableTemplate.ImageOffsetY = (UINT32)BgrtLogoDestY;
  }

  //
  // Update Status field of Boot Graphics Resource Table
  //
  if (mIsLogoValid) {
    mBootGraphicsResourceTableTemplate.Status = EFI_ACPI_5_0_BGRT_STATUS_VALID;
  } else {
    mBootGraphicsResourceTableTemplate.Status = EFI_ACPI_5_0_BGRT_STATUS_INVALID;
  }

  //
  // Update Checksum of Boot Graphics Resource Table
  //
  mBootGraphicsResourceTableTemplate.Header.Checksum = 0;
  mBootGraphicsResourceTableTemplate.Header.Checksum =
    CalculateCheckSum8 (
      (UINT8 *)&mBootGraphicsResourceTableTemplate,
      sizeof (EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE)
      );

  //
  // Publish Boot Graphics Resource Table.
  //
  Status = AcpiTableProtocol->InstallAcpiTable (
                                AcpiTableProtocol,
                                &mBootGraphicsResourceTableTemplate,
                                sizeof (EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE),
                                &mBootGraphicsResourceTableKey
                                );
  if (EFI_ERROR (Status)) {
    return;
  }

  mAcpiBgrtInstalled     = TRUE;
  mAcpiBgrtStatusChanged = FALSE;
  mAcpiBgrtBufferChanged = FALSE;
}

/**
  The module Entry Point of the Boot Graphics Resource Table DXE driver.

  @param[in]  ImageHandle    The firmware allocated handle for the EFI image.
  @param[in]  SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS    The entry point is executed successfully.
  @retval Other          Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
BootGraphicsDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                   Status;
  EFI_ACPI_DESCRIPTION_HEADER  *Header;

  //
  // Update Header fields of Boot Graphics Resource Table from PCDs
  //
  Header = &mBootGraphicsResourceTableTemplate.Header;
  ZeroMem (Header->OemId, sizeof (Header->OemId));
  CopyMem (
    Header->OemId,
    PcdGetPtr (PcdAcpiDefaultOemId),
    MIN (PcdGetSize (PcdAcpiDefaultOemId), sizeof (Header->OemId))
    );
  WriteUnaligned64 (&Header->OemTableId, PcdGet64 (PcdAcpiDefaultOemTableId));
  Header->OemRevision     = PcdGet32 (PcdAcpiDefaultOemRevision);
  Header->CreatorId       = PcdGet32 (PcdAcpiDefaultCreatorId);
  Header->CreatorRevision = PcdGet32 (PcdAcpiDefaultCreatorRevision);

  //
  // Install Boot Logo and Boot Logo 2 Protocols.
  //
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mBootLogoHandle,
                  &gEfiBootLogoProtocolGuid,
                  &mBootLogoProtocolTemplate,
                  &gEdkiiBootLogo2ProtocolGuid,
                  &mBootLogo2ProtocolTemplate,
                  NULL
                  );
  ASSERT_EFI_ERROR (Status);

  //
  // Register notify function to install BGRT on ReadyToBoot Event.
  //
  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  BgrtReadyToBootEventNotify,
                  NULL,
                  &gEfiEventReadyToBootGuid,
                  &mBootGraphicsReadyToBootEvent
                  );
  ASSERT_EFI_ERROR (Status);

  return Status;
}
