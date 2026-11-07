/** @file
  Host fixture for the private GOP ReadyToBoot callback.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "../../../GraphicsOutputDxe/GraphicsOutput.c"

EFI_GRAPHICS_OUTPUT_PROTOCOL *
TestCreateGraphicsWithSize (
  VOID                  *Pixels,
  EFI_PHYSICAL_ADDRESS  PhysicalBase,
  BOOLEAN               LogicalMode,
  UINT32                Width,
  UINT32                Height
  )
{
  GRAPHICS_OUTPUT_PRIVATE_DATA  *Private;
  RETURN_STATUS                 Status;
  UINTN                         Size;

  Private = AllocateCopyPool (sizeof (*Private), &mGraphicsOutputInstanceTemplate);
  if (Private == NULL) {
    return NULL;
  }

  Private->PhysicalModeInfo.HorizontalResolution = Width;
  Private->PhysicalModeInfo.VerticalResolution   = Height;
  Private->PhysicalModeInfo.PixelsPerScanLine    = Width;
  Private->PhysicalModeInfo.PixelFormat          = PixelBlueGreenRedReserved8BitPerColor;
  Private->PhysicalFrameBufferBase               = PhysicalBase;
  Private->PhysicalFrameBufferSize               = Width * Height * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);
  Private->GraphicsOutput.Mode                   = &Private->GraphicsOutputMode;
  Private->HasHiDpiMode                          = TRUE;
  Private->LogicalModeScale                      = 2;
  Size                                           = 0;
  Status                                         = FrameBufferBltConfigure (Pixels, &Private->PhysicalModeInfo, NULL, &Size);
  if (Status != RETURN_BUFFER_TOO_SMALL) {
    FreePool (Private);
    return NULL;
  }

  Private->FrameBufferBltLibConfigure = AllocatePool (Size);
  if (Private->FrameBufferBltLibConfigure == NULL) {
    FreePool (Private);
    return NULL;
  }

  Status = FrameBufferBltConfigure (
             Pixels,
             &Private->PhysicalModeInfo,
             Private->FrameBufferBltLibConfigure,
             &Size
             );
  if (RETURN_ERROR (Status)) {
    FreePool (Private->FrameBufferBltLibConfigure);
    FreePool (Private);
    return NULL;
  }

  GraphicsOutputSetModeInternal (&Private->GraphicsOutput, GRAPHICS_OUTPUT_MODE_PHYSICAL, FALSE);
  if (LogicalMode) {
    Private->GraphicsOutputMode.Mode = GRAPHICS_OUTPUT_MODE_HIDPI;
    Private->FrameBufferScale        = 2;
  }

  return &Private->GraphicsOutput;
}

VOID
TestSignalGraphicsReadyToBoot (
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  GraphicsOutputReadyToBoot (NULL, GRAPHICS_OUTPUT_PRIVATE_FROM_THIS (Gop));
}

VOID
TestFreeGraphics (
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  GRAPHICS_OUTPUT_PRIVATE_DATA  *Private = GRAPHICS_OUTPUT_PRIVATE_FROM_THIS (Gop);

  FreePool (Private->FrameBufferBltLibConfigure);
  FreePool (Private);
}

EFI_GRAPHICS_OUTPUT_PROTOCOL *
TestCreateGraphics (
  VOID                  *Pixels,
  EFI_PHYSICAL_ADDRESS  Base,
  BOOLEAN               Logical
  )
{
  return TestCreateGraphicsWithSize (Pixels, Base, Logical, 32, 32);
}

EFI_GRAPHICS_OUTPUT_PROTOCOL *
TestCreateStandardGraphics (
  VOID                  *Pixels,
  EFI_PHYSICAL_ADDRESS  Base
  )
{
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop = TestCreateGraphicsWithSize (Pixels, Base, FALSE, 640, 480);

  if (Gop != NULL) {
    Gop->Mode->MaxMode = 1;
  }

  return Gop;
}
