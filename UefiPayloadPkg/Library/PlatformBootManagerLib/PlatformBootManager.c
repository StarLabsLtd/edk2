/** @file
  This file include all platform action which can be customized
  by IBV/OEM.

Copyright (c) 2015 - 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PlatformBootManager.h"
#include "PlatformConsole.h"
#include <Library/Tcg2PhysicalPresenceLib.h>
#include <Protocol/FirmwareVolume2.h>

STATIC
BOOLEAN
ShouldScaleBootPromptForHiDpi (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput
  )
{
  UINT32  HorizontalResolution;
  UINT32  VerticalResolution;

  if ((GraphicsOutput == NULL) ||
      (GraphicsOutput->Mode == NULL) ||
      (GraphicsOutput->Mode->Info == NULL) ||
      !FeaturePcdGet (PcdPayloadFbHiDpiSupport))
  {
    return FALSE;
  }

  HorizontalResolution = GraphicsOutput->Mode->Info->HorizontalResolution;
  VerticalResolution   = GraphicsOutput->Mode->Info->VerticalResolution;

  return (HorizontalResolution >= PcdGet32 (PcdPayloadFbHiDpiScaleThresholdHorizontal)) &&
         (VerticalResolution >= PcdGet32 (PcdPayloadFbHiDpiScaleThresholdVertical)) &&
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

    if (ShouldScaleBootPromptForHiDpi (*GraphicsOutput)) {
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
  EFI_FONT_DISPLAY_INFO  FontInfo;
  EFI_HII_ROW_INFO       *RowInfoArray;
  UINTN                  RowInfoArraySize;
  UINTN                  Columns;
  UINTN                  Rows;
  UINTN                  BaseGlyphWidth;
  UINTN                  BaseGlyphHeight;
  UINTN                  PointX;
  UINTN                  PointY;
  UINTN                  BitmapWidth;
  UINTN                  BitmapHeight;
  UINTN                  RenderWidth;
  UINTN                  RenderHeight;
  UINTN                  Index;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *ScaledBitmap;

  if ((GraphicsOutput == NULL) || (String == NULL) || (TextScale <= 1)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol (&gEfiHiiFontProtocolGuid, NULL, (VOID **)&HiiFont);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "%a: HII font protocol unavailable: %r\n", __func__, Status));
    return Status;
  }

  Status = gST->ConOut->QueryMode (gST->ConOut, gST->ConOut->Mode->Mode, &Columns, &Rows);
  if (EFI_ERROR (Status) || (Columns == 0) || (Rows == 0)) {
    Columns = PcdGet32 (PcdConOutColumn);
    Rows    = PcdGet32 (PcdConOutRow);
    if ((Columns == 0) || (Rows == 0)) {
      Columns = 80;
      Rows    = 25;
    }
  }

  BaseGlyphWidth  = EFI_GLYPH_WIDTH;
  BaseGlyphHeight = EFI_GLYPH_HEIGHT;
  PointX          = ((UINTN)GraphicsOutput->Mode->Info->HorizontalResolution - (Columns * BaseGlyphWidth)) / 2 + (Column * BaseGlyphWidth);
  PointY          = ((UINTN)GraphicsOutput->Mode->Info->VerticalResolution - (Rows * BaseGlyphHeight)) / 2 + (Row * BaseGlyphHeight);
  if (Row > 0) {
    PointY += (Row - 1) * BaseGlyphHeight * TextScale;
  }

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
  DEBUG ((
    DEBUG_INFO,
    "%a: \"%s\" cols=%u rows=%u point=(%u,%u) scale=%u status=%r\n",
    __func__,
    String,
    (UINT32)Columns,
    (UINT32)Rows,
    (UINT32)PointX,
    (UINT32)PointY,
    (UINT32)TextScale,
    Status
    ));
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

  ScaledBitmap = NULL;
  Status       = ScaleBitmap2x (Blt->Image.Bitmap, RenderWidth, RenderHeight, Blt->Width, &ScaledBitmap);
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

  Status = GraphicsOutput->Blt (
                             GraphicsOutput,
                             ScaledBlt->Image.Bitmap,
                             EfiBltBufferToVideo,
                             0,
                             0,
                             PointX,
                             PointY,
                             ScaledBlt->Width,
                             ScaledBlt->Height,
                             ScaledBlt->Width * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                             );
  DEBUG ((
    DEBUG_INFO,
    "%a: \"%s\" render=%ux%u scaled=%ux%u blt-status=%r\n",
    __func__,
    String,
    (UINT32)RenderWidth,
    (UINT32)RenderHeight,
    (UINT32)ScaledBlt->Width,
    (UINT32)ScaledBlt->Height,
    Status
    ));
  FreePool (ScaledBlt->Image.Bitmap);
  FreePool (ScaledBlt);

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
BOOLEAN
DisplayBootManagerPrompt (
  IN BOOLEAN  UseEscape
  )
{
  EFI_STATUS                    Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *GraphicsOutput;
  UINTN                         TextScale;

  Status = GetBootPromptGraphicsOutput (&GraphicsOutput);
  if (EFI_ERROR (Status) || !ShouldScaleBootPromptForHiDpi (GraphicsOutput)) {
    DEBUG ((DEBUG_INFO, "%a: HiDPI prompt disabled, status=%r\n", __func__, Status));
    return FALSE;
  }

  DEBUG ((
    DEBUG_INFO,
    "%a: using GOP mode=%u res=%ux%u pixel-format=%u\n",
    __func__,
    GraphicsOutput->Mode->Mode,
    GraphicsOutput->Mode->Info->HorizontalResolution,
    GraphicsOutput->Mode->Info->VerticalResolution,
    GraphicsOutput->Mode->Info->PixelFormat
    ));

  TextScale = 2U;
  if (UseEscape) {
    Status = DrawBootPromptLine (GraphicsOutput, L"Esc or Down to enter Boot Manager Menu.", 4, 1, TextScale);
  } else {
    Status = DrawBootPromptLine (GraphicsOutput, L"F2 or Down to enter Boot Manager Menu.", 4, 1, TextScale);
  }

  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  Status = DrawBootPromptLine (GraphicsOutput, L"ENTER to boot directly.", 4, 2, TextScale);
  return !EFI_ERROR (Status);
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
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Black;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  White;
  EDKII_PLATFORM_LOGO_PROTOCOL   *PlatformLogo;
  EFI_STATUS                     Status;

  Black.Blue = Black.Green = Black.Red = Black.Reserved = 0;
  White.Blue = White.Green = White.Red = White.Reserved = 0xFF;

  Status = gBS->LocateProtocol (&gEdkiiPlatformLogoProtocolGuid, NULL, (VOID **)&PlatformLogo);

  if (!EFI_ERROR (Status)) {
    gST->ConOut->ClearScreen (gST->ConOut);
    BootLogoEnableLogo ();
  }

  //
  // Ensure TCG2 physical presence variables are initialized (required for OPAL BlockSID UI).
  //
  Tcg2PhysicalPresenceLibProcessRequest (NULL);

  EfiBootManagerConnectAll ();
  EfiBootManagerRefreshAllBootOption ();

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

  //
  // Process TPM PPI request
  //
  Status=TcgPhysicalPresenceLibProcessRequest (); // Check for TPM1.2 First
  if (EFI_ERROR (Status)) {
	  Tcg2PhysicalPresenceLibProcessRequest (NULL); //Check for TPM2.0
  }

  //
  // Register UEFI Shell
  //
  PlatformRegisterFvBootOption (&gUefiShellFileGuid, L"UEFI Shell", LOAD_OPTION_ACTIVE);

  if (FixedPcdGetBool (PcdBootManagerEscape)) {
    if (!DisplayBootManagerPrompt (TRUE)) {
      Print (
        L"\n"
        L"    Esc or Down      to enter Boot Manager Menu.\n"
        L"    ENTER            to boot directly.\n"
        L"\n"
        );
    }
  } else {
    if (!DisplayBootManagerPrompt (FALSE)) {
      Print (
        L"\n"
        L"    F2 or Down      to enter Boot Manager Menu.\n"
        L"    ENTER           to boot directly.\n"
        L"\n"
        );
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
  /* Clear text from screen once timeout expires */
  if (TimeoutRemain == 0) {
    gST->ConOut->ClearScreen (gST->ConOut);
    BootLogoEnableLogo ();
  }
  return;
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
