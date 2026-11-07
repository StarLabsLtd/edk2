/** @file
  Production GraphicsConsole exercised with the host framebuffer.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

// These normally live in separate DXE images. Keep their private globals distinct.
#define mCrLfString  TestGraphicsConsoleCrLfString
#include "../../../../MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsole.c"
#undef mCrLfString

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *
TestCreateConsole (
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  GRAPHICS_CONSOLE_DEV  *Private = AllocateCopyPool (sizeof (*Private), &mGraphicsConsoleDevTemplate);

  if (Private == NULL) {
    return NULL;
  }

  Private->ModeData = AllocateZeroPool (sizeof (*Private->ModeData));
  if (Private->ModeData == NULL) {
    FreePool (Private);
    return NULL;
  }

  Private->GraphicsOutput               = Gop;
  Private->SimpleTextOutput.Mode        = &Private->SimpleTextOutputMode;
  Private->SimpleTextOutputMode.MaxMode = 1;
  Private->ModeData->Columns            = 4;
  Private->ModeData->Rows               = 1;
  Private->ModeData->GopWidth           = Gop->Mode->Info->HorizontalResolution;
  Private->ModeData->GopHeight          = Gop->Mode->Info->VerticalResolution;
  Private->ModeData->GopModeNumber      = Gop->Mode->Mode;
  Private->ModeData->GlyphWidth         = EFI_GLYPH_WIDTH;
  Private->ModeData->GlyphHeight        = EFI_GLYPH_HEIGHT;
  Private->ModeData->TextScale          = 1;
  return &Private->SimpleTextOutput;
}

VOID
TestFreeConsole (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Console
  )
{
  GRAPHICS_CONSOLE_DEV  *Private = GRAPHICS_CONSOLE_CON_OUT_DEV_FROM_THIS (Console);

  if (Private->LineBuffer != NULL) {
    FreePool (Private->LineBuffer);
  }

  FreePool (Private->ModeData);
  FreePool (Private);
}

VOID
TestPublishConsoleMode (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Console
  )
{
  Console->Mode->Mode = 0;
}

EFI_STATUS
TestStartConsole (
  VOID
  )
{
  return GraphicsConsoleControllerDriverStart (&gGraphicsConsoleDriverBinding, (EFI_HANDLE)(UINTN)1, NULL);
}
