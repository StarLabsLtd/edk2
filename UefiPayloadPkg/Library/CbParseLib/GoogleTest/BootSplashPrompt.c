/** @file
  Exercise the private production prompt cleanup with mocked console services.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "../../PlatformBootManagerLib/PlatformBootManager.c"

VOID
TestClearBootPrompt (UINTN X, UINTN Y, UINTN Width, UINTN Height)
{
  mBootPrompt.X = X;
  mBootPrompt.Y = Y;
  mBootPrompt.Width = Width;
  mBootPrompt.Height = Height;
  mBootPromptTextShown = FALSE;
  ClearBootManagerPrompt ();
}
