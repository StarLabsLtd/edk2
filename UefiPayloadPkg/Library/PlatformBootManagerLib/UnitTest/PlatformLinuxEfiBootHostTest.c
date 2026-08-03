/** @file
  Host checks for Linux EFI-application boot option validation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "../PlatformLinuxEfiBoot.h"

#include <stdio.h>

STATIC
int
ExpectStatus (
  IN EFI_STATUS  Actual,
  IN EFI_STATUS  Expected,
  IN CONST char  *Message
  )
{
  if (Actual != Expected) {
    fprintf (
      stderr,
      "platform Linux EFI boot test: %s: got 0x%llx expected 0x%llx\n",
      Message,
      (unsigned long long)Actual,
      (unsigned long long)Expected
      );
    return 1;
  }

  return 0;
}

int
main (
  void
  )
{
  CHAR16  PathWithBackslashes[] = L"\\EFI\\Linux\\bzImage.efi";
  CHAR16  PathCopy[]            = L"\\EFI\\Linux\\bzImage.efi";
  int     Failures;
  UINTN   Index;

  Failures  = 0;
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (PathWithBackslashes),
                EFI_SUCCESS,
                "absolute backslash path"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (L"\\EFI\\Linux\\kernel with spaces.efi"),
                EFI_SUCCESS,
                "absolute path with spaces"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (NULL),
                EFI_INVALID_PARAMETER,
                "NULL path rejected"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (L""),
                EFI_INVALID_PARAMETER,
                "empty path rejected"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (L"EFI\\Linux\\bzImage.efi"),
                EFI_INVALID_PARAMETER,
                "relative path rejected"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (L"\\EFI/Linux/bzImage.efi"),
                EFI_INVALID_PARAMETER,
                "forward slash path rejected"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (L"FS0:\\EFI\\Linux\\bzImage.efi"),
                EFI_INVALID_PARAMETER,
                "filesystem prefix rejected"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (L"\\EFI\\\\Linux\\bzImage.efi"),
                EFI_INVALID_PARAMETER,
                "duplicate separator rejected"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidatePath (L"\\EFI\\Linux\\"),
                EFI_INVALID_PARAMETER,
                "trailing separator rejected"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidateDescription (L"Q35 Linux EFI"),
                EFI_SUCCESS,
                "description accepted"
                );
  Failures += ExpectStatus (
                PlatformLinuxEfiBootValidateDescription (L""),
                EFI_INVALID_PARAMETER,
                "empty description rejected"
                );

  for (Index = 0; PathWithBackslashes[Index] != CHAR_NULL; Index++) {
    if (PathWithBackslashes[Index] != PathCopy[Index]) {
      fprintf (stderr, "platform Linux EFI boot test: path mutated\n");
      Failures++;
      break;
    }
  }

  return (Failures == 0) ? 0 : 1;
}
