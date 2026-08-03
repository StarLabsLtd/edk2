/** @file
  Linux EFI-application boot option helpers.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PlatformLinuxEfiBoot.h"

EFI_STATUS
PlatformLinuxEfiBootValidatePath (
  IN CONST CHAR16  *Path
  )
{
  UINTN    Index;
  BOOLEAN  PreviousWasSeparator;

  if ((Path == NULL) || (Path[0] == CHAR_NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Path[0] != L'\\') || (Path[1] == CHAR_NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  PreviousWasSeparator = TRUE;
  for (Index = 1; Path[Index] != CHAR_NULL; Index++) {
    if ((Path[Index] == L'/') || (Path[Index] == L':')) {
      return EFI_INVALID_PARAMETER;
    }

    if (Path[Index] == L'\\') {
      if (PreviousWasSeparator) {
        return EFI_INVALID_PARAMETER;
      }

      PreviousWasSeparator = TRUE;
      continue;
    }

    PreviousWasSeparator = FALSE;
  }

  if (PreviousWasSeparator) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
PlatformLinuxEfiBootValidateDescription (
  IN CONST CHAR16  *Description
  )
{
  if ((Description == NULL) || (Description[0] == CHAR_NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}
