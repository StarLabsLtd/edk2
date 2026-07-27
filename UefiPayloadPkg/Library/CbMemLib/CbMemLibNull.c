/** @file
  Null CBMEM library for non-coreboot payload builds.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/CbMemLib.h>

RETURN_STATUS
EFIAPI
CbMemFind (
  IN  UINT32  Id,
  OUT VOID    **Address,
  OUT UINT32  *Size
  )
{
  (VOID)Id;
  if (Address != NULL) {
    *Address = NULL;
  }
  if (Size != NULL) {
    *Size = 0;
  }
  return RETURN_NOT_FOUND;
}

RETURN_STATUS
EFIAPI
CbMemPublishTableHob (
  VOID
  )
{
  return RETURN_NOT_FOUND;
}

RETURN_STATUS
EFIAPI
CbMemTimestampAdd (
  IN UINT32  Id
  )
{
  (VOID)Id;
  return RETURN_NOT_FOUND;
}

RETURN_STATUS
EFIAPI
CbMemLogSummary (
  VOID
  )
{
  return RETURN_NOT_FOUND;
}
