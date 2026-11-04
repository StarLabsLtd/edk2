/** @file
  Exercise the production private readiness/lifecycle query on IA32.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <assert.h>
#include <stdio.h>
#undef NULL
#include "CorebootMmBridge.c"

EFI_GUID gEfiSmmVariableProtocolGuid = { .Data1 = 1 };
EFI_GUID gSmmVariableWriteGuid = { .Data1 = 2 };
EFI_GUID gEfiEventReadyToBootGuid = { .Data1 = 3 };
EFI_GUID gEfiEventExitBootServicesGuid = { .Data1 = 4 };
STATIC EFI_MM_SYSTEM_TABLE mTable;
EFI_MM_SYSTEM_TABLE *gMmst = &mTable;
STATIC BOOLEAN mReadyToBoot;
STATIC BOOLEAN mExited;
STATIC BOOLEAN mReady = TRUE;
STATIC BOOLEAN mLocateError;

STATIC EFI_STATUS EFIAPI
Locate (
  IN EFI_GUID *Guid,
  IN VOID *Registration,
  OUT VOID **Interface
  )
{
  (void)Registration;
  *Interface = NULL;
  if (Guid == &gEfiEventReadyToBootGuid) {
    if (mLocateError) {
      return EFI_DEVICE_ERROR;
    }
    return mReadyToBoot ? EFI_SUCCESS : EFI_NOT_FOUND;
  }
  if (Guid == &gEfiEventExitBootServicesGuid) {
    return mExited ? EFI_SUCCESS : EFI_NOT_FOUND;
  }
  return mReady ? EFI_SUCCESS : EFI_NOT_FOUND;
}

int
main (void)
{
  UINT8 Query = 0;
  UINTN Size = sizeof (Query);

  mTable.MmLocateProtocol = Locate;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_SUCCESS);
  Query = 1;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_SUCCESS);
  mReadyToBoot = TRUE;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_SUCCESS && Query == 0);
  Query = 0;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_SUCCESS);
  Query = 1;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_SUCCESS && Query == 0);
  Query = 1;
  mReadyToBoot = FALSE;
  mExited = TRUE;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_SUCCESS && Query == 0);
  Query = 1;
  mExited = FALSE;
  mLocateError = TRUE;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_SUCCESS && Query == 0);
  Query = 1;
  mLocateError = FALSE;
  mReady = FALSE;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_NOT_FOUND);
  Query = 2;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_INVALID_PARAMETER);
  Query = 1;
  Size = 0;
  assert (VariableServiceReady (NULL, NULL, &Query, &Size) == EFI_INVALID_PARAMETER);
  puts ("Private MM boot access: readiness, handoff closure, errors and framing passed");
  return 0;
}
