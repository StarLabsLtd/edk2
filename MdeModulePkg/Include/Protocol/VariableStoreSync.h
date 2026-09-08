/** @file
  Cooperate with a firmware writer outside the runtime variable driver.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef EDKII_VARIABLE_STORE_SYNC_H_
#define EDKII_VARIABLE_STORE_SYNC_H_

#include <Uefi.h>

#define EDKII_VARIABLE_STORE_SYNC_PROTOCOL_GUID \
  { 0xd2851463, 0x7631, 0x4512, { 0xbc, 0x30, 0x3e, 0x38, 0x99, 0x27, 0x6f, 0xbf } }

/**
  Exclude external writers for one runtime variable operation.

  Generation changes after an external write, including a partially failed one.
  Writes made through the associated FVB do not change Generation. This is
  cooperative serialization, not an authorization boundary. Never wait for an
  interrupted owner: return EFI_NOT_READY if an operation is already active.

  @param[out] Generation  External-write generation while exclusion is held.
  @retval EFI_SUCCESS    Exclusion acquired. The caller must call End once.
  @retval Others         Exclusion was not acquired.
**/
typedef
EFI_STATUS
(EFIAPI *EDKII_VARIABLE_STORE_BEGIN)(
  OUT UINT64  *Generation
  );

/**
  Release exclusion acquired by a successful Begin.

  @retval EFI_SUCCESS  Exclusion released.
  @retval Others       The caller must not continue using the store.
**/
typedef
EFI_STATUS
(EFIAPI *EDKII_VARIABLE_STORE_END)(
  VOID
  );

//
// Installed on the variable store's FVB handle. The interface and its callbacks
// are runtime-resident; the producer converts the callbacks on address change.
//
typedef struct {
  EDKII_VARIABLE_STORE_BEGIN    Begin;
  EDKII_VARIABLE_STORE_END      End;
} EDKII_VARIABLE_STORE_SYNC_PROTOCOL;

extern EFI_GUID  gEdkiiVariableStoreSyncProtocolGuid;

#endif
