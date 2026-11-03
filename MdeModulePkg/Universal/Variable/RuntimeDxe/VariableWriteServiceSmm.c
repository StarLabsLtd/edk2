/** @file
  MM variable write-service readiness initialization.

  Copyright (c) 2010 - 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Variable.h"

/**
  Initializes variable write service for MM.

**/
EFI_STATUS
VariableWriteServiceInitializeSmm (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = VariableWriteServiceInitialize ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Variable write service initialization failed. Status = %r\n", Status));
    return Status;
  }

  //
  // Notify the variable wrapper driver the variable write service is ready
  //
  return VariableNotifySmmWriteReady ();
}
