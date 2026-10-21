/** @file
  Variable write-service initialization.

  Copyright (c) 2006 - 2020, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2015-2018 Hewlett Packard Enterprise Development LP<BR>
  Copyright (c) Microsoft Corporation.<BR>
  Copyright (c) 2022, ARM Limited. All rights reserved.<BR>
  Copyright (C) 2026 Advanced Micro Devices, Inc. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "Variable.h"
#include "VariableParsing.h"

VARIABLE_ENTRY_PROPERTY  mVariableEntryProperty[] = {
  {
    &gEdkiiVarErrorFlagGuid,
    VAR_ERROR_FLAG_NAME,
    {
      VAR_CHECK_VARIABLE_PROPERTY_REVISION,
      VAR_CHECK_VARIABLE_PROPERTY_READ_ONLY,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (VAR_ERROR_FLAG),
      sizeof (VAR_ERROR_FLAG)
    }
  },
};

extern AUTH_VAR_LIB_CONTEXT_IN  mAuthContextIn;

/**
  Initializes variable write service.

  @retval EFI_SUCCESS          Function successfully executed.
  @retval Others               Fail to initialize the variable service.

**/
EFI_STATUS
VariableWriteServiceInitialize (
  VOID
  )
{
  EFI_STATUS               Status;
  UINTN                    Index;
  UINT8                    Data;
  VARIABLE_ENTRY_PROPERTY  *VariableEntry;

  AcquireLockOnlyAtBootTime (&mVariableModuleGlobal->VariableGlobal.VariableServicesLock);

  //
  // Check if the free area is really free.
  //
  for (Index = mVariableModuleGlobal->NonVolatileLastVariableOffset; Index < mNvVariableCache->Size; Index++) {
    Data = ((UINT8 *)mNvVariableCache)[Index];
    if (Data != 0xff) {
      //
      // There must be something wrong in variable store, do reclaim operation.
      //
      Status = Reclaim (
                 mVariableModuleGlobal->VariableGlobal.NonVolatileVariableBase,
                 &mVariableModuleGlobal->NonVolatileLastVariableOffset,
                 FALSE,
                 NULL,
                 NULL,
                 0
                 );
      if (EFI_ERROR (Status)) {
        ReleaseLockOnlyAtBootTime (&mVariableModuleGlobal->VariableGlobal.VariableServicesLock);
        return Status;
      }

      break;
    }
  }

  FlushHobVariableToFlash (NULL, NULL);

  Status = EFI_SUCCESS;
  ZeroMem (&mAuthContextOut, sizeof (mAuthContextOut));
  if (mVariableModuleGlobal->VariableGlobal.AuthFormat) {
    //
    // Authenticated variable initialize.
    //
    mAuthContextIn.StructSize          = sizeof (AUTH_VAR_LIB_CONTEXT_IN);
    mAuthContextIn.MaxAuthVariableSize =  mVariableModuleGlobal->MaxAuthVariableSize -
                                         GetVariableHeaderSize (mVariableModuleGlobal->VariableGlobal.AuthFormat);
    Status = AuthVariableLibInitialize (&mAuthContextIn, &mAuthContextOut);
    if (!EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "Variable driver will work with auth variable support!\n"));
      mVariableModuleGlobal->VariableGlobal.AuthSupport = TRUE;
      if (mAuthContextOut.AuthVarEntry != NULL) {
        for (Index = 0; Index < mAuthContextOut.AuthVarEntryCount; Index++) {
          VariableEntry = &mAuthContextOut.AuthVarEntry[Index];
          Status        = VarCheckLibVariablePropertySet (
                            VariableEntry->Name,
                            VariableEntry->Guid,
                            &VariableEntry->VariableProperty
                            );
          if (EFI_ERROR (Status)) {
            ReleaseLockOnlyAtBootTime (&mVariableModuleGlobal->VariableGlobal.VariableServicesLock);
            return Status;
          }
        }
      }
    } else if (Status == EFI_UNSUPPORTED) {
      DEBUG ((DEBUG_INFO, "NOTICE - AuthVariableLibInitialize() returns %r!\n", Status));
      DEBUG ((DEBUG_INFO, "Variable driver will continue to work without auth variable support!\n"));
      mVariableModuleGlobal->VariableGlobal.AuthSupport = FALSE;
      Status                                            = EFI_SUCCESS;
    }
  }

  if (!EFI_ERROR (Status)) {
    for (Index = 0; Index < ARRAY_SIZE (mVariableEntryProperty); Index++) {
      VariableEntry = &mVariableEntryProperty[Index];
      Status        = VarCheckLibVariablePropertySet (VariableEntry->Name, VariableEntry->Guid, &VariableEntry->VariableProperty);
      if (EFI_ERROR (Status)) {
        ReleaseLockOnlyAtBootTime (&mVariableModuleGlobal->VariableGlobal.VariableServicesLock);
        return Status;
      }
    }
  }

  ReleaseLockOnlyAtBootTime (&mVariableModuleGlobal->VariableGlobal.VariableServicesLock);

  //
  // Initialize MOR Lock variable.
  //
  MorLockInit ();

  return Status;
}
