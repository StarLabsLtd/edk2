/** @file
  Persistent FMP controller-state format, shared with protected update owners.
  Copyright (c) 2016, Microsoft Corporation. All rights reserved.<BR>
  Copyright (c) 2018 - 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once
#include <Uefi.h>
#define VARNAME_LSV       L"FmpLsv"
#define VARNAME_FMPSTATE  L"FmpState"
///
/// FMP Controller State structure that is used to store the state of
/// a controller in one combined UEFI Variable.
///
typedef struct {
  BOOLEAN    VersionValid;
  BOOLEAN    LsvValid;
  BOOLEAN    LastAttemptStatusValid;
  BOOLEAN    LastAttemptVersionValid;
  UINT32     Version;
  UINT32     Lsv;
  UINT32     LastAttemptStatus;
  UINT32     LastAttemptVersion;
} FMP_CONTROLLER_STATE;
