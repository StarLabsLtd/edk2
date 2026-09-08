/** @file
  ACPI access to ordinary CFR preferences through the resident variable owner.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include <IndustryStandard/StarlabsCfr.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/MmServicesTableLib.h>
#include <Protocol/SmmVariable.h>

#define CFR_ATTRIBUTES  (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)

typedef struct {
  STARLABS_CFR_OPTION    Id;
  CONST CHAR16           *Name;
  UINT8                  Count;
  UINT32                 Values[5];
} CFR_OPTION;

// Values are the existing Merlin/CFR encodings, not percentages or booleans.
STATIC CONST CFR_OPTION  mOptions[] = {
  { CfrFnLock,             L"fn_lock_state",   2, { 0,    1    }
  },
  { CfrTrackpad,           L"trackpad_state",  2, { 0,    0x22 }
  },
  { CfrKeyboardBrightness, L"kbl_brightness",  4, { 0xdd, 0xcc, 0xbb, 0xaa}
  },
  { CfrKeyboardBacklight,  L"kbl_state",       2, { 0,    0xdd }
  },
  { CfrKeyboardTimeout,    L"kbl_timeout",     5, { 0,    1, 2, 3, 4}
  },
  { CfrFnCtrlSwap,         L"fn_ctrl_swap",    2, { 0,    1    }
  },
  { CfrMaxCharge,          L"max_charge",      3, { 0,    0xbb, 0xaa}
  },
  { CfrFanMode,            L"fan_mode",        4, { 0,    0xbb, 0xaa, 0xcc}
  },
  { CfrChargingSpeed,      L"charging_speed",  3, { 0,    1, 2 }
  },
  { CfrLidSwitch,          L"lid_switch",      3, { 0,    1, 2 }
  },
  { CfrPowerLed,           L"power_led",       3, { 0,    1, 2 }
  },
  { CfrChargeLed,          L"charge_led",      3, { 0,    1, 2 }
  },
  { CfrPowerOnAc,          L"power_on_ac",     2, { 0,    1    }
  },
  { CfrAutomaticStart,     L"automatic_start", 3, { 0,    1, 2 }
  }
};

STATIC EFI_GUID                   mCfrGuid = {
  0xceae4c1d, 0x335b, 0x4685, { 0xa4, 0xa0, 0xfc, 0x4a, 0x94, 0xee, 0xa0, 0x85 }
};
STATIC EFI_SMM_VARIABLE_PROTOCOL  *mVariable;
STATIC STARLABS_CFR_MAILBOX       *mMailbox;
STATIC UINT32                     mSupportedOptions;

STATIC
EFI_STATUS
AccessOption (
  IN OUT STARLABS_CFR_MAILBOX  *Request
  )
{
  CONST CFR_OPTION  *Option;
  UINTN             Index;
  UINTN             Size;
  UINT32            Value;
  UINT32            Attributes;
  EFI_STATUS        Status;

  if ((Request->Version != STARLABS_CFR_VERSION) || (Request->Reserved != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Request->Command == STARLABS_CFR_CAPS) {
    Request->Value = mSupportedOptions;
    return EFI_SUCCESS;
  }

  if ((Request->Command != STARLABS_CFR_GET) && (Request->Command != STARLABS_CFR_SET)) {
    return EFI_UNSUPPORTED;
  }

  if ((Request->Id >= 32) || ((mSupportedOptions & (1U << Request->Id)) == 0)) {
    return EFI_UNSUPPORTED;
  }

  Option = NULL;
  for (Index = 0; Index < ARRAY_SIZE (mOptions); Index++) {
    if (mOptions[Index].Id == Request->Id) {
      Option = &mOptions[Index];
      break;
    }
  }

  if (Option == NULL) {
    return EFI_UNSUPPORTED;
  }

  if (Request->Command == STARLABS_CFR_SET) {
    // Preserve the legacy "re-enabled" trackpad normalization.
    if ((Request->Id == CfrTrackpad) && (Request->Value == 0x11)) {
      Request->Value = 0;
    }

    for (Index = 0; Index < Option->Count; Index++) {
      if (Option->Values[Index] == Request->Value) {
        break;
      }
    }

    if (Index == Option->Count) {
      return EFI_INVALID_PARAMETER;
    }
  }

  Size   = sizeof (Value);
  Status = mVariable->SmmGetVariable ((CHAR16 *)Option->Name, &mCfrGuid, &Attributes, &Size, &Value);
  if (!EFI_ERROR (Status) && ((Size != sizeof (Value)) || (Attributes != CFR_ATTRIBUTES))) {
    return EFI_COMPROMISED_DATA;
  }

  if (Request->Command == STARLABS_CFR_GET) {
    if (!EFI_ERROR (Status)) {
      for (Index = 0; Index < Option->Count; Index++) {
        if (Option->Values[Index] == Value) {
          break;
        }
      }

      if (Index == Option->Count) {
        return EFI_COMPROMISED_DATA;
      }

      Request->Value = Value;
    }

    return Status;
  }

  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }

  if (!EFI_ERROR (Status) && (Value == Request->Value)) {
    return EFI_SUCCESS;
  }

  return mVariable->SmmSetVariable ((CHAR16 *)Option->Name, &mCfrGuid, CFR_ATTRIBUTES, sizeof (Request->Value), &Request->Value);
}

STATIC
EFI_STATUS
EFIAPI
HandleCfr (
  IN EFI_HANDLE  DispatchHandle,
  IN CONST VOID  *Context,
  IN OUT VOID    *CommBuffer,
  IN OUT UINTN   *CommBufferSize
  )
{
  STARLABS_CFR_MAILBOX  Request;
  EFI_STATUS            Status;

  if (IoRead8 (STARLABS_CFR_APM_PORT) != STARLABS_CFR_APM_COMMAND) {
    return EFI_SUCCESS;
  }

  // The address is fixed at initialization; never follow caller-owned pointers.
  CopyMem (&Request, mMailbox, sizeof (Request));
  if (Request.Status != STARLABS_CFR_PENDING) {
    return EFI_SUCCESS;
  }

  Status = AccessOption (&Request);
  switch (Status) {
    case EFI_SUCCESS:           Request.Status = STARLABS_CFR_SUCCESS;
      break;
    case EFI_INVALID_PARAMETER: Request.Status = STARLABS_CFR_INVALID;
      break;
    case EFI_NOT_FOUND:         Request.Status = STARLABS_CFR_NOT_FOUND;
      break;
    case EFI_UNSUPPORTED:       Request.Status = STARLABS_CFR_UNSUPPORTED;
      break;
    case EFI_WRITE_PROTECTED:
    case EFI_SECURITY_VIOLATION:
    case EFI_ACCESS_DENIED:     Request.Status = STARLABS_CFR_DENIED;
      break;
    default:                   Request.Status = STARLABS_CFR_ERROR;
      break;
  }

  mMailbox->Value = Request.Value;
  MemoryFence ();
  mMailbox->Status = Request.Status;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
StarlabsCfrMmInitialize (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HOB_GUID_TYPE          *Hob;
  PAYLOAD_MM_INTERFACE_INFO  *Info;
  EFI_HANDLE                 DispatchHandle;
  EFI_STATUS                 Status;

  Hob = GetFirstGuidHob (&gPayloadMmInterfaceInfoGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*Info))) {
    return EFI_NOT_FOUND;
  }

  Info = GET_GUID_HOB_DATA (Hob);
  if ((Info->Revision != 1) || (Info->CfrMailbox == 0) ||
      (Info->CfrMailboxSize != sizeof (*mMailbox)) || (Info->CfrSupportedOptions == 0) ||
      ((Info->CfrSupportedOptions & ~STARLABS_CFR_OPTION_MASK) != 0))
  {
    return EFI_UNSUPPORTED;
  }

  Status = gMmst->MmLocateProtocol (&gEfiSmmVariableProtocolGuid, NULL, (VOID **)&mVariable);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mMailbox          = (VOID *)(UINTN)Info->CfrMailbox;
  mSupportedOptions = Info->CfrSupportedOptions;
  return gMmst->MmiHandlerRegister (HandleCfr, NULL, &DispatchHandle);
}
