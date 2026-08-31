/** @file
  Supported Intel client platform data for the boot-key boundary.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Register/Intel/Cpuid.h>
#include <Library/BaseLib.h>
#include <Library/BootKeyIntelClientPlatformLib.h>
#include <Library/DebugLib.h>

#define INTEL_CPUID_FAMILY_MODEL_MASK  0xfffffff0U
#define INTEL_CPUID_ALDER_LAKE_N       0x000b06e0U
#define INTEL_CPUID_RAPTOR_LAKE_U      0x000b06a0U
#define INTEL_CPUID_METEOR_LAKE        0x000a06a0U

STATIC CONST BOOT_KEY_INTEL_CLIENT_PLATFORM  mAlderRaptorLakePlatform = {
  0xfed91000U,
  SIZE_1MB,
  SIZE_1MB
};

STATIC CONST BOOT_KEY_INTEL_CLIENT_PLATFORM  mMeteorLakePlatform = {
  0xfc801000U,
  SIZE_1MB,
  SIZE_1MB
};

EFI_STATUS
EFIAPI
BootKeyGetIntelClientPlatform (
  OUT CONST BOOT_KEY_INTEL_CLIENT_PLATFORM  **Platform OPTIONAL
  )
{
  UINT32                                   Ebx;
  UINT32                                   Ecx;
  UINT32                                   Edx;
  CONST BOOT_KEY_INTEL_CLIENT_PLATFORM     *MatchedPlatform;
  UINT32                                   ProcessorFamilyModel;
  UINT32                                   ProcessorSignature;

  if (Platform != NULL) {
    *Platform = NULL;
  }

  AsmCpuid (CPUID_SIGNATURE, NULL, &Ebx, &Ecx, &Edx);
  AsmCpuid (CPUID_VERSION_INFO, &ProcessorSignature, NULL, NULL, NULL);
  ProcessorFamilyModel = ProcessorSignature & INTEL_CPUID_FAMILY_MODEL_MASK;

  if ((Ebx != CPUID_SIGNATURE_GENUINE_INTEL_EBX) ||
      (Edx != CPUID_SIGNATURE_GENUINE_INTEL_EDX) ||
      (Ecx != CPUID_SIGNATURE_GENUINE_INTEL_ECX))
  {
    MatchedPlatform = NULL;
  } else {
    switch (ProcessorFamilyModel) {
      case INTEL_CPUID_ALDER_LAKE_N:
      case INTEL_CPUID_RAPTOR_LAKE_U:
        MatchedPlatform = &mAlderRaptorLakePlatform;
        break;
      case INTEL_CPUID_METEOR_LAKE:
        MatchedPlatform = &mMeteorLakePlatform;
        break;
      default:
        MatchedPlatform = NULL;
        break;
    }
  }

  if (MatchedPlatform == NULL) {
    DEBUG ((
      DEBUG_ERROR,
      "Boot-key Intel client requires ADL-N, RPL-U or MTL: CPUID=0x%08x\n",
      ProcessorSignature
      ));
    return EFI_SECURITY_VIOLATION;
  }

  if (Platform != NULL) {
    *Platform = MatchedPlatform;
  }

  return EFI_SUCCESS;
}
