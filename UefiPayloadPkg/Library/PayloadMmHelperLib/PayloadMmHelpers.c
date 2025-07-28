/** @file
  This library provides some payload MM helper functions.

  Copyright (c) 2025, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/CpuLib.h>
#include <Library/DebugLib.h>
#include <Library/PayloadMmHelperLib.h>

#include <Guid/PayloadMmInterfaceInfoGuid.h>

#include <Register/Intel/Cpuid.h>

/**
  The routine returns TRUE when CPU supports it (CPUID[7,0].ECX.BIT[16] is set) and
  the max physical address bits is bigger than 48. Because 4-level paging can support
  to address physical address up to 2^48 - 1, there is no need to enable 5-level paging
  with max physical address bits <= 48.

  @retval TRUE  5-level paging enabling is needed.
  @retval FALSE 5-level paging enabling is not needed.
**/
BOOLEAN
Is5LevelPagingNeeded (
  VOID
  )
{
  CPUID_VIR_PHY_ADDRESS_SIZE_EAX               VirPhyAddressSize;
  CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_ECX  ExtFeatureEcx;
  UINT32                                       MaxExtendedFunctionId;

  AsmCpuid (CPUID_EXTENDED_FUNCTION, &MaxExtendedFunctionId, NULL, NULL, NULL);
  if (MaxExtendedFunctionId >= CPUID_VIR_PHY_ADDRESS_SIZE) {
    AsmCpuid (CPUID_VIR_PHY_ADDRESS_SIZE, &VirPhyAddressSize.Uint32, NULL, NULL, NULL);
  } else {
    VirPhyAddressSize.Bits.PhysicalAddressBits = 36;
  }

  AsmCpuidEx (
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS,
    CPUID_STRUCTURED_EXTENDED_FEATURE_FLAGS_SUB_LEAF_INFO,
    NULL,
    NULL,
    &ExtFeatureEcx.Uint32,
    NULL
    );
  DEBUG ((
    DEBUG_INFO,
    "PhysicalAddressBits = %d, 5LPageTable = %d.\n",
    VirPhyAddressSize.Bits.PhysicalAddressBits,
    ExtFeatureEcx.Bits.FiveLevelPage
    ));

  if ((VirPhyAddressSize.Bits.PhysicalAddressBits > 4 * 9 + 12) &&
      (ExtFeatureEcx.Bits.FiveLevelPage == 1))
  {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**
  Fills control-flow fields used by payload MM assembly code.

**/
VOID
EFIAPI
CheckFeatureSupported (
  IN PAYLOAD_MM_EDK2_PRIVATE_DATA  *PrivateData
  )
{
  UINT32                      RegEax;
  CPUID_EXTENDED_CPU_SIG_EDX  ExtendedRegEdx;

  PrivateData->Intel5LevelPagingNeeded = Is5LevelPagingNeeded ();

  //
  // Check XD supported or not.
  //
  PrivateData->XdSupported = TRUE;

  RegEax                = 0;
  AsmCpuid (CPUID_EXTENDED_FUNCTION, &RegEax, NULL, NULL, NULL);
  if (RegEax <= CPUID_EXTENDED_FUNCTION) {
    //
    // Extended CPUID functions are not supported on this processor.
    //
    PrivateData->XdSupported = FALSE;
  }

  ExtendedRegEdx.Uint32 = 0;
  AsmCpuid (CPUID_EXTENDED_CPU_SIG, NULL, NULL, NULL, &ExtendedRegEdx.Uint32);
  if (ExtendedRegEdx.Bits.NX == 0) {
    //
    // Execute Disable Bit feature is not supported on this processor.
    //
    PrivateData->XdSupported = FALSE;
  }

  //
  // AMD processors do not support MSR_IA32_MISC_ENABLE.
  //
  PrivateData->MsrIa32MiscEnableSupported = !StandardSignatureIsAuthenticAMD ();
}
