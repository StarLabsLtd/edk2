/** @file

  Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#pragma once

#include <Library/UefiBootManagerLib.h>

//
// Platform Boot Manager Protocol GUID value
//
#define EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL_GUID \
    { \
      0xaa17add4, 0x756c, 0x460d, { 0x94, 0xb8, 0x43, 0x88, 0xd7, 0xfb, 0x3e, 0x59 } \
    }

//
// Protocol interface structure
//
typedef struct _EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL;

//
// Revision The revision to which the protocol interface adheres.
//          All future revisions must be backwards compatible.
//          If a future version is not back wards compatible it is not the same GUID.
//
#define EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL_REVISION   0x00000001
#define EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL_REVISION2  0x00000002

//
// Function Prototypes
//

/*
  This function allows platform to refresh all boot options specific to the platform. Within
  this function, platform can make modifications to the auto enumerated platform boot options
  as well as NV boot options.

  @param[in const] BootOptions             An array of auto enumerated platform boot options.
                                           This array will be freed by caller upon successful
                                           exit of this function and output array would be used.

  @param[in const] BootOptionsCount        The number of elements in BootOptions.

  @param[out]      UpdatedBootOptions      An array of boot options that have been customized
                                           for the platform on top of input boot options. This
                                           array would be allocated by REFRESH_ALL_BOOT_OPTIONS
                                           and would be freed by caller after consuming it.

  @param[out]      UpdatedBootOptionsCount The number of elements in UpdatedBootOptions.


  @retval EFI_SUCCESS                      Platform refresh to input BootOptions and
                                           BootCount have been done.

  @retval EFI_OUT_OF_RESOURCES             Memory allocation failed.

  @retval EFI_INVALID_PARAMETER            Input is not correct.

  @retval EFI_UNSUPPORTED                  Platform specific overrides are not supported.
*/
typedef
EFI_STATUS
(EFIAPI *PLATFORM_BOOT_MANAGER_REFRESH_ALL_BOOT_OPTIONS)(
  IN  CONST EFI_BOOT_MANAGER_LOAD_OPTION *BootOptions,
  IN  CONST UINTN                        BootOptionsCount,
  OUT       EFI_BOOT_MANAGER_LOAD_OPTION **UpdatedBootOptions,
  OUT       UINTN                        *UpdatedBootOptionsCount
  );

/*
  This function allows the platform to enforce policy before BDS launches
  non-recovery executable boot paths. The implementation must not consume or
  mutate boot wait timeout state.

  @retval EFI_SUCCESS            Platform policy allows boot path execution.
  @retval EFI_SECURITY_VIOLATION Platform policy blocks boot path execution.
  @retval Other                  Platform policy blocks boot path execution.
*/
typedef
EFI_STATUS
(EFIAPI *PLATFORM_BOOT_MANAGER_BEFORE_BOOT)(
  VOID
  );

struct _EDKII_PLATFORM_BOOT_MANAGER_PROTOCOL {
  UINT64                                            Revision;
  PLATFORM_BOOT_MANAGER_REFRESH_ALL_BOOT_OPTIONS    RefreshAllBootOptions;
  PLATFORM_BOOT_MANAGER_BEFORE_BOOT                 BeforeBoot;
};

extern EFI_GUID  gEdkiiPlatformBootManagerProtocolGuid;
