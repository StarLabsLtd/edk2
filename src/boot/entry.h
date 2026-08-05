/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 stage entry contract.
 */

#ifndef CDK2_NATIVE_ENTRY_H_
#define CDK2_NATIVE_ENTRY_H_

#include "context.h"

/*
 * Dispatch the registered native modules using an initialized context.
 *
 * Service ownership stays with the caller so the native handoff can provide
 * platform-specific callbacks before module dispatch.
 *
 * @param[in,out] context  Initialized native service context.
 *
 * @retval EFI_SUCCESS            All registered modules completed.
 * @retval EFI_INVALID_PARAMETER  context is NULL.
 * @retval EFI_COMPROMISED_DATA   The linker-collected module table is invalid.
 * @retval Other                  A module returned an error.
 */
EFI_STATUS
cdk2_native_run_modules(struct cdk2_native_context *context);

/*
 * Native cdk2 stage entry point.
 *
 * @param[in] bootloader_parameter coreboot bootloader parameter address.
 *
 * @retval EFI_SUCCESS            All registered modules completed.
 * @retval Other                  Stage initialization or module failure.
 */
EFI_STATUS
cdk2_native_stage_entry(UINTN bootloader_parameter);

#endif
