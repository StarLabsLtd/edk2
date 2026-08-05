/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * cdk2 platform extension points.
 */

#ifndef CDK2_PLATFORM_LIB_H_
#define CDK2_PLATFORM_LIB_H_

#include <uefi.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cdk2_native_context;

/*
 * Register the handoff operations used by an initialized freestanding native
 * stage.
 *
 * Implementations must not clear or reinitialize the common native service
 * table owned by cdk2_native_stage_entry().
 */
EFI_STATUS
EFIAPI
cdk2_platform_initialize_native_context(struct cdk2_native_context *context,
					UINTN bootloader_parameter);

/** Run immediately before the payload hands control to DXE. */
void EFIAPI cdk2_platform_late_init(void);

#ifdef __cplusplus
}
#endif

#endif
