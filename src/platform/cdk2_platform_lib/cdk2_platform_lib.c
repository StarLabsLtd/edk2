/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Default cdk2 platform extension points.
 */

#include <library/cdk2_platform_lib.h>

__weak
EFI_STATUS
EFIAPI
cdk2_platform_initialize_native_context(struct cdk2_native_context *context,
					UINTN bootloader_parameter)
{
	(void)context;
	(void)bootloader_parameter;
	return EFI_UNSUPPORTED;
}

__weak
void EFIAPI cdk2_platform_late_init(void)
{
	/* Board-specific payloads may override this hook. */
}
