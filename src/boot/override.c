/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 strong-hook test override.
 */

#include <library/cdk2_platform_lib.h>

EFI_STATUS
EFIAPI
cdk2_platform_initialize_native_context(struct cdk2_native_context *context,
					UINTN bootloader_parameter)
{
	(void)context;
	(void)bootloader_parameter;
	return EFI_UNSUPPORTED;
}

void EFIAPI cdk2_platform_late_init(void)
{
	/* A board-specific native stage can provide the strong definition here. */
}
