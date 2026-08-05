/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 platform module.
 */

#include "module.h"
static EFI_STATUS EFIAPI cdk2_native_platform_module_init(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	/*
	 * Late platform policy runs once at the transfer boundary. Keep this module
	 * as a registration and context-validation point only.
	 */
	return EFI_SUCCESS;
}

CDK2_NATIVE_REGISTER("platform", cdk2_native_platform_module_init);
