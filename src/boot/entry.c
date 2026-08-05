/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 stage entry point.
 */

#include <library/cdk2_platform_lib.h>
#include <cdk2/config.h>
#include "entry.h"
#include "module.h"
#include "services.h"
#include "symbols.h"

/*
 * Entry point for the native cdk2 stage.
 *
 * This is intentionally a small boundary. Platform policy is provided by the
 * registered native modules. Keep the bootloader parameter at this boundary so
 * the native handoff receives the original coreboot argument.
 */
EFI_STATUS
cdk2_native_run_modules(struct cdk2_native_context *context)
{
	UINTN module_table_start;
	UINTN module_table_end;
	UINTN module_table_size;

	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	module_table_start = (UINTN)__cdk2_modules_start;
	module_table_end = (UINTN)__cdk2_modules_end;
	if (module_table_end < module_table_start) {
		return EFI_COMPROMISED_DATA;
	}

	module_table_size = module_table_end - module_table_start;
	if (module_table_size == 0 || (module_table_start % sizeof(*__cdk2_modules_start)) != 0 ||
	    (module_table_size % sizeof(*__cdk2_modules_start)) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	return cdk2_native_run_module_table(context, __cdk2_modules_start,
					    module_table_size / sizeof(*__cdk2_modules_start));
}

EFI_STATUS
cdk2_native_run_module_table(struct cdk2_native_context *context,
			     const struct cdk2_native_module *modules, UINTN module_count)
{
	const struct cdk2_native_module *module;
	EFI_STATUS status;
	UINTN index;

	if (context == NULL || (modules == NULL && module_count != 0)) {
		return EFI_INVALID_PARAMETER;
	}

	for (index = 0; index < module_count; index++) {
		module = &modules[index];
		if (module->init == NULL) {
			return EFI_COMPROMISED_DATA;
		}

		status = module->init(context);
		if (EFI_ERROR(status)) {
			return status;
		}
	}

	return EFI_SUCCESS;
}

__section(".text.entry") __used EFI_STATUS cdk2_native_stage_entry(UINTN bootloader_parameter)
{
	struct cdk2_native_context context = {0};
	EFI_STATUS status;

	/*
	 * The platform handoff owns native-context construction from the bootloader
	 * handoff. The freestanding entry only forwards the original coreboot
	 * argument so the direct coreboot path has a single init boundary.
	 */
	status = cdk2_platform_initialize_native_context(&context, bootloader_parameter);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_run_modules(&context);
	if (EFI_ERROR(status)) {
		return status;
	}

	return cdk2_native_run_entry(&context);
}
