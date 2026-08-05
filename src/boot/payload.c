/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 payload entry flow.
 */

#include <library/cdk2_native_services.h>

EFI_STATUS
EFIAPI
cdk2_native_run_entry(struct cdk2_native_context *context)
{
	EFI_STATUS status;

	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_native_validate_ops(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_prepare_entry(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	return cdk2_native_transfer(context);
}

EFI_STATUS
EFIAPI
cdk2_native_payload_entry(UINTN bootloader_parameter,
			  cdk2_native_initialize_context_fn_t initialize_context)
{
	struct cdk2_native_context context = {0};
	EFI_STATUS status;

	if (initialize_context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = initialize_context(&context, bootloader_parameter);
	if (EFI_ERROR(status)) {
		return status;
	}

	return cdk2_native_run_entry(&context);
}
