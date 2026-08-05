/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host checks for native module dispatch.
 */

#include "entry.h"
#include "module.h"

#include <stdio.h>

static UINTN m_first_calls;
static UINTN m_second_calls;
static UINTN m_fail_calls;

const struct cdk2_native_module __cdk2_modules_start[1] = {
	{"unused-start", NULL}
};
const struct cdk2_native_module __cdk2_modules_end[1] = {
	{"unused-end", NULL}
};

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 module test: %s\n", message);
		return 1;
	}

	return 0;
}

static EFI_STATUS EFIAPI test_first_module(struct cdk2_native_context *context)
{
	if (context == NULL || context->bootloader_parameter != 0) {
		return EFI_INVALID_PARAMETER;
	}

	m_first_calls++;
	context->bootloader_parameter = 1;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_second_module(struct cdk2_native_context *context)
{
	if (context == NULL || context->bootloader_parameter != 1) {
		return EFI_INVALID_PARAMETER;
	}

	m_second_calls++;
	context->bootloader_parameter = 2;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_fail_module(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_fail_calls++;
	return EFI_DEVICE_ERROR;
}

EFI_STATUS
EFIAPI
cdk2_native_initialize_stage_context(struct cdk2_native_context *context,
				     UINTN bootloader_parameter)
{
	(void)context;
	(void)bootloader_parameter;
	return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
cdk2_platform_initialize_native_context(struct cdk2_native_context *context,
					UINTN bootloader_parameter)
{
	(void)context;
	(void)bootloader_parameter;
	return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
cdk2_native_run_entry(struct cdk2_native_context *context)
{
	(void)context;
	return EFI_UNSUPPORTED;
}

int main(void)
{
	struct cdk2_native_context context;
	EFI_STATUS status;
	int failures;
	const struct cdk2_native_module ordered_modules[] = {
		{ "first", test_first_module },
		{ "second", test_second_module }
	};
	const struct cdk2_native_module null_init_module[] = {
		{ "null-init", NULL }
	};
	const struct cdk2_native_module failing_modules[] = {
		{ "fail", test_fail_module },
		{ "second", test_second_module }
	};

	failures = 0;

	context = (struct cdk2_native_context){0};
	status = cdk2_native_run_module_table(&context, ordered_modules,
					      ARRAY_SIZE(ordered_modules));
	failures += expect(status == EFI_SUCCESS, "ordered modules rejected");
	failures += expect(m_first_calls == 1, "first module did not run once");
	failures += expect(m_second_calls == 1, "second module did not run once");
	failures += expect(context.bootloader_parameter == 2, "modules ran out of order");

	status = cdk2_native_run_module_table(NULL, ordered_modules,
					      ARRAY_SIZE(ordered_modules));
	failures += expect(status == EFI_INVALID_PARAMETER, "NULL context accepted");

	status = cdk2_native_run_module_table(&context, NULL, 1);
	failures += expect(status == EFI_INVALID_PARAMETER, "NULL module table accepted");

	status = cdk2_native_run_module_table(&context, null_init_module,
					      ARRAY_SIZE(null_init_module));
	failures += expect(status == EFI_COMPROMISED_DATA, "NULL module init accepted");

	context = (struct cdk2_native_context){0};
	m_second_calls = 0;
	status = cdk2_native_run_module_table(&context, failing_modules,
					      ARRAY_SIZE(failing_modules));
	failures += expect(status == EFI_DEVICE_ERROR, "module failure was not returned");
	failures += expect(m_fail_calls == 1, "failing module did not run once");
	failures += expect(m_second_calls == 0, "dispatch continued after module failure");

	if (failures != 0) {
		return 1;
	}

	puts("cdk2 module test: PASS");
	return 0;
}
