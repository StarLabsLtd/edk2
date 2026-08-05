/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 module registration contract.
 */

#ifndef CDK2_NATIVE_MODULE_H_
#define CDK2_NATIVE_MODULE_H_

#include "context.h"
#include <library/cdk2_platform_lib.h>

typedef EFI_STATUS cdk2_native_module_init_fn_t(struct cdk2_native_context *context);

struct cdk2_native_module {
	const CHAR8 *name;

	cdk2_native_module_init_fn_t *init;
};

EFI_STATUS
cdk2_native_run_module_table(struct cdk2_native_context *context,
			     const struct cdk2_native_module *modules, UINTN module_count);

#if defined(__GNUC__)
#define CDK2_NATIVE_REGISTER(name, function)                                            \
	static const struct cdk2_native_module cdk2_module_##function __used __section( \
		".cdk2.modules") = {name, function}
#else
#define CDK2_NATIVE_REGISTER(name, function) \
	static const struct cdk2_native_module cdk2_module_##function = {name, function}
#endif

#endif
