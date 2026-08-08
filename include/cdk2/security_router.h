/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SECURITY_ROUTER_H_
#define CDK2_SECURITY_ROUTER_H_

#include <uefi.h>

#define CDK2_SECURITY_ROUTER_MAX_HANDLERS 8U

typedef EFI_STATUS CDK2_MS_ABI cdk2_security2_handler_fn(
	const void *file, const void *file_buffer, UINTN file_size,
	BOOLEAN boot_policy, void *context);
typedef EFI_STATUS CDK2_MS_ABI cdk2_security_router_register_fn(
	cdk2_security2_handler_fn *handler, void *context);

struct cdk2_security_router {
	cdk2_security_router_register_fn *register_handler;
	cdk2_security_router_register_fn *unregister_handler;
};

extern const EFI_GUID cdk2_security_router_guid;

#endif
