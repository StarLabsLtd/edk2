/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_RESET_SYSTEM_H_
#define CDK2_RESET_SYSTEM_H_

#include <uefi.h>

typedef enum {
	cdk2_reset_cold,
	cdk2_reset_warm,
	cdk2_reset_shutdown,
	cdk2_reset_platform_specific
} CDK2_RESET_TYPE;

typedef void CDK2_MS_ABI cdk2_reset_function(CDK2_RESET_TYPE type,
					     EFI_STATUS status, UINTN data_size,
					     void *reset_data);
typedef cdk2_reset_function * cdk2_reset_fn;

struct cdk2_reset_notification_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_reset_register_function(
	struct cdk2_reset_notification_protocol *protocol, cdk2_reset_fn function);

struct cdk2_reset_notification_protocol {
	cdk2_reset_register_function *register_reset_notify;
	cdk2_reset_register_function *unregister_reset_notify;
};

#endif
