/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TCG2_ENTRY_H_
#define CDK2_TCG2_ENTRY_H_

#include <cdk2/tcg2_service.h>

typedef EFI_STATUS cdk2_tcg2_entry_action_fn(void *context);
typedef EFI_STATUS cdk2_tcg2_entry_create_fn(void *context, void **event);
typedef EFI_STATUS cdk2_tcg2_entry_notify_fn(void *context, void *event);
typedef EFI_STATUS cdk2_tcg2_entry_close_fn(void *context, void *event);
typedef EFI_STATUS cdk2_tcg2_entry_install_fn(void *context,
	cdk2_const_guid_ptr guid, void *interface);
typedef void cdk2_tcg2_entry_release_fn(void *context,
	struct cdk2_tcg2_service *service);

struct cdk2_tcg2_entry_ops {
	cdk2_tcg2_entry_action_fn *register_security;
	cdk2_tcg2_entry_action_fn *unregister_security;
	cdk2_tcg2_entry_create_fn *create_variable_event;
	cdk2_tcg2_entry_notify_fn *register_variable_notify;
	cdk2_tcg2_entry_create_fn *create_exit_event;
	cdk2_tcg2_entry_close_fn *close_event;
	cdk2_tcg2_entry_install_fn *install_config;
	cdk2_tcg2_entry_install_fn *install_protocol;
	cdk2_tcg2_entry_release_fn *release_service;
};

EFI_STATUS cdk2_tcg2_entry_publish(struct cdk2_tcg2_service *service,
	void *context, const struct cdk2_tcg2_entry_ops *ops);

#endif
