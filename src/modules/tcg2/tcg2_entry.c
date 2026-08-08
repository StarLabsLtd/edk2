/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_entry.h>

EFI_STATUS cdk2_tcg2_entry_publish(struct cdk2_tcg2_service *service,
	void *context, const struct cdk2_tcg2_entry_ops *ops)
{
	void *variable_event = NULL;
	void *exit_event = NULL;
	EFI_STATUS status;

	if (service == NULL || ops == NULL || ops->register_security == NULL ||
	    ops->unregister_security == NULL || ops->create_variable_event == NULL ||
	    ops->register_variable_notify == NULL || ops->create_exit_event == NULL ||
	    ops->close_event == NULL || ops->install_config == NULL ||
	    ops->install_protocol == NULL || ops->release_service == NULL)
		return EFI_INVALID_PARAMETER;
	status = ops->register_security(context);
	if (EFI_ERROR(status))
		goto release_service;
	status = ops->create_variable_event(context, &variable_event);
	if (EFI_ERROR(status))
		goto unregister_security;
	status = ops->register_variable_notify(context, variable_event);
	if (EFI_ERROR(status))
		goto close_variable_event;
	status = ops->create_exit_event(context, &exit_event);
	if (EFI_ERROR(status))
		goto close_variable_event;
	status = ops->install_config(context, &efi_tcg2_final_events_table_guid,
		service->final_table);
	if (EFI_ERROR(status))
		goto close_exit_event;
	status = ops->install_protocol(context, &efi_tcg2_protocol_guid,
		&service->protocol);
	if (!EFI_ERROR(status))
		return EFI_SUCCESS;
	ops->install_config(context, &efi_tcg2_final_events_table_guid, NULL);
close_exit_event:
	ops->close_event(context, exit_event);
close_variable_event:
	ops->close_event(context, variable_event);
unregister_security:
	ops->unregister_security(context);
release_service:
	ops->release_service(context, service);
	return status;
}
