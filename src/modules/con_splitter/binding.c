/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_splitter_binding.h>

static struct cdk2_split_binding_instance *find_instance(
	struct cdk2_split_binding *binding, void *controller)
{
	UINTN index;

	for (index = 0; index < CDK2_CON_SPLITTER_MAX_INPUTS; index++)
		if (binding->instances[index].active &&
		    binding->instances[index].controller == controller)
			return &binding->instances[index];
	return NULL;
}

EFI_STATUS cdk2_split_binding_supported(struct cdk2_split_binding *binding,
	void *controller)
{
	void *interface;
	EFI_STATUS status, close_status;

	if (binding == NULL || controller == NULL || binding->ops == NULL ||
	    binding->ops->open == NULL || binding->ops->close == NULL ||
	    binding->protocol == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_instance(binding, controller) != NULL)
		return CDK2_CON_SPLITTER_ALREADY_STARTED;
	status = binding->ops->open(binding->context, controller,
		binding->protocol, CDK2_CON_SPLITTER_OPEN_BY_DRIVER, &interface);
	if (EFI_ERROR(status))
		return status;
	close_status = binding->ops->close(binding->context, controller,
		binding->protocol);
	return EFI_ERROR(close_status) ? close_status : EFI_SUCCESS;
}

EFI_STATUS cdk2_split_binding_start(struct cdk2_split_binding *binding,
	void *controller)
{
	struct cdk2_split_binding_instance *instance = NULL;
	EFI_STATUS status;
	UINTN index;

	if (binding == NULL || controller == NULL || binding->ops == NULL ||
	    binding->ops->open == NULL || binding->ops->close == NULL ||
	    binding->ops->admit == NULL || binding->protocol == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_instance(binding, controller) != NULL)
		return CDK2_CON_SPLITTER_ALREADY_STARTED;
	for (index = 0; index < CDK2_CON_SPLITTER_MAX_INPUTS; index++)
		if (!binding->instances[index].active) {
			instance = &binding->instances[index];
			break;
		}
	if (instance == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = binding->ops->open(binding->context, controller,
		binding->protocol, CDK2_CON_SPLITTER_OPEN_BY_DRIVER,
		&instance->interface);
	if (EFI_ERROR(status))
		return status;
	status = binding->ops->admit(binding->context, instance->interface);
	if (EFI_ERROR(status)) {
		(void)binding->ops->close(binding->context, controller,
			binding->protocol);
		instance->interface = NULL;
		return status;
	}
	instance->controller = controller;
	instance->active = TRUE;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_binding_stop(struct cdk2_split_binding *binding,
	void *controller)
{
	struct cdk2_split_binding_instance *instance;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL || binding->ops == NULL ||
	    binding->ops->remove == NULL || binding->ops->close == NULL)
		return EFI_INVALID_PARAMETER;
	instance = find_instance(binding, controller);
	if (instance == NULL)
		return EFI_NOT_FOUND;
	status = binding->ops->remove(binding->context, instance->interface);
	if (EFI_ERROR(status))
		return status;
	status = binding->ops->close(binding->context, controller,
		binding->protocol);
	if (EFI_ERROR(status)) {
		(void)binding->ops->admit(binding->context, instance->interface);
		return status;
	}
	*instance = (struct cdk2_split_binding_instance) { 0 };
	return EFI_SUCCESS;
}
