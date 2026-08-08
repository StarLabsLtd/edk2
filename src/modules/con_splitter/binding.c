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
	status = binding->ops->admit(binding->context, controller, instance->interface);
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
	status = binding->ops->remove(binding->context, controller, instance->interface);
	if (EFI_ERROR(status))
		return status;
	status = binding->ops->close(binding->context, controller,
		binding->protocol);
	if (EFI_ERROR(status)) {
		(void)binding->ops->admit(binding->context, controller,
			instance->interface);
		return status;
	}
	*instance = (struct cdk2_split_binding_instance) { 0 };
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI driver_supported(
	struct cdk2_split_driver_binding *driver, void *controller, void *remaining)
{
	(void)remaining;
	return cdk2_split_binding_supported(driver->binding, controller);
}

static EFI_STATUS CDK2_MS_ABI driver_start(
	struct cdk2_split_driver_binding *driver, void *controller, void *remaining)
{
	(void)remaining;
	return cdk2_split_binding_start(driver->binding, controller);
}

static EFI_STATUS CDK2_MS_ABI driver_stop(
	struct cdk2_split_driver_binding *driver, void *controller, UINTN children,
	void **child_buffer)
{
	(void)child_buffer;
	if (children != 0U)
		return EFI_INVALID_PARAMETER;
	return cdk2_split_binding_stop(driver->binding, controller);
}

static EFI_STATUS CDK2_MS_ABI get_driver_name(
	struct cdk2_split_component_name *component, CHAR8 *language,
	CHAR16 **name)
{
	static CHAR16 driver_name[] = L"CDK2 Console Splitter Driver";

	if (component == NULL || language == NULL || name == NULL ||
	    language[0] != 'e' || language[1] != 'n')
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_split_component_name *component, void *controller,
	void *child, CHAR8 *language, CHAR16 **name)
{
	(void)component; (void)controller; (void)child; (void)language; (void)name;
	return EFI_UNSUPPORTED;
}

void cdk2_split_publication_prepare(struct cdk2_split_publication *publication,
	struct cdk2_split_binding *binding, void *image_handle)
{
	publication->driver = (struct cdk2_split_driver_binding) {
		driver_supported, driver_start, driver_stop, 0x10U, image_handle, NULL,
		binding
	};
	publication->component_name = (struct cdk2_split_component_name) {
		get_driver_name, get_controller_name, "eng"
	};
	publication->component_name2 = (struct cdk2_split_component_name) {
		get_driver_name, get_controller_name, "en"
	};
	publication->handle = NULL;
}

EFI_STATUS cdk2_split_publications_install(
	struct cdk2_split_publication *publications, UINTN count,
	cdk2_split_publish_fn *publish, cdk2_split_unpublish_fn *unpublish,
	void *context)
{
	EFI_STATUS status;
	UINTN index;

	if (publications == NULL || publish == NULL || unpublish == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < count; index++) {
		status = publish(context, &publications[index].handle,
			&publications[index].driver,
			&publications[index].component_name,
			&publications[index].component_name2);
		if (EFI_ERROR(status)) {
			while (index != 0U) {
				index--;
				(void)unpublish(context, publications[index].handle,
					&publications[index].driver,
					&publications[index].component_name,
					&publications[index].component_name2);
			}
			return status;
		}
		publications[index].driver.driver_binding_handle =
			publications[index].handle;
	}
	return EFI_SUCCESS;
}
