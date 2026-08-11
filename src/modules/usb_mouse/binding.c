/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mouse.h>

static CHAR16 driver_name[] = L"CDK2 USB Mouse Driver";
static CHAR16 controller_name[] = L"Generic USB Mouse";

static struct cdk2_usb_mouse_binding *from_driver(
	struct cdk2_mouse_driver_binding *driver)
{
	return (void *)((UINT8 *)driver - offsetof(struct cdk2_usb_mouse_binding, driver));
}

static EFI_STATUS CDK2_MS_ABI supported(struct cdk2_mouse_driver_binding *driver,
	void *controller, void *remaining)
{
	struct cdk2_usb_mouse_binding *binding = from_driver(driver);
	struct cdk2_usb_io *usb_io;
	EFI_STATUS status;

	(void)remaining;
	status = binding->ops->open(binding->context, controller, &cdk2_usb_io_guid,
		(void **)&usb_io, binding->image, controller, CDK2_OPEN_BY_DRIVER);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_is_usb_mouse(usb_io) ? EFI_SUCCESS : EFI_UNSUPPORTED;
	(void)binding->ops->close(binding->context, controller, &cdk2_usb_io_guid,
		binding->image, controller);
	return status;
}

static EFI_STATUS CDK2_MS_ABI start(struct cdk2_mouse_driver_binding *driver,
	void *controller, void *remaining)
{
	struct cdk2_usb_mouse_binding *binding = from_driver(driver);
	struct cdk2_usb_mouse *mouse;
	EFI_STATUS status;

	(void)remaining;
	status = binding->ops->allocate(binding->context, sizeof(*mouse), (void **)&mouse);
	if (EFI_ERROR(status))
		return status;
	*mouse = (struct cdk2_usb_mouse) { .ops = binding->ops,
		.context = binding->context, .image = binding->image };
	status = cdk2_usb_mouse_start(mouse, controller);
	if (EFI_ERROR(status)) {
		if (mouse->usb_open || mouse->pointer_installed || mouse->polling) {
			mouse->next = binding->instances;
			binding->instances = mouse;
			return status;
		}
		binding->ops->free(binding->context, mouse);
		return status;
	}
	mouse->next = binding->instances;
	binding->instances = mouse;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI stop(struct cdk2_mouse_driver_binding *driver,
	void *controller, UINTN number_of_children, void **children)
{
	struct cdk2_usb_mouse_binding *binding = from_driver(driver);
	struct cdk2_usb_mouse **link = &binding->instances;
	struct cdk2_usb_mouse *mouse;
	EFI_STATUS status;

	(void)children;
	if (number_of_children != 0U)
		return EFI_INVALID_PARAMETER;
	while (*link != NULL && (*link)->controller != controller)
		link = &(*link)->next;
	if (*link == NULL)
		return EFI_UNSUPPORTED;
	mouse = *link;
	status = cdk2_usb_mouse_stop(mouse);
	if (EFI_ERROR(status))
		return status;
	*link = mouse->next;
	binding->ops->free(binding->context, mouse);
	return EFI_SUCCESS;
}

static EFI_STATUS language_name(CHAR8 *language, CHAR16 **name, BOOLEAN modern,
	CHAR16 *value)
{
	if (language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (language[0] != 'e' || language[1] != 'n')
		return EFI_UNSUPPORTED;
	if ((modern && language[2] != '\0') ||
	    (!modern && (language[2] != 'g' || language[3] != '\0')))
		return EFI_UNSUPPORTED;
	*name = value;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_driver_name(
	struct cdk2_mouse_component_name *component, CHAR8 *language, CHAR16 **name)
{
	(void)component;
	return language_name(language, name, FALSE, driver_name);
}

static EFI_STATUS CDK2_MS_ABI get_driver_name2(
	struct cdk2_mouse_component_name *component, CHAR8 *language, CHAR16 **name)
{
	(void)component;
	return language_name(language, name, TRUE, driver_name);
}

static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_mouse_component_name *component, void *controller, void *child,
	CHAR8 *language, CHAR16 **name)
{
	struct cdk2_usb_mouse_binding *binding;
	struct cdk2_usb_mouse *mouse;
	BOOLEAN modern;

	if (component == NULL || controller == NULL || child != NULL)
		return EFI_UNSUPPORTED;
	modern = component->supported_languages[2] == '\0';
	if (modern)
		binding = (void *)((UINT8 *)component -
			offsetof(struct cdk2_usb_mouse_binding, component_name2));
	else
		binding = (void *)((UINT8 *)component -
			offsetof(struct cdk2_usb_mouse_binding, component_name));
	for (mouse = binding->instances; mouse != NULL; mouse = mouse->next)
		if (mouse->controller == controller)
			return language_name(language, name, modern, controller_name);
	return EFI_UNSUPPORTED;
}

void cdk2_usb_mouse_binding_init(struct cdk2_usb_mouse_binding *binding,
	const struct cdk2_usb_mouse_ops *ops, void *context, void *image)
{
	*binding = (struct cdk2_usb_mouse_binding) {
		.ops = ops,
		.context = context,
		.image = image,
		.driver = { supported, start, stop, 0x0aU, image, image },
		.component_name = { get_driver_name, get_controller_name, "eng" },
		.component_name2 = { get_driver_name2, get_controller_name, "en" },
	};
}
