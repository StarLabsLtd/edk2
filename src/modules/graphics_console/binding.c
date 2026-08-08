/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/graphics_console_binding.h>

#define EFI_NOT_STARTED EFIERR(19)

static const EFI_GUID device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID gop_guid = { 0x9042a9de, 0x23dc, 0x4a38,
	{ 0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a } };
static const EFI_GUID font_guid = { 0xe9ca4775, 0x8657, 0x47fc,
	{ 0x97, 0xe7, 0x7e, 0xd6, 0x5a, 0x08, 0x43, 0x24 } };
static const EFI_GUID text_guid = { 0x387477c2, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };

static void rollback(struct cdk2_graphics_console_binding *binding)
{
	if (binding->text_installed) {
		binding->ops->uninstall(binding->context, binding->controller, &text_guid,
			&binding->text);
		binding->text_installed = FALSE;
	}
	if (binding->font_open) {
		binding->ops->close(binding->context, binding->controller, &font_guid);
		binding->font_open = FALSE;
	}
	if (binding->gop_open) {
		binding->ops->close(binding->context, binding->controller, &gop_guid);
		binding->gop_open = FALSE;
	}
	if (binding->device_path_open) {
		binding->ops->close(binding->context, binding->controller, &device_path_guid);
		binding->device_path_open = FALSE;
	}
}

EFI_STATUS cdk2_graphics_binding_supported(struct cdk2_graphics_console_binding *binding,
	void *controller)
{
	void *interface;
	EFI_STATUS status;

	if (binding == NULL || binding->ops == NULL || binding->ops->open == NULL ||
	    binding->ops->close == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->ops->open(binding->context, controller, &gop_guid,
		CDK2_OPEN_BY_DRIVER, &interface);
	if (!EFI_ERROR(status))
		binding->ops->close(binding->context, controller, &gop_guid);
	return status;
}

EFI_STATUS cdk2_graphics_binding_start(struct cdk2_graphics_console_binding *binding,
	void *controller)
{
	void *interface;
	EFI_STATUS status;

	if (binding == NULL || binding->ops == NULL || binding->ops->open == NULL ||
	    binding->ops->close == NULL || binding->ops->install == NULL ||
	    binding->ops->uninstall == NULL)
		return EFI_INVALID_PARAMETER;
	binding->controller = controller;
	status = binding->ops->open(binding->context, controller, &device_path_guid,
		CDK2_OPEN_BY_DRIVER, &interface);
	if (EFI_ERROR(status))
		return status;
	binding->device_path_open = TRUE;
	status = binding->ops->open(binding->context, controller, &gop_guid,
		CDK2_OPEN_BY_DRIVER, (void **)&binding->gop);
	if (EFI_ERROR(status))
		goto fail;
	binding->gop_open = TRUE;
	status = binding->ops->open(binding->context, controller, &font_guid,
		CDK2_OPEN_BY_DRIVER, (void **)&binding->font);
	if (EFI_ERROR(status))
		goto fail;
	binding->font_open = TRUE;
	status = binding->ops->install(binding->context, controller, &text_guid, &binding->text);
	if (EFI_ERROR(status))
		goto fail;
	binding->text_installed = TRUE;
	return EFI_SUCCESS;
fail:
	rollback(binding);
	return status;
}

EFI_STATUS cdk2_graphics_binding_stop(struct cdk2_graphics_console_binding *binding)
{
	if (binding == NULL || !binding->text_installed)
		return EFI_NOT_STARTED;
	rollback(binding);
	binding->controller = NULL;
	binding->gop = NULL;
	binding->font = NULL;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_graphics_gop_blt(struct cdk2_graphics_console_binding *binding,
	void *buffer, UINTN operation, UINTN source_x, UINTN source_y,
	UINTN destination_x, UINTN destination_y, UINTN width, UINTN height, UINTN delta)
{
	if (binding == NULL || binding->gop == NULL || binding->gop->blt == NULL)
		return EFI_NOT_READY;
	return binding->gop->blt(binding->gop, buffer, operation, source_x, source_y,
		destination_x, destination_y, width, height, delta);
}
