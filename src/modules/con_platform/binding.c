/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_platform.h>

#define EFI_NOT_STARTED EFIERR(19)

static const EFI_GUID device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID text_in_guid = { 0x387477c1, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID text_out_guid = { 0x387477c2, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID input_marker_guid = { 0xd3b36f2b, 0xd551, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID output_marker_guid = { 0xd3b36f2c, 0xd551, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID error_marker_guid = { 0xd3b36f2d, 0xd551, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const CHAR16 con_in[] = { 'C', 'o', 'n', 'I', 'n', 0 };
static const CHAR16 con_in_dev[] = { 'C', 'o', 'n', 'I', 'n', 'D', 'e', 'v', 0 };
static const CHAR16 con_out[] = { 'C', 'o', 'n', 'O', 'u', 't', 0 };
static const CHAR16 con_out_dev[] = { 'C', 'o', 'n', 'O', 'u', 't', 'D', 'e', 'v', 0 };
static const CHAR16 err_out[] = { 'E', 'r', 'r', 'O', 'u', 't', 0 };
static const CHAR16 err_out_dev[] = { 'E', 'r', 'r', 'O', 'u', 't', 'D', 'e', 'v', 0 };

static const EFI_GUID *text_guid(const struct cdk2_con_binding *binding)
{
	return binding->direction == CDK2_CON_INPUT ? &text_in_guid : &text_out_guid;
}

EFI_STATUS cdk2_con_binding_supported(struct cdk2_con_binding *binding, void *controller)
{
	void *interface = NULL;
	EFI_STATUS status;

	if (binding == NULL || binding->ops == NULL || binding->ops->open == NULL ||
	    binding->ops->close == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->ops->open(binding->context, controller, &device_path_guid,
		CDK2_CON_OPEN_TEST, NULL);
	if (EFI_ERROR(status))
		return status;
	status = binding->ops->open(binding->context, controller, text_guid(binding),
		CDK2_CON_OPEN_BY_DRIVER, &interface);
	if (!EFI_ERROR(status))
		(void)binding->ops->close(binding->context, controller, text_guid(binding));
	return status;
}

static void rollback(struct cdk2_con_binding *binding)
{
	if (binding->error_marker) {
		(void)binding->ops->uninstall(binding->context, binding->controller,
			&error_marker_guid);
		binding->error_marker = FALSE;
	}
	if (binding->output_marker) {
		(void)binding->ops->uninstall(binding->context, binding->controller,
			&output_marker_guid);
		binding->output_marker = FALSE;
	}
	if (binding->input_marker) {
		(void)binding->ops->uninstall(binding->context, binding->controller,
			&input_marker_guid);
		binding->input_marker = FALSE;
	}
	if (binding->protocol_open) {
		(void)binding->ops->close(binding->context, binding->controller,
			text_guid(binding));
		binding->protocol_open = FALSE;
	}
}

EFI_STATUS cdk2_con_binding_start(struct cdk2_con_binding *binding, void *controller)
{
	void *path = NULL;
	EFI_STATUS status, selected, error_selected;

	if (binding == NULL || binding->ops == NULL || binding->ops->open == NULL ||
	    binding->ops->close == NULL || binding->ops->install == NULL ||
	    binding->ops->uninstall == NULL || binding->ops->update == NULL)
		return EFI_INVALID_PARAMETER;
	binding->controller = controller;
	status = binding->ops->open(binding->context, controller, &device_path_guid,
		CDK2_CON_OPEN_GET, &path);
	if (EFI_ERROR(status))
		return status;
	binding->path = path;
	status = binding->ops->open(binding->context, controller, text_guid(binding),
		CDK2_CON_OPEN_BY_DRIVER, &binding->interface);
	if (EFI_ERROR(status))
		return status;
	binding->protocol_open = TRUE;
	if (binding->direction == CDK2_CON_INPUT) {
		selected = binding->ops->update(binding->context, con_in, path,
			binding->path_size, CDK2_CON_CHECK);
		status = binding->ops->update(binding->context, con_in_dev, path,
			binding->path_size, CDK2_CON_APPEND);
		if (!EFI_ERROR(status) && !EFI_ERROR(selected)) {
			status = binding->ops->install(binding->context, controller,
				&input_marker_guid);
			binding->input_marker = !EFI_ERROR(status);
		}
	} else {
		selected = binding->ops->update(binding->context, con_out, path,
			binding->path_size, CDK2_CON_CHECK);
		error_selected = binding->ops->update(binding->context, err_out, path,
			binding->path_size, CDK2_CON_CHECK);
		if (binding->ops->gop_candidate == NULL ||
		    !binding->ops->gop_candidate(binding->context, path, binding->path_size)) {
			status = binding->ops->update(binding->context, con_out_dev, path,
				binding->path_size, CDK2_CON_APPEND);
			if (!EFI_ERROR(status))
				status = binding->ops->update(binding->context, err_out_dev, path,
					binding->path_size, CDK2_CON_APPEND);
		}
		if (!EFI_ERROR(status) && !EFI_ERROR(selected)) {
			status = binding->ops->install(binding->context, controller,
				&output_marker_guid);
			binding->output_marker = !EFI_ERROR(status);
		}
		if (!EFI_ERROR(status) && !EFI_ERROR(error_selected)) {
			status = binding->ops->install(binding->context, controller,
				&error_marker_guid);
			binding->error_marker = !EFI_ERROR(status);
		}
	}
	if (EFI_ERROR(status))
		rollback(binding);
	return status;
}

EFI_STATUS cdk2_con_binding_stop(struct cdk2_con_binding *binding)
{
	if (binding == NULL || !binding->protocol_open)
		return EFI_NOT_STARTED;
	if (binding->direction == CDK2_CON_INPUT)
		(void)binding->ops->update(binding->context, con_in_dev, binding->path,
			binding->path_size, CDK2_CON_DELETE);
	else {
		(void)binding->ops->update(binding->context, con_out_dev, binding->path,
			binding->path_size, CDK2_CON_DELETE);
		(void)binding->ops->update(binding->context, err_out_dev, binding->path,
			binding->path_size, CDK2_CON_DELETE);
	}
	rollback(binding);
	binding->controller = NULL;
	binding->interface = NULL;
	binding->path = NULL;
	return EFI_SUCCESS;
}
