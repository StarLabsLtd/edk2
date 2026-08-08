/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_platform.h>

EFI_STATUS cdk2_con_update_variable(const struct cdk2_con_variable_ops *ops,
	void *context, const CHAR16 *name, const void *path, UINTN path_size,
	enum cdk2_con_variable_operation operation)
{
	void *current = NULL, *updated = NULL;
	UINTN current_size = 0, updated_size = 0;
	EFI_STATUS status;

	if (ops == NULL || ops->read == NULL || ops->write == NULL || ops->edit == NULL ||
	    ops->release == NULL || name == NULL || path == NULL || path_size == 0U ||
	    operation > CDK2_CON_DELETE)
		return EFI_INVALID_PARAMETER;
	status = ops->read(context, name, &current, &current_size);
	if (status == EFI_NOT_FOUND) {
		current = NULL;
		current_size = 0U;
		status = EFI_SUCCESS;
	}
	if (EFI_ERROR(status))
		return status;
	status = ops->edit(context, current, current_size, path, path_size,
		operation, &updated, &updated_size);
	if (current != NULL)
		ops->release(context, current);
	if (operation == CDK2_CON_CHECK) {
		if (updated != NULL)
			ops->release(context, updated);
		return status;
	}
	if (operation == CDK2_CON_APPEND && status == CDK2_CON_ALREADY_STARTED)
		return EFI_SUCCESS;
	if (EFI_ERROR(status))
		return status;
	status = ops->write(context, name, updated, updated_size);
	if (updated != NULL)
		ops->release(context, updated);
	return status;
}
