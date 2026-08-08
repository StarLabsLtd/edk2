/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_splitter.h>

static EFI_STATUS validate_ops(const struct cdk2_split_text_out_ops *ops)
{
	return ops == NULL || ops->output == NULL || ops->test == NULL ||
		ops->query == NULL || ops->set_mode == NULL || ops->set_attribute == NULL ||
		ops->clear == NULL || ops->set_cursor == NULL || ops->enable_cursor == NULL ?
		EFI_INVALID_PARAMETER : EFI_SUCCESS;
}

EFI_STATUS cdk2_split_text_out_init(struct cdk2_split_text_out *splitter,
	UINTN columns, UINTN rows)
{
	if (splitter == NULL || columns == 0U || rows == 0U)
		return EFI_INVALID_PARAMETER;
	__builtin_memset(splitter, 0, sizeof(*splitter));
	splitter->columns = columns;
	splitter->rows = rows;
	splitter->attribute = 7U;
	splitter->cursor_visible = TRUE;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_text_out_add(struct cdk2_split_text_out *splitter,
	const struct cdk2_split_text_out_ops *ops, void *context)
{
	UINTN index;

	if (splitter == NULL || context == NULL || EFI_ERROR(validate_ops(ops)))
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == context)
			return CDK2_CON_SPLITTER_ALREADY_STARTED;
	if (splitter->device_count == CDK2_CON_SPLITTER_MAX_OUTPUTS)
		return EFI_OUT_OF_RESOURCES;
	splitter->devices[splitter->device_count++] =
		(struct cdk2_split_text_out_device) { ops, context };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_text_out_remove(struct cdk2_split_text_out *splitter,
	void *context)
{
	UINTN index;

	if (splitter == NULL || context == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++) {
		if (splitter->devices[index].context != context)
			continue;
		for (; index + 1U < splitter->device_count; index++)
			splitter->devices[index] = splitter->devices[index + 1U];
		splitter->device_count--;
		return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}

static void update_virtual_cursor(struct cdk2_split_text_out *splitter,
	const CHAR16 *string)
{
	for (; *string != 0U; string++) {
		if (*string == L'\b') {
			if (splitter->column != 0U)
				splitter->column--;
			else if (splitter->row != 0U) {
				splitter->row--;
				splitter->column = splitter->columns - 1U;
			}
		} else if (*string == L'\r') {
			splitter->column = 0U;
		} else if (*string == L'\n') {
			if (splitter->row + 1U < splitter->rows)
				splitter->row++;
		} else if (++splitter->column == splitter->columns) {
			splitter->column = 0U;
			if (splitter->row + 1U < splitter->rows)
				splitter->row++;
		}
	}
}

static EFI_STATUS fanout(struct cdk2_split_text_out *splitter, const CHAR16 *string,
	BOOLEAN test_only)
{
	EFI_STATUS result = EFI_SUCCESS, status;
	UINTN index;

	if (splitter == NULL || string == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++) {
		status = test_only ? splitter->devices[index].ops->test(
			splitter->devices[index].context, string) :
			splitter->devices[index].ops->output(
			splitter->devices[index].context, string);
		if (EFI_ERROR(status))
			result = status;
	}
	if (!test_only && splitter->device_count == 0U)
		update_virtual_cursor(splitter, string);
	return result;
}

EFI_STATUS cdk2_split_text_out_output(struct cdk2_split_text_out *splitter,
	const CHAR16 *string)
{
	return fanout(splitter, string, FALSE);
}

EFI_STATUS cdk2_split_text_out_test(struct cdk2_split_text_out *splitter,
	const CHAR16 *string)
{
	return fanout(splitter, string, TRUE);
}

static EFI_STATUS aggregate_status(EFI_STATUS result, EFI_STATUS status)
{
	return EFI_ERROR(status) ? status : result;
}

EFI_STATUS cdk2_split_text_out_set_attribute(struct cdk2_split_text_out *splitter,
	UINTN attribute)
{
	EFI_STATUS result = EFI_SUCCESS;
	UINTN index;

	if (splitter == NULL || (attribute & ~0x7fU) != 0U)
		return EFI_UNSUPPORTED;
	for (index = 0; index < splitter->device_count; index++)
		result = aggregate_status(result, splitter->devices[index].ops->set_attribute(
			splitter->devices[index].context, attribute));
	splitter->attribute = attribute;
	return result;
}

EFI_STATUS cdk2_split_text_out_clear(struct cdk2_split_text_out *splitter)
{
	EFI_STATUS result = EFI_SUCCESS;
	UINTN index;

	if (splitter == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		result = aggregate_status(result, splitter->devices[index].ops->clear(
			splitter->devices[index].context));
	splitter->column = splitter->row = 0U;
	return result;
}

EFI_STATUS cdk2_split_text_out_set_cursor(struct cdk2_split_text_out *splitter,
	UINTN column, UINTN row)
{
	EFI_STATUS result = EFI_SUCCESS;
	UINTN index;

	if (splitter == NULL)
		return EFI_INVALID_PARAMETER;
	if (column >= splitter->columns || row >= splitter->rows)
		return EFI_UNSUPPORTED;
	for (index = 0; index < splitter->device_count; index++)
		result = aggregate_status(result, splitter->devices[index].ops->set_cursor(
			splitter->devices[index].context, column, row));
	splitter->column = column;
	splitter->row = row;
	return result;
}

EFI_STATUS cdk2_split_text_out_enable_cursor(struct cdk2_split_text_out *splitter,
	BOOLEAN visible)
{
	EFI_STATUS result = EFI_SUCCESS;
	UINTN index;

	if (splitter == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		result = aggregate_status(result, splitter->devices[index].ops->enable_cursor(
			splitter->devices[index].context, visible));
	splitter->cursor_visible = visible;
	return result;
}
