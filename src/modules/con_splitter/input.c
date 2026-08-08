/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_splitter.h>

EFI_STATUS cdk2_split_text_in_add(struct cdk2_split_text_in *splitter,
	cdk2_split_key_read_fn *read, cdk2_split_reset_fn *reset, void *context)
{
	UINTN index;

	if (splitter == NULL || read == NULL || reset == NULL || context == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == context)
			return CDK2_CON_SPLITTER_ALREADY_STARTED;
	if (splitter->device_count == CDK2_CON_SPLITTER_MAX_INPUTS)
		return EFI_OUT_OF_RESOURCES;
	splitter->devices[splitter->device_count++] =
		(struct cdk2_split_text_in_device) { read, reset, context };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_text_in_remove(struct cdk2_split_text_in *splitter, void *context)
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

EFI_STATUS cdk2_split_text_in_read(struct cdk2_split_text_in *splitter,
	struct cdk2_split_key *key)
{
	struct cdk2_split_key candidate;
	EFI_STATUS status;
	UINTN index;

	if (splitter == NULL || key == NULL)
		return EFI_INVALID_PARAMETER;
	key->scan_code = key->unicode = 0U;
	for (index = 0; index < splitter->device_count; index++) {
		do {
			candidate = (struct cdk2_split_key) { 0 };
			status = splitter->devices[index].read(
				splitter->devices[index].context, &candidate);
		} while (!EFI_ERROR(status) && candidate.scan_code == 0U &&
			 candidate.unicode == 0U);
		if (!EFI_ERROR(status)) {
			*key = candidate;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_READY;
}

EFI_STATUS cdk2_split_text_in_reset(struct cdk2_split_text_in *splitter,
	BOOLEAN extended)
{
	EFI_STATUS result = EFI_SUCCESS, status;
	UINTN index;

	if (splitter == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++) {
		status = splitter->devices[index].reset(splitter->devices[index].context,
			extended);
		if (EFI_ERROR(status))
			result = status;
	}
	return result;
}

static INT32 scale_relative(INT32 value, UINT64 virtual_resolution,
	UINT64 device_resolution)
{
	if (value == 0 || device_resolution == 0U)
		return 0;
	return (INT32)(((INT64)value * (INT64)virtual_resolution) /
		(INT64)device_resolution);
}

EFI_STATUS cdk2_split_pointer_get_state(struct cdk2_split_pointer *splitter,
	struct cdk2_split_pointer_state *state)
{
	struct cdk2_split_pointer_state current;
	EFI_STATUS result = EFI_NOT_READY, status;
	UINTN index;

	if (splitter == NULL || state == NULL)
		return EFI_INVALID_PARAMETER;
	*state = (struct cdk2_split_pointer_state) { 0 };
	for (index = 0; index < splitter->device_count; index++) {
		status = splitter->devices[index].get_state(
			splitter->devices[index].context, &current);
		if (!EFI_ERROR(status)) {
			if (result == EFI_NOT_READY)
				result = EFI_SUCCESS;
			state->left |= current.left;
			state->right |= current.right;
			state->x += scale_relative(current.x, splitter->resolution_x,
				splitter->devices[index].resolution_x);
			state->y += scale_relative(current.y, splitter->resolution_y,
				splitter->devices[index].resolution_y);
			state->z += scale_relative(current.z, splitter->resolution_z,
				splitter->devices[index].resolution_z);
		} else if (status == EFI_DEVICE_ERROR) {
			result = status;
		}
	}
	return result;
}

static UINT64 scale_absolute(UINT64 value, UINT64 source_min, UINT64 source_max,
	UINT64 target_min, UINT64 target_max)
{
	if (source_min == source_max)
		return 0U;
	return target_min + ((value - source_min) * (target_max - target_min)) /
		(source_max - source_min);
}

EFI_STATUS cdk2_split_absolute_get_state(struct cdk2_split_absolute *splitter,
	struct cdk2_split_absolute_state *state)
{
	struct cdk2_split_absolute_state current;
	struct cdk2_split_absolute_device *device;
	EFI_STATUS result = EFI_NOT_READY, status;
	UINTN index;

	if (splitter == NULL || state == NULL)
		return EFI_INVALID_PARAMETER;
	*state = (struct cdk2_split_absolute_state) { 0 };
	for (index = 0; index < splitter->device_count; index++) {
		device = &splitter->devices[index];
		status = device->get_state(device->context, &current);
		if (!EFI_ERROR(status)) {
			if (result == EFI_NOT_READY)
				result = EFI_SUCCESS;
			state->buttons = current.buttons;
			state->x = scale_absolute(current.x, device->min_x, device->max_x,
				splitter->min_x, splitter->max_x);
			state->y = scale_absolute(current.y, device->min_y, device->max_y,
				splitter->min_y, splitter->max_y);
			state->z = scale_absolute(current.z, device->min_z, device->max_z,
				splitter->min_z, splitter->max_z);
		} else if (status == EFI_DEVICE_ERROR) {
			result = status;
		}
	}
	return result;
}
