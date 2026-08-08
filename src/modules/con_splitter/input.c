/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_splitter.h>

EFI_STATUS cdk2_split_text_in_add(struct cdk2_split_text_in *splitter,
	cdk2_split_key_read_fn *read, cdk2_split_reset_fn *reset, void *context)
{
	return cdk2_split_text_in_add_event(splitter, read, reset, context, NULL);
}

EFI_STATUS cdk2_split_text_in_add_event(struct cdk2_split_text_in *splitter,
	cdk2_split_key_read_fn *read, cdk2_split_reset_fn *reset, void *context,
	void *wait_event)
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
		(struct cdk2_split_text_in_device) { read, reset, context, wait_event };
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

static BOOLEAN key_matches(const struct cdk2_split_key_data *match,
	const struct cdk2_split_key_data *key)
{
	return match->key.scan_code == key->key.scan_code &&
		match->key.unicode == key->key.unicode &&
		(match->state.shift_state == 0U ||
		 match->state.shift_state == key->state.shift_state) &&
		(match->state.toggle_state == 0U ||
		 match->state.toggle_state == key->state.toggle_state);
}

static BOOLEAN same_key_data(const struct cdk2_split_key_data *left,
	const struct cdk2_split_key_data *right)
{
	return left->key.scan_code == right->key.scan_code &&
		left->key.unicode == right->key.unicode &&
		left->state.shift_state == right->state.shift_state &&
		left->state.toggle_state == right->state.toggle_state;
}

EFI_STATUS cdk2_split_text_in_read_ex(struct cdk2_split_text_in *splitter,
	struct cdk2_split_key_data *key)
{
	EFI_STATUS status;

	if (splitter == NULL || key == NULL)
		return EFI_INVALID_PARAMETER;
	key->state = splitter->state;
	status = cdk2_split_text_in_read(splitter, &key->key);
	if (EFI_ERROR(status))
		return status;
	return cdk2_split_text_in_deliver(splitter, key);
}

EFI_STATUS cdk2_split_text_in_deliver(struct cdk2_split_text_in *splitter,
	struct cdk2_split_key_data *key)
{
	UINTN index;

	if (splitter == NULL || key == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->notify_count; index++)
		if (splitter->notifies[index].active &&
		    key_matches(&splitter->notifies[index].match, key))
			(void)splitter->notifies[index].callback(key);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_text_in_set_state(struct cdk2_split_text_in *splitter,
	const UINT8 *toggle_state)
{
	if (splitter == NULL || toggle_state == NULL)
		return EFI_INVALID_PARAMETER;
	splitter->state.toggle_state = *toggle_state;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_text_in_register_notify(struct cdk2_split_text_in *splitter,
	const struct cdk2_split_key_data *match, cdk2_split_key_notify_fn *callback,
	void **handle)
{
	UINTN index;

	if (splitter == NULL || match == NULL || callback == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->notify_count; index++) {
		if (splitter->notifies[index].active &&
		    same_key_data(&splitter->notifies[index].match, match) &&
		    splitter->notifies[index].callback == callback) {
			*handle = &splitter->notifies[index];
			return EFI_SUCCESS;
		}
	}
	for (index = 0; index < splitter->notify_count; index++)
		if (!splitter->notifies[index].active)
			break;
	if (index == splitter->notify_count) {
		if (splitter->notify_count == CDK2_CON_SPLITTER_MAX_KEY_NOTIFIES)
			return EFI_OUT_OF_RESOURCES;
		splitter->notify_count++;
	}
	splitter->notifies[index] = (struct cdk2_split_key_notify) {
		*match, callback, TRUE
	};
	*handle = &splitter->notifies[index];
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_text_in_unregister_notify(struct cdk2_split_text_in *splitter,
	void *handle)
{
	UINTN index;

	if (splitter == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->notify_count; index++) {
		if (handle != &splitter->notifies[index] ||
		    !splitter->notifies[index].active)
			continue;
		splitter->notifies[index].active = FALSE;
		return EFI_SUCCESS;
	}
	return EFI_INVALID_PARAMETER;
}

static INT32 scale_relative(INT32 value, UINT64 virtual_resolution,
	UINT64 device_resolution)
{
	if (value == 0 || device_resolution == 0U)
		return 0;
	return (INT32)(((INT64)value * (INT64)virtual_resolution) /
		(INT64)device_resolution);
}

EFI_STATUS cdk2_split_pointer_reset(struct cdk2_split_pointer *splitter,
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

EFI_STATUS cdk2_split_pointer_add(struct cdk2_split_pointer *splitter,
	const struct cdk2_split_pointer_device *device)
{
	UINTN index;

	if (splitter == NULL || device == NULL || device->reset == NULL ||
	    device->get_state == NULL ||
	    device->context == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == device->context)
			return CDK2_CON_SPLITTER_ALREADY_STARTED;
	if (splitter->device_count == CDK2_CON_SPLITTER_MAX_INPUTS)
		return EFI_OUT_OF_RESOURCES;
	splitter->devices[splitter->device_count++] = *device;
	if (device->resolution_x > splitter->resolution_x)
		splitter->resolution_x = device->resolution_x;
	if (device->resolution_y > splitter->resolution_y)
		splitter->resolution_y = device->resolution_y;
	if (device->resolution_z > splitter->resolution_z)
		splitter->resolution_z = device->resolution_z;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_pointer_remove(struct cdk2_split_pointer *splitter, void *context)
{
	struct cdk2_split_pointer_device remaining[CDK2_CON_SPLITTER_MAX_INPUTS];
	UINTN count, index;

	if (splitter == NULL || context == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == context)
			break;
	if (index == splitter->device_count)
		return EFI_NOT_FOUND;
	for (; index + 1U < splitter->device_count; index++)
		splitter->devices[index] = splitter->devices[index + 1U];
	count = --splitter->device_count;
	__builtin_memcpy(remaining, splitter->devices, count * sizeof(remaining[0]));
	__builtin_memset(splitter, 0, sizeof(*splitter));
	for (index = 0; index < count; index++)
		(void)cdk2_split_pointer_add(splitter, &remaining[index]);
	return EFI_SUCCESS;
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

EFI_STATUS cdk2_split_absolute_reset(struct cdk2_split_absolute *splitter,
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

EFI_STATUS cdk2_split_absolute_add(struct cdk2_split_absolute *splitter,
	const struct cdk2_split_absolute_device *device)
{
	UINTN index;

	if (splitter == NULL || device == NULL || device->reset == NULL ||
	    device->get_state == NULL ||
	    device->context == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == device->context)
			return CDK2_CON_SPLITTER_ALREADY_STARTED;
	if (splitter->device_count == CDK2_CON_SPLITTER_MAX_INPUTS)
		return EFI_OUT_OF_RESOURCES;
	splitter->devices[splitter->device_count++] = *device;
	if (splitter->device_count == 1U) {
		splitter->min_x = device->min_x; splitter->min_y = device->min_y;
		splitter->min_z = device->min_z; splitter->max_x = device->max_x;
		splitter->max_y = device->max_y; splitter->max_z = device->max_z;
	} else {
		if (device->min_x < splitter->min_x)
			splitter->min_x = device->min_x;
		if (device->min_y < splitter->min_y)
			splitter->min_y = device->min_y;
		if (device->min_z < splitter->min_z)
			splitter->min_z = device->min_z;
		if (device->max_x > splitter->max_x)
			splitter->max_x = device->max_x;
		if (device->max_y > splitter->max_y)
			splitter->max_y = device->max_y;
		if (device->max_z > splitter->max_z)
			splitter->max_z = device->max_z;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_absolute_remove(struct cdk2_split_absolute *splitter, void *context)
{
	struct cdk2_split_absolute_device remaining[CDK2_CON_SPLITTER_MAX_INPUTS];
	UINTN count, index;

	if (splitter == NULL || context == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == context)
			break;
	if (index == splitter->device_count)
		return EFI_NOT_FOUND;
	for (; index + 1U < splitter->device_count; index++)
		splitter->devices[index] = splitter->devices[index + 1U];
	count = --splitter->device_count;
	__builtin_memcpy(remaining, splitter->devices, count * sizeof(remaining[0]));
	__builtin_memset(splitter, 0, sizeof(*splitter));
	for (index = 0; index < count; index++)
		(void)cdk2_split_absolute_add(splitter, &remaining[index]);
	return EFI_SUCCESS;
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
