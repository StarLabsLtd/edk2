/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_splitter.h>

static BOOLEAN same_mode(const struct cdk2_split_gop_mode *left,
	const struct cdk2_split_gop_mode *right)
{
	return left->width == right->width && left->height == right->height &&
		left->pixel_format == right->pixel_format;
}

static EFI_STATUS rebuild_modes(struct cdk2_split_gop *splitter)
{
	struct cdk2_split_gop_mode candidate;
	UINTN device, mode, other;
	EFI_STATUS status;

	splitter->mode_count = 0U;
	if (splitter->device_count == 0U)
		return EFI_SUCCESS;
	for (mode = 0; mode < splitter->devices[0].max_mode &&
	     splitter->mode_count < CDK2_CON_SPLITTER_MAX_MODES; mode++) {
		status = splitter->devices[0].query_mode(splitter->devices[0].context,
			(UINT32)mode, &candidate);
		if (EFI_ERROR(status))
			continue;
		candidate.device_mode[0] = (INT32)mode;
		for (device = 1U; device < splitter->device_count; device++) {
			candidate.device_mode[device] = -1;
			for (other = 0; other < splitter->devices[device].max_mode; other++) {
				struct cdk2_split_gop_mode physical;

				status = splitter->devices[device].query_mode(
					splitter->devices[device].context, (UINT32)other,
					&physical);
				if (!EFI_ERROR(status) && same_mode(&candidate, &physical)) {
					candidate.device_mode[device] = (INT32)other;
					break;
				}
			}
			if (candidate.device_mode[device] < 0)
				break;
		}
		if (device == splitter->device_count)
			splitter->modes[splitter->mode_count++] = candidate;
	}
	if (splitter->mode >= splitter->mode_count)
		splitter->mode = 0U;
	return splitter->mode_count == 0U ? EFI_UNSUPPORTED : EFI_SUCCESS;
}

EFI_STATUS cdk2_split_gop_add(struct cdk2_split_gop *splitter,
	const struct cdk2_split_gop_device *device)
{
	UINTN index;
	EFI_STATUS status;

	if (splitter == NULL || device == NULL || device->context == NULL ||
	    device->query_mode == NULL || device->set_mode == NULL ||
	    device->blt == NULL || device->max_mode == 0U)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == device->context)
			return CDK2_CON_SPLITTER_ALREADY_STARTED;
	if (splitter->device_count == CDK2_CON_SPLITTER_MAX_GOPS)
		return EFI_OUT_OF_RESOURCES;
	splitter->devices[splitter->device_count++] = *device;
	status = rebuild_modes(splitter);
	if (EFI_ERROR(status)) {
		splitter->device_count--;
		(void)rebuild_modes(splitter);
	}
	return status;
}

EFI_STATUS cdk2_split_gop_remove(struct cdk2_split_gop *splitter, void *context)
{
	UINTN index;

	if (splitter == NULL || context == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++)
		if (splitter->devices[index].context == context)
			break;
	if (index == splitter->device_count)
		return EFI_NOT_FOUND;
	for (; index + 1U < splitter->device_count; index++)
		splitter->devices[index] = splitter->devices[index + 1U];
	splitter->device_count--;
	(void)rebuild_modes(splitter);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_gop_query_mode(struct cdk2_split_gop *splitter, UINT32 mode,
	struct cdk2_split_gop_mode *information)
{
	if (splitter == NULL || information == NULL)
		return EFI_INVALID_PARAMETER;
	if (mode >= splitter->mode_count)
		return EFI_UNSUPPORTED;
	*information = splitter->modes[mode];
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_split_gop_set_mode(struct cdk2_split_gop *splitter, UINT32 mode)
{
	EFI_STATUS result = EFI_SUCCESS, status;
	UINTN index;

	if (splitter == NULL || mode >= splitter->mode_count)
		return EFI_UNSUPPORTED;
	for (index = 0; index < splitter->device_count; index++) {
		status = splitter->devices[index].set_mode(
			splitter->devices[index].context,
			(UINT32)splitter->modes[mode].device_mode[index]);
		if (EFI_ERROR(status))
			result = status;
	}
	if (!EFI_ERROR(result))
		splitter->mode = mode;
	return result;
}

EFI_STATUS cdk2_split_gop_blt(struct cdk2_split_gop *splitter, void *buffer,
	UINTN operation, UINTN source_x, UINTN source_y, UINTN destination_x,
	UINTN destination_y, UINTN width, UINTN height, UINTN delta)
{
	EFI_STATUS result = EFI_SUCCESS, status;
	UINTN index;

	if (splitter == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < splitter->device_count; index++) {
		status = splitter->devices[index].blt(splitter->devices[index].context,
			buffer, operation, source_x, source_y, destination_x,
			destination_y, width, height, delta);
		if (EFI_ERROR(status))
			result = status;
	}
	return result;
}
