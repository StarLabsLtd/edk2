/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/scsi_bus.h>
BOOLEAN cdk2_scsi_target_equal(const struct cdk2_scsi_target *left,
	const struct cdk2_scsi_target *right)
{
	UINTN index;
	if (left == NULL || right == NULL || left->lun != right->lun)
		return FALSE;
	for (index = 0; index < CDK2_SCSI_TARGET_MAX; index++)
		if (left->id[index] != right->id[index])
			return FALSE;
	return TRUE;
}
EFI_STATUS cdk2_scsi_device_init(struct cdk2_scsi_device *device,
	const struct cdk2_scsi_backend *backend, const struct cdk2_scsi_target *target,
	UINT8 device_type)
{
	if (device == NULL || backend == NULL || target == NULL ||
	    backend->pass == NULL || backend->reset_bus == NULL ||
	    backend->reset_target == NULL)
		return EFI_INVALID_PARAMETER;
	device->backend = *backend;
	device->location = *target;
	device->device_type = device_type;
	return EFI_SUCCESS;
}
EFI_STATUS cdk2_scsi_get_location(const struct cdk2_scsi_device *device,
	UINT8 **target, UINT64 *lun)
{
	if (device == NULL || target == NULL || lun == NULL)
		return EFI_INVALID_PARAMETER;
	*target = (UINT8 *)device->location.id;
	*lun = device->location.lun;
	return EFI_SUCCESS;
}
EFI_STATUS cdk2_scsi_reset_bus(struct cdk2_scsi_device *device)
{
	if (device == NULL)
		return EFI_INVALID_PARAMETER;
	return device->backend.reset_bus(device->backend.interface);
}
EFI_STATUS cdk2_scsi_reset_device(struct cdk2_scsi_device *device)
{
	if (device == NULL)
		return EFI_INVALID_PARAMETER;
	return device->backend.reset_target(device->backend.interface,
		device->location.id, device->location.lun);
}
EFI_STATUS cdk2_scsi_execute(struct cdk2_scsi_device *device,
	struct cdk2_scsi_request *request, void *event)
{
	if (device == NULL || request == NULL || request->cdb == NULL ||
	    request->cdb_length == 0U || request->cdb_length > 16U ||
	    request->data_direction > 2U ||
	    (request->in_length != 0U && request->in_data == NULL) ||
	    (request->out_length != 0U && request->out_data == NULL))
		return EFI_INVALID_PARAMETER;
	if ((device->backend.attributes & 4U) == 0U)
		event = NULL;
	return device->backend.pass(device->backend.interface, device->location.id,
		device->location.lun, request, event);
}

static BOOLEAN already_present(const struct cdk2_scsi_bus *bus,
	const struct cdk2_scsi_target *target)
{
	UINTN index;

	for (index = 0; index < bus->count; index++)
		if (cdk2_scsi_target_equal(&bus->devices[index].location, target))
			return TRUE;
	return FALSE;
}

static EFI_STATUS add_target(struct cdk2_scsi_bus *bus,
	const struct cdk2_scsi_target *target)
{
	void *path = NULL;
	EFI_STATUS status;

	if (already_present(bus, target))
		return CDK2_SCSI_ALREADY_STARTED;
	if (bus->count >= bus->capacity)
		return EFI_OUT_OF_RESOURCES;
	status = bus->backend.build_path(bus->backend.interface, target->id,
		target->lun, &path);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_scsi_device_init(&bus->devices[bus->count], &bus->backend,
		target, 0xffU);
	if (!EFI_ERROR(status))
		status = bus->publish(bus->context, &bus->devices[bus->count], path);
	if (EFI_ERROR(status)) {
		bus->backend.release_path(bus->backend.interface, path);
		return status;
	}
	bus->paths[bus->count++] = path;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_enumerate(struct cdk2_scsi_bus *bus,
	const struct cdk2_scsi_target *only)
{
	struct cdk2_scsi_target target = { { 0 }, 0 };
	UINT8 *target_id = target.id;
	EFI_STATUS status;

	if (bus == NULL || bus->devices == NULL || bus->paths == NULL ||
	    bus->publish == NULL || bus->unpublish == NULL ||
	    bus->backend.next == NULL || bus->backend.build_path == NULL ||
	    bus->backend.release_path == NULL)
		return EFI_INVALID_PARAMETER;
	if (only != NULL)
		return add_target(bus, only);
	target_id = NULL;
	for (;;) {
		status = bus->backend.next(bus->backend.interface, &target_id,
			&target.lun);
		if (status == EFI_NOT_FOUND)
			return EFI_SUCCESS;
		if (EFI_ERROR(status) || target_id == NULL)
			return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
		for (UINTN byte = 0; byte < sizeof(target.id); byte++)
			target.id[byte] = target_id[byte];
		status = add_target(bus, &target);
		if (EFI_ERROR(status) && status != CDK2_SCSI_ALREADY_STARTED)
			return status;
	}
}

EFI_STATUS cdk2_scsi_remove_all(struct cdk2_scsi_bus *bus)
{
	EFI_STATUS status;

	if (bus == NULL || bus->unpublish == NULL)
		return EFI_INVALID_PARAMETER;
	while (bus->count != 0U) {
		status = bus->unpublish(bus->context, &bus->devices[bus->count - 1U],
			bus->paths[bus->count - 1U]);
		if (EFI_ERROR(status))
			return status;
		bus->backend.release_path(bus->backend.interface,
			bus->paths[bus->count - 1U]);
		bus->count--;
	}
	return EFI_SUCCESS;
}
