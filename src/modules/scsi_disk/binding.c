/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_disk.h>

#include <string.h>

#ifndef EFI_ALREADY_STARTED
#define EFI_ALREADY_STARTED EFIERR(20)
#endif
#ifndef EFI_NOT_STARTED
#define EFI_NOT_STARTED EFIERR(19)
#endif

static UINTN find_controller(struct cdk2_scsi_disk_binding *binding,
	void *controller)
{
	for (UINTN index = 0; index < binding->count; index++)
		if (binding->controllers[index]->handle == controller)
			return index;
	return binding->count;
}

EFI_STATUS cdk2_scsi_disk_binding_init(struct cdk2_scsi_disk_binding *binding,
	const struct cdk2_scsi_disk_binding_services *services)
{
	if (binding == NULL || services == NULL || services->open_parent == NULL ||
	    services->close_parent == NULL || services->probe == NULL ||
	    services->install == NULL || services->uninstall == NULL ||
	    services->signal == NULL || services->allocate == NULL ||
	    services->release == NULL)
		return EFI_INVALID_PARAMETER;
	memset(binding, 0, sizeof(*binding));
	binding->services = *services;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_binding_start(struct cdk2_scsi_disk_binding *binding,
	void *controller)
{
	struct cdk2_scsi_disk_bound_controller *bound;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_controller(binding, controller) != binding->count)
		return EFI_ALREADY_STARTED;
	if (binding->count == CDK2_SCSI_DISK_MAX_CONTROLLERS)
		return EFI_OUT_OF_RESOURCES;
	status = binding->services.allocate(binding->services.context, sizeof(*bound) +
		sizeof(struct cdk2_scsi_disk_backend),
		(void **)&bound);
	if (EFI_ERROR(status))
		return status;
	memset(bound, 0, sizeof(*bound));
	bound->backend = (void *)(bound + 1);
	memset(bound->backend, 0, sizeof(*bound->backend));
	bound->handle = controller;
	status = binding->services.open_parent(binding->services.context, controller,
		&bound->scsi_io);
	if (EFI_ERROR(status))
		goto fail;
	bound->parent_open = TRUE;
	status = binding->services.probe(binding->services.context, bound);
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_scsi_disk_async_init(&bound->async, &bound->disk,
		binding->services.context, binding->services.signal);
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_scsi_disk_async_set_lock(&bound->async,
		binding->services.context, binding->services.lock,
		binding->services.unlock);
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_scsi_disk_block_init(&bound->block, &bound->disk, &bound->async);
	if (EFI_ERROR(status))
		goto fail;
	status = cdk2_scsi_disk_info_init(bound);
	if (EFI_ERROR(status))
		goto fail;
	status = binding->services.install(binding->services.context, controller, bound);
	if (EFI_ERROR(status))
		goto fail;
	bound->installed = TRUE;
	binding->controllers[binding->count++] = bound;
	return EFI_SUCCESS;
fail:
	if (bound->parent_open && EFI_ERROR(binding->services.close_parent(
	    binding->services.context, controller))) {
		binding->controllers[binding->count++] = bound;
		return status;
	}
	binding->services.release(binding->services.context, bound);
	return status;
}

EFI_STATUS cdk2_scsi_disk_binding_stop(struct cdk2_scsi_disk_binding *binding,
	void *controller)
{
	struct cdk2_scsi_disk_bound_controller *bound;
	UINTN index;
	EFI_STATUS status;

	if (binding == NULL || controller == NULL)
		return EFI_INVALID_PARAMETER;
	index = find_controller(binding, controller);
	if (index == binding->count)
		return EFI_NOT_STARTED;
	bound = binding->controllers[index];
	if (bound->installed) {
		status = cdk2_scsi_disk_async_stop(&bound->async);
		if (EFI_ERROR(status))
			return status;
		status = binding->services.uninstall(binding->services.context, controller,
			bound);
		if (EFI_ERROR(status)) {
			bound->async.stopping = FALSE;
			return status;
		}
		bound->installed = FALSE;
	}
	status = binding->services.close_parent(binding->services.context, controller);
	if (EFI_ERROR(status)) {
		EFI_STATUS restore = binding->services.install(binding->services.context,
			controller, bound);

		if (!EFI_ERROR(restore)) {
			bound->installed = TRUE;
			bound->async.stopping = FALSE;
		}
		return status;
	}
	for (; index + 1U < binding->count; index++)
		binding->controllers[index] = binding->controllers[index + 1U];
	binding->controllers[--binding->count] = NULL;
	binding->services.release(binding->services.context, bound);
	return EFI_SUCCESS;
}
