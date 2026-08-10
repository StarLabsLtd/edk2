/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_bus_binding.h>
#include <cdk2/scsi_disk.h>

#include <string.h>

struct async_call {
	struct cdk2_scsi_disk_backend *backend;
	struct cdk2_scsi_disk_backend_services services;
	struct cdk2_scsi_request request;
	struct cdk2_scsi_disk_command command;
	void (*complete)(void *context, EFI_STATUS status, UINT8 host, UINT8 target);
	void *complete_context;
	void *event;
};

static void fill_request(struct cdk2_scsi_request *request,
	struct cdk2_scsi_disk_command *command, void *buffer, UINT32 bytes,
	BOOLEAN write)
{
	*request = (struct cdk2_scsi_request) { .timeout = 30000000ULL,
		.in_data = write ? NULL : buffer, .out_data = write ? buffer : NULL,
		.cdb = command->cdb, .in_length = write ? 0U : bytes,
		.out_length = write ? bytes : 0U, .cdb_length = command->cdb_length,
		.data_direction = write ? 1U : 0U };
}

static EFI_STATUS execute(void *opaque, struct cdk2_scsi_disk_command *command,
	void *buffer, UINT32 bytes, BOOLEAN write, UINT8 *host_status,
	UINT8 *target_status)
{
	struct cdk2_scsi_disk_backend *backend = opaque;
	struct cdk2_scsi_request request;
	EFI_STATUS status;

	fill_request(&request, command, buffer, bytes, write);
	status = backend->io->execute_scsi_command(backend->io, &request, NULL);
	*host_status = request.host_status;
	*target_status = request.target_status;
	return status;
}

static void CDK2_MS_ABI async_notify(void *event, void *opaque)
{
	struct async_call *call = opaque;
	struct cdk2_scsi_disk_backend_services services = call->services;
	void (*complete)(void *, EFI_STATUS, UINT8, UINT8) = call->complete;
	void *complete_context = call->complete_context;
	UINT8 host_status = call->request.host_status;
	UINT8 target_status = call->request.target_status;

	call->backend->active_event = NULL;
	(void)services.close_event(services.context, event);
	services.release(services.context, call);
	complete(complete_context, EFI_SUCCESS, host_status, target_status);
}

static EFI_STATUS submit(void *opaque, struct cdk2_scsi_disk_command *command,
	void *buffer, UINT32 bytes, BOOLEAN write,
	void (*complete)(void *, EFI_STATUS, UINT8, UINT8), void *complete_context)
{
	struct cdk2_scsi_disk_backend *backend = opaque;
	struct async_call *call;
	EFI_STATUS status;

	status = backend->services.allocate(backend->services.context, sizeof(*call),
		(void **)&call);
	if (EFI_ERROR(status))
		return status;
	memset(call, 0, sizeof(*call));
	call->services = backend->services;
	call->backend = backend;
	call->command = *command;
	call->complete = complete;
	call->complete_context = complete_context;
	fill_request(&call->request, &call->command, buffer, bytes, write);
	status = backend->services.create_event(backend->services.context,
		async_notify, call, &call->event);
	if (EFI_ERROR(status))
		goto fail;
	backend->active_event = call->event;
	status = backend->io->execute_scsi_command(backend->io, &call->request,
		call->event);
	if (!EFI_ERROR(status))
		return EFI_SUCCESS;
	backend->active_event = NULL;
	(void)backend->services.close_event(backend->services.context, call->event);
fail:
	backend->services.release(backend->services.context, call);
	return status;
}

static EFI_STATUS wait(void *opaque)
{
	struct cdk2_scsi_disk_backend *backend = opaque;

	return backend->active_event == NULL ? EFI_SUCCESS :
		backend->services.wait_event(backend->services.context,
			backend->active_event);
}

static EFI_STATUS cancel(void *opaque)
{
	struct cdk2_scsi_disk_backend *backend = opaque;

	return backend->io->reset_device(backend->io);
}

static EFI_STATUS capacity(struct cdk2_scsi_disk_backend *backend,
	struct cdk2_scsi_disk *disk)
{
	struct cdk2_scsi_disk_command command = { .cdb = { 0x25U },
		.cdb_length = 10U };
	UINT8 response10[8] = { 0 };
	UINT8 response16[32] = { 0 };
	UINT8 host = 0, target = 0;
	BOOLEAN needs16;
	EFI_STATUS status;

	status = execute(backend, &command, response10, sizeof(response10), FALSE,
		&host, &target);
	if (EFI_ERROR(status))
		return status;
	if (host != 0U || target != 0U)
		return EFI_DEVICE_ERROR;
	status = cdk2_scsi_disk_parse_capacity10(response10, &disk->media.last_block,
		&disk->media.block_size, &needs16);
	if (EFI_ERROR(status) || !needs16)
		return status;
	command = (struct cdk2_scsi_disk_command) { .cdb = { 0x9eU, 0x10U },
		.cdb_length = 16U };
	command.cdb[13] = sizeof(response16);
	status = execute(backend, &command, response16, sizeof(response16), FALSE,
		&host, &target);
	if (EFI_ERROR(status))
		return status;
	if (host != 0U || target != 0U)
		return EFI_DEVICE_ERROR;
	return cdk2_scsi_disk_parse_capacity16(response16, &disk->media.last_block,
		&disk->media.block_size);
}

static EFI_STATUS inquiry(struct cdk2_scsi_disk_backend *backend,
	struct cdk2_scsi_disk *disk)
{
	struct cdk2_scsi_disk_command command = { .cdb = { 0x12U, 0, 0, 0,
		sizeof(disk->inquiry), 0 }, .cdb_length = 6U };
	UINT8 host = 0, target = 0;
	EFI_STATUS status = execute(backend, &command, disk->inquiry,
		sizeof(disk->inquiry), FALSE, &host, &target);

	if (EFI_ERROR(status))
		return status;
	return host != 0U || target != 0U ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_disk_backend_init(struct cdk2_scsi_disk_backend *backend,
	struct cdk2_scsi_io *io,
	const struct cdk2_scsi_disk_backend_services *services,
	struct cdk2_scsi_disk *disk)
{
	UINT8 type;
	EFI_STATUS status;

	if (backend == NULL || io == NULL || services == NULL || disk == NULL ||
	    io->get_device_type == NULL || io->execute_scsi_command == NULL ||
	    io->reset_device == NULL || services->allocate == NULL ||
	    services->release == NULL || services->create_event == NULL ||
	    services->close_event == NULL || services->wait_event == NULL)
		return EFI_INVALID_PARAMETER;
	status = io->get_device_type(io, &type);
	if (EFI_ERROR(status))
		return status;
	if (type != 0U)
		return EFI_UNSUPPORTED;
	memset(backend, 0, sizeof(*backend));
	memset(disk, 0, sizeof(*disk));
	backend->io = io;
	backend->services = *services;
	disk->media = (struct cdk2_scsi_disk_media) { .present = TRUE,
		.io_align = io->io_align == 0U ? 1U : io->io_align };
	disk->transport = (struct cdk2_scsi_disk_transport) { .context = backend,
		.execute = execute, .submit = submit, .cancel = cancel, .wait = wait };
	status = inquiry(backend, disk);
	if (EFI_ERROR(status))
		return status;
	status = capacity(backend, disk);
	if (EFI_ERROR(status))
		return status;
	disk->cdb16 = disk->media.last_block > UINT32_MAX;
	return EFI_SUCCESS;
}
