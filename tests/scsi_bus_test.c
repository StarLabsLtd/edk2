/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/scsi_bus.h>
#include <stdio.h>

static int calls;
static void *last_event;
static struct cdk2_scsi_target listed[2] = { { { 1 }, 2 }, { { 3 }, 4 } };
static UINTN cursor;

static EFI_STATUS pass(void *context, const UINT8 *target, UINT64 lun,
	struct cdk2_scsi_request *request, void *event)
{
	(void)context;
	(void)target;
	(void)lun;
	(void)request;
	calls++;
	last_event = event;
	return EFI_SUCCESS;
}

static EFI_STATUS reset(void *context)
{
	(void)context;
	calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS reset_target(void *context, const UINT8 *target, UINT64 lun)
{
	(void)context;
	(void)target;
	(void)lun;
	calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS next(void *context, UINT8 **target, UINT64 *lun)
{
	(void)context;
	if (cursor == 2U)
		return EFI_NOT_FOUND;
	*target = listed[cursor].id;
	*lun = listed[cursor++].lun;
	return EFI_SUCCESS;
}

static EFI_STATUS build(void *context, const UINT8 *target, UINT64 lun, void **path)
{
	(void)context;
	(void)target;
	(void)lun;
	*path = (void *)1;
	return EFI_SUCCESS;
}

static void release(void *context, void *path)
{
	(void)context;
	(void)path;
}

static EFI_STATUS publish(void *context, struct cdk2_scsi_device *device, void *path)
{
	(void)context;
	(void)device;
	(void)path;
	return EFI_SUCCESS;
}

static EFI_STATUS unpublish(void *context, struct cdk2_scsi_device *device, void *path)
{
	(void)context;
	(void)device;
	(void)path;
	return EFI_SUCCESS;
}

static int check(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "scsi: %s\n", message);
	return !condition;
}

int main(void)
{
	struct cdk2_scsi_backend backend = { .io_align = 8, .pass = pass,
		.reset_bus = reset, .reset_target = reset_target, .next = next,
		.build_path = build, .release_path = release };
	struct cdk2_scsi_target target = { { 1 }, 7 };
	struct cdk2_scsi_target other = { { 1 }, 7 };
	struct cdk2_scsi_device device;
	struct cdk2_scsi_device devices[2];
	void *paths[2];
	struct cdk2_scsi_bus bus = { backend, devices, paths, 2, 0, NULL,
		publish, unpublish };
	UINT8 cdb[16] = { 0 };
	struct cdk2_scsi_request request = { .cdb = cdb, .cdb_length = 16 };
	int failures = 0;

	failures += check(cdk2_scsi_device_init(&device, &backend, &target, 0) ==
		EFI_SUCCESS, "init");
	failures += check(cdk2_scsi_target_equal(&target, &other), "target equality");
	failures += check(cdk2_scsi_execute(&device, &request, (void *)1) == EFI_SUCCESS &&
		last_event == NULL, "blocking downgrade");
	device.backend.attributes = 4;
	failures += check(cdk2_scsi_execute(&device, &request, (void *)1) == EFI_SUCCESS &&
		last_event == (void *)1, "nonblocking event");
	request.cdb_length = 17;
	failures += check(cdk2_scsi_execute(&device, &request, NULL) ==
		EFI_INVALID_PARAMETER, "CDB bound");
	failures += check(cdk2_scsi_reset_bus(&device) == EFI_SUCCESS &&
		cdk2_scsi_reset_device(&device) == EFI_SUCCESS, "reset delegation");
	failures += check(cdk2_scsi_enumerate(&bus, NULL) == EFI_SUCCESS &&
		bus.count == 2, "target iteration");
	failures += check(cdk2_scsi_remove_all(&bus) == EFI_SUCCESS && bus.count == 0,
		"reverse teardown");
	return failures != 0;
}
