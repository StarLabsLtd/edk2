/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_bus_binding.h>
#include <cdk2/scsi_disk.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

typedef void CDK2_MS_ABI notify_fn(void *event, void *context);
struct event { notify_fn * notify; void *context; };
struct fixture {
	struct event *event;
	UINTN allocations, releases, creates, closes, executes, resets, completes;
	UINT8 type;
};

static struct fixture *active;

static EFI_STATUS CDK2_MS_ABI get_type(struct cdk2_scsi_io *io, UINT8 *type)
{
	(void)io; *type = active->type; return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI reset_device(struct cdk2_scsi_io *io)
{
	(void)io; active->resets++; return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI execute(struct cdk2_scsi_io *io,
	struct cdk2_scsi_request *request, void *event)
{
	UINT8 opcode = ((UINT8 *)request->cdb)[0];

	(void)io; active->executes++;
	if (opcode == 0x25U) {
		UINT8 capacity[8] = { 0, 0, 0, 99, 0, 0, 2, 0 };
		memcpy(request->in_data, capacity, sizeof(capacity));
	} else if (opcode != 0x28U && opcode != 0x2aU) {
		return EFI_DEVICE_ERROR;
	}
	request->host_status = 0U;
	request->target_status = 0U;
	if (event != NULL)
		active->event = event;
	return EFI_SUCCESS;
}

static EFI_STATUS allocate(void *opaque, UINTN size, void **buffer)
{
	struct fixture *fixture = opaque;

	fixture->allocations++; *buffer = malloc(size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static void release(void *opaque, void *buffer)
{
	struct fixture *fixture = opaque;

	fixture->releases++; free(buffer);
}

static EFI_STATUS create_event(void *opaque,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context, void **event)
{
	struct fixture *fixture = opaque;
	struct event *created = malloc(sizeof(*created));

	if (created == NULL)
		return EFI_OUT_OF_RESOURCES;
	*created = (struct event) { notify, context };
	fixture->creates++; *event = created; return EFI_SUCCESS;
}

static EFI_STATUS close_event(void *opaque, void *event)
{
	struct fixture *fixture = opaque;

	fixture->closes++; free(event); return EFI_SUCCESS;
}

static void complete(void *opaque, EFI_STATUS status, UINT8 host, UINT8 target)
{
	struct fixture *fixture = opaque;

	CHECK(status == EFI_SUCCESS && host == 0U && target == 0U);
	fixture->completes++;
}

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_scsi_io io = { .get_device_type = get_type,
		.reset_device = reset_device, .execute_scsi_command = execute,
		.io_align = 8U };
	struct cdk2_scsi_disk_backend_services services = { .context = &fixture,
		.allocate = allocate, .release = release, .create_event = create_event,
		.close_event = close_event };
	struct cdk2_scsi_disk_backend backend;
	struct cdk2_scsi_disk disk;
	struct cdk2_scsi_disk_command command;
	UINT8 buffer[512] __attribute__((aligned(8)));

	active = &fixture;
	fixture.type = 5U;
	CHECK(cdk2_scsi_disk_backend_init(&backend, &io, &services, &disk) ==
		EFI_UNSUPPORTED);
	fixture.type = 0U;
	CHECK(cdk2_scsi_disk_backend_init(&backend, &io, &services, &disk) ==
		EFI_SUCCESS && disk.media.block_size == 512U &&
		disk.media.last_block == 99U && disk.media.io_align == 8U);
	CHECK(cdk2_scsi_disk_build_rw(FALSE, 0, 1, FALSE, &command) == EFI_SUCCESS &&
		disk.transport.submit(disk.transport.context, &command, buffer,
			sizeof(buffer), FALSE, complete, &fixture) == EFI_SUCCESS &&
		fixture.completes == 0U && fixture.event != NULL);
	{
		struct event *event = fixture.event;

		fixture.event = NULL;
		event->notify(event, event->context);
	}
	CHECK(fixture.completes == 1U && fixture.allocations == fixture.releases &&
		fixture.creates == fixture.closes);
	CHECK(disk.transport.cancel(disk.transport.context) == EFI_SUCCESS &&
		fixture.resets == 1U);
	puts("scsi disk backend tests: PASS");
	return 0;
}
