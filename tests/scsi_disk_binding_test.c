/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_disk.h>

#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	UINTN opens, closes, probes, installs, uninstalls, allocations, releases;
	UINTN fail_open, fail_probe, fail_install, fail_uninstall, fail_close;
};

static EFI_STATUS submit(void *opaque, struct cdk2_scsi_disk_command *command,
	void *buffer, UINT32 bytes, BOOLEAN write,
	void (*complete)(void *, EFI_STATUS, UINT8, UINT8), void *context)
{
	(void)opaque; (void)command; (void)buffer; (void)bytes; (void)write;
	(void)complete; (void)context; return EFI_SUCCESS;
}

static EFI_STATUS cancel(void *opaque)
{
	(void)opaque; return EFI_SUCCESS;
}

static EFI_STATUS open_parent(void *opaque, void *controller, void **io)
{
	struct fixture *fixture = opaque;

	(void)controller; fixture->opens++; *io = fixture;
	return fixture->opens == fixture->fail_open ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS close_parent(void *opaque, void *controller)
{
	struct fixture *fixture = opaque;

	(void)controller; fixture->closes++;
	return fixture->closes == fixture->fail_close ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS probe(void *opaque,
	struct cdk2_scsi_disk_bound_controller *bound)
{
	struct fixture *fixture = opaque;

	CHECK(bound->scsi_io == fixture && bound->backend != NULL); fixture->probes++;
	if (fixture->probes == fixture->fail_probe)
		return EFI_DEVICE_ERROR;
	bound->disk = (struct cdk2_scsi_disk) { .media = { 0, 0, 1, 0, 512, 1, 99 },
		.transport = { .context = fixture, .submit = submit, .cancel = cancel } };
	return EFI_SUCCESS;
}

static EFI_STATUS install(void *opaque, void *controller,
	struct cdk2_scsi_disk_bound_controller *bound)
{
	struct fixture *fixture = opaque;

	(void)controller; CHECK(bound != NULL); fixture->installs++;
	return fixture->installs == fixture->fail_install ? EFI_DEVICE_ERROR :
		EFI_SUCCESS;
}

static EFI_STATUS uninstall(void *opaque, void *controller,
	struct cdk2_scsi_disk_bound_controller *bound)
{
	struct fixture *fixture = opaque;

	(void)controller; CHECK(bound != NULL); fixture->uninstalls++;
	return fixture->uninstalls == fixture->fail_uninstall ? EFI_DEVICE_ERROR :
		EFI_SUCCESS;
}

static EFI_STATUS signal(void *opaque, void *event)
{
	(void)opaque; (void)event; return EFI_SUCCESS;
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

static void initialize(struct cdk2_scsi_disk_binding *binding,
	struct fixture *fixture)
{
	struct cdk2_scsi_disk_binding_services services = { .context = fixture,
		.open_parent = open_parent, .close_parent = close_parent, .probe = probe,
		.install = install, .uninstall = uninstall, .signal = signal,
		.allocate = allocate, .release = release };

	CHECK(cdk2_scsi_disk_binding_init(binding, &services) == EFI_SUCCESS);
}

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_scsi_disk_binding binding;

	initialize(&binding, &fixture);
	fixture.fail_open = 1U;
	CHECK(cdk2_scsi_disk_binding_start(&binding, (void *)1) == EFI_DEVICE_ERROR &&
		binding.count == 0U && fixture.releases == 1U);
	fixture.fail_open = 0U; fixture.fail_probe = 1U;
	CHECK(cdk2_scsi_disk_binding_start(&binding, (void *)1) == EFI_DEVICE_ERROR &&
		fixture.closes == 1U && fixture.releases == 2U);
	fixture.fail_probe = 0U; fixture.fail_install = 1U;
	fixture.fail_close = fixture.closes + 1U;
	CHECK(cdk2_scsi_disk_binding_start(&binding, (void *)1) == EFI_DEVICE_ERROR &&
		fixture.closes == 2U && fixture.releases == 2U && binding.count == 1U &&
		!binding.controllers[0]->installed);
	fixture.fail_close = 0U;
	CHECK(cdk2_scsi_disk_binding_stop(&binding, (void *)1) == EFI_SUCCESS &&
		binding.count == 0U && fixture.releases == 3U);
	fixture.fail_install = 0U;
	CHECK(cdk2_scsi_disk_binding_start(&binding, (void *)1) == EFI_SUCCESS &&
		cdk2_scsi_disk_binding_start(&binding, (void *)1) == EFI_ALREADY_STARTED &&
		cdk2_scsi_disk_binding_start(&binding, (void *)2) == EFI_SUCCESS &&
		binding.count == 2U);
	{
		UINT8 inquiry[36];
		UINT32 size = 0U;
		UINT8 sense_count = 0xffU;

		CHECK(binding.controllers[0]->disk_info.interface.data1 == 0x08f74baaU &&
			binding.controllers[0]->disk_info.inquiry(
				&binding.controllers[0]->disk_info, NULL, &size) ==
			EFI_BUFFER_TOO_SMALL && size == sizeof(inquiry));
		CHECK(binding.controllers[0]->disk_info.inquiry(
			&binding.controllers[0]->disk_info, inquiry, &size) == EFI_SUCCESS &&
			binding.controllers[0]->disk_info.identify(
				&binding.controllers[0]->disk_info, inquiry, &size) ==
			EFI_NOT_FOUND && binding.controllers[0]->disk_info.sense_data(
				&binding.controllers[0]->disk_info, inquiry, &size,
				&sense_count) == EFI_NOT_FOUND && sense_count == 0U);
	}
	fixture.fail_uninstall = fixture.uninstalls + 1U;
	CHECK(cdk2_scsi_disk_binding_stop(&binding, (void *)1) == EFI_DEVICE_ERROR &&
		binding.count == 2U && binding.controllers[0]->installed &&
		!binding.controllers[0]->async.stopping);
	fixture.fail_uninstall = 0U; fixture.fail_close = fixture.closes + 1U;
	CHECK(cdk2_scsi_disk_binding_stop(&binding, (void *)1) == EFI_DEVICE_ERROR &&
		binding.count == 2U && binding.controllers[0]->installed &&
		!binding.controllers[0]->async.stopping);
	fixture.fail_close = 0U;
	CHECK(cdk2_scsi_disk_binding_stop(&binding, (void *)1) == EFI_SUCCESS &&
		binding.count == 1U && binding.controllers[0]->handle == (void *)2);
	CHECK(cdk2_scsi_disk_binding_stop(&binding, (void *)2) == EFI_SUCCESS &&
		binding.count == 0U && fixture.allocations == fixture.releases);
	puts("scsi disk binding tests: PASS");
	return 0;
}
