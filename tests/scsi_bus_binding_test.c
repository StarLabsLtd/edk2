/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_bus_binding.h>
#include <stdio.h>
#include <stdlib.h>

static UINTN closes;
static struct cdk2_device_path end_path = { 0x7f, 0xff, { 4, 0 } };

static EFI_STATUS open_fault(void *context, void *controller, const EFI_GUID *protocol,
	void **interface, void *agent, void *child, UINT32 attributes)
{
	(void)context;
	(void)controller;
	(void)agent;
	(void)child;
	(void)attributes;
	if (protocol->data1 == cdk2_device_path_guid.data1) {
		*interface = &end_path;
		return EFI_SUCCESS;
	}
	return EFI_DEVICE_ERROR;
}

static EFI_STATUS close_ok(void *context, void *controller, const EFI_GUID *protocol,
	void *agent, void *child)
{
	(void)context;
	(void)controller;
	(void)protocol;
	(void)agent;
	(void)child;
	closes++;
	return EFI_SUCCESS;
}

static EFI_STATUS install_unused(void *context, void **handle, const EFI_GUID *first,
	void *first_interface, const EFI_GUID *second, void *second_interface)
{
	(void)context;
	(void)handle;
	(void)first;
	(void)first_interface;
	(void)second;
	(void)second_interface;
	return EFI_SUCCESS;
}

static EFI_STATUS uninstall_unused(void *context, void *handle, const EFI_GUID *first,
	void *first_interface, const EFI_GUID *second, void *second_interface)
{
	(void)context;
	(void)handle;
	(void)first;
	(void)first_interface;
	(void)second;
	(void)second_interface;
	return EFI_SUCCESS;
}

static EFI_STATUS allocate_ok(void *context, UINTN size, void **buffer)
{
	(void)context;
	*buffer = malloc(size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static void free_ok(void *context, void *buffer)
{
	(void)context;
	free(buffer);
}

static int check(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "scsi binding: %s\n", message);
	return !condition;
}

int main(void)
{
	struct cdk2_scsi_binding binding;
	struct cdk2_scsi_binding_ops ops = { open_fault, close_ok, install_unused,
		uninstall_unused, NULL, allocate_ok, free_ok, NULL };
	int failures = 0;

	cdk2_scsi_binding_init(&binding, &ops, NULL, (void *)1);
	failures += check(sizeof(struct cdk2_scsi_io) == 6U * sizeof(void *),
		"EFI_SCSI_IO protocol ABI size");
	failures += check(offsetof(struct cdk2_scsi_io, io_align) == 5U * sizeof(void *),
		"IoAlign is after all five methods");
	failures += check(offsetof(struct cdk2_scsi_request, cdb_length) == 48U,
		"request packet field layout");
	failures += check(binding.driver.version == 0x0aU &&
		binding.driver.supported != NULL && binding.driver.start != NULL &&
		binding.driver.stop != NULL, "DriverBinding initialization");
	failures += check(binding.component_name.supported_languages[2] == 'g' &&
		binding.component_name2.supported_languages[2] == '\0',
		"ComponentName language sets");
	failures += check(cdk2_scsi_binding_start(&binding, (void *)2, NULL) ==
		EFI_DEVICE_ERROR && closes == 1U,
		"failed pass-through open rolls back the device-path open");
	return failures != 0;
}
