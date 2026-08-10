/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_bus_binding.h>
#include <stdio.h>
#include <stdlib.h>

static UINTN closes;
static BOOLEAN fail_child_open;
static BOOLEAN fail_uninstall;
static struct cdk2_device_path end_path = { 0x7f, 0xff, { 4, 0 } };
static struct cdk2_device_path child_node = { 3, 0x12, { 4, 0 } };
static struct cdk2_ext_scsi_mode pass_mode = { 0, 3, 8 };
static struct cdk2_ext_scsi pass;
static UINT8 next_id[CDK2_SCSI_TARGET_MAX] = { 2, 0xff };
static UINTN next_cursor;

static EFI_STATUS CDK2_MS_ABI pass_command(struct cdk2_ext_scsi *interface,
	UINT8 *target, UINT64 lun, struct cdk2_scsi_request *packet, void *event)
{
	(void)interface; (void)target; (void)lun; (void)event;
	if (packet->cdb_length != 6 || ((UINT8 *)packet->cdb)[0] != 0x12 ||
	    packet->in_length < 36)
		return EFI_DEVICE_ERROR;
	((UINT8 *)packet->in_data)[0] = 0;
	packet->host_status = 0; packet->target_status = 0;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_target(struct cdk2_ext_scsi *interface,
	struct cdk2_device_path *path, UINT8 **target, UINT64 *lun)
{
	(void)interface; (void)path;
	for (UINTN index = 0; index < CDK2_SCSI_TARGET_MAX; index++)
		(*target)[index] = index == 0 ? 1 : 0;
	*lun = 0; return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_next(struct cdk2_ext_scsi *interface,
	UINT8 **target, UINT64 *lun)
{
	(void)interface;
	if (target == NULL || *target == NULL)
		return EFI_INVALID_PARAMETER;
	if (next_cursor == 0U) {
		for (UINTN index = 0; index < CDK2_SCSI_TARGET_MAX; index++)
			if ((*target)[index] != 0xffU)
				return EFI_INVALID_PARAMETER;
		*target = next_id; *lun = 0; next_cursor++;
		return EFI_SUCCESS;
	}
	if (*target != next_id)
		return EFI_INVALID_PARAMETER;
	next_cursor = 0; return EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI build_path(struct cdk2_ext_scsi *interface,
	UINT8 *target, UINT64 lun, struct cdk2_device_path **path)
{
	(void)interface; (void)target; (void)lun;
	*path = malloc(sizeof(child_node));
	if (*path == NULL)
		return EFI_OUT_OF_RESOURCES;
	**path = child_node; return EFI_SUCCESS;
}

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

static EFI_STATUS open_good(void *context, void *controller, const EFI_GUID *protocol,
	void **interface, void *agent, void *child, UINT32 attributes)
{
	(void)context; (void)controller; (void)agent; (void)child; (void)attributes;
	if (attributes == CDK2_OPEN_BY_CHILD_CONTROLLER && fail_child_open)
		return EFI_DEVICE_ERROR;
	*interface = protocol->data1 == cdk2_device_path_guid.data1 ?
		(void *)&end_path : (void *)&pass;
	return EFI_SUCCESS;
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
	*handle = (void *)9;
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
	return fail_uninstall ? EFI_DEVICE_ERROR : EFI_SUCCESS;
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
	struct cdk2_device_path target_path = { 3, 0x12, { 4, 0 } };
	void *child;
	UINT8 type = 0xff;

	pass = (struct cdk2_ext_scsi) {
		.pass_thru = pass_command,
		.get_next_target_lun = get_next,
		.build_device_path = build_path,
		.get_target_lun = get_target,
		.mode = &pass_mode,
	};

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
	ops.open = open_good;
	cdk2_scsi_binding_init(&binding, &ops, NULL, (void *)1);
	failures += check(cdk2_scsi_binding_start(&binding, (void *)2, &target_path) ==
		EFI_SUCCESS && binding.children != NULL,
		"targeted start discovers and publishes the child");
	if (binding.children != NULL) {
		struct cdk2_device_path *published_end = (void *)
			((UINT8 *)binding.children->path + sizeof(child_node));

		child = binding.children->handle;
		failures += check(binding.children->path->type == child_node.type &&
			published_end->type == 0x7f && published_end->subtype == 0xff,
			"single producer node is published with a fresh End node");
		failures += check(binding.children->io.get_device_type(
			&binding.children->io, &type) == EFI_SUCCESS && type == 0,
			"INQUIRY publishes the discovered direct-access type");
		failures += check(cdk2_scsi_binding_stop(&binding, (void *)2, 1,
			&child) == EFI_SUCCESS && cdk2_scsi_binding_stop(&binding,
			(void *)2, 0, NULL) == EFI_SUCCESS,
			"child and parent ownership stop cleanly");
	}
	cdk2_scsi_binding_init(&binding, &ops, NULL, (void *)1);
	fail_child_open = FALSE; next_cursor = 0;
	failures += check(cdk2_scsi_binding_start(&binding, (void *)2, NULL) ==
		EFI_SUCCESS && binding.children != NULL,
		"full scan uses the all-ones initial target contract");
	if (binding.children != NULL) {
		child = binding.children->handle;
		failures += check(cdk2_scsi_binding_stop(&binding, (void *)2, 1,
			&child) == EFI_SUCCESS && cdk2_scsi_binding_stop(&binding,
			(void *)2, 0, NULL) == EFI_SUCCESS,
			"enumerated child stops cleanly");
	}
	cdk2_scsi_binding_init(&binding, &ops, NULL, (void *)1);
	fail_child_open = TRUE; fail_uninstall = TRUE;
	failures += check(cdk2_scsi_binding_start(&binding, (void *)2, &target_path) ==
		EFI_DEVICE_ERROR && binding.children != NULL &&
		binding.children->installed && !binding.children->by_child,
		"failed BY_CHILD rollback retains installed child ownership");
	if (binding.children != NULL) {
		child = binding.children->handle; fail_uninstall = FALSE;
		failures += check(cdk2_scsi_binding_stop(&binding, (void *)2, 1,
			&child) == EFI_SUCCESS && cdk2_scsi_binding_stop(&binding,
			(void *)2, 0, NULL) == EFI_SUCCESS,
			"retained rollback child is removable on retry");
	}
	return failures != 0;
}
