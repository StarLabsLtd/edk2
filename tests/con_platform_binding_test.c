/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_platform.h>
#include <stdio.h>

static UINTN opens, closes, installs, uninstalls, updates, fail_install;
static UINT8 path[4];
static EFI_STATUS open_protocol(void *context, void *controller, const EFI_GUID *guid,
	UINT32 attribute, void **interface)
{
	(void)context; (void)controller; (void)guid; opens++;
	if (attribute == CDK2_CON_OPEN_GET) { *interface = path; return EFI_SUCCESS; }
	if (interface != NULL) *interface = path;
	return EFI_SUCCESS;
}
static EFI_STATUS close_protocol(void *context, void *controller, const EFI_GUID *guid)
{ (void)context; (void)controller; (void)guid; closes++; return EFI_SUCCESS; }
static EFI_STATUS install(void *context, void *controller, const EFI_GUID *guid)
{ (void)context; (void)controller; (void)guid; installs++; return installs == fail_install ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS uninstall(void *context, void *controller, const EFI_GUID *guid)
{ (void)context; (void)controller; (void)guid; uninstalls++; return EFI_SUCCESS; }
static EFI_STATUS update(void *context, const CHAR16 *name, const void *device_path,
	UINTN size, enum cdk2_con_variable_operation operation)
{ (void)context; (void)name; (void)device_path; (void)size; updates++; return operation == CDK2_CON_CHECK ? EFI_SUCCESS : EFI_SUCCESS; }
static BOOLEAN gop(void *context, const void *device_path, UINTN size)
{ (void)context; (void)device_path; (void)size; return FALSE; }
static int expect(int value, const char *message)
{ if (!value) fprintf(stderr, "con binding test: %s\n", message); return !value; }

int main(void)
{
	static const struct cdk2_con_binding_ops ops = {
		open_protocol, close_protocol, install, uninstall, update, gop
	};
	struct cdk2_con_binding input = {
		.ops = &ops, .path_size = sizeof(path), .direction = CDK2_CON_INPUT
	};
	struct cdk2_con_binding output = {
		.ops = &ops, .path_size = sizeof(path), .direction = CDK2_CON_OUTPUT
	};
	int failures = 0;

	failures += expect(cdk2_con_binding_supported(&input, path) == EFI_SUCCESS && closes == 1U,
		"Supported leaked protocol ownership");
	failures += expect(cdk2_con_binding_start(&input, path) == EFI_SUCCESS && input.protocol_open &&
		input.input_marker && cdk2_con_binding_stop(&input) == EFI_SUCCESS && closes == 2U,
		"input lifecycle was not symmetric");
	fail_install = installs + 2U;
	failures += expect(cdk2_con_binding_start(&output, path) == EFI_DEVICE_ERROR &&
		!output.protocol_open && !output.output_marker && uninstalls != 0U,
		"failed output marker publication leaked ownership");
	fail_install = 0U;
	failures += expect(cdk2_con_binding_start(&output, path) == EFI_SUCCESS &&
		output.output_marker && output.error_marker &&
		cdk2_con_binding_stop(&output) == EFI_SUCCESS && updates >= 10U,
		"output lifecycle did not manage console variables and markers");
	return failures == 0 ? 0 : 1;
}
