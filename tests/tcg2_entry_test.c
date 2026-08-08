/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_entry.h>
#include <stdio.h>
#include <string.h>

const EFI_GUID efi_tcg2_protocol_guid = {
	0x607f766c, 0x7455, 0x42be,
	{ 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }
};
const EFI_GUID efi_tcg2_final_events_table_guid = {
	0x1e2ed096, 0x30e2, 0x4254,
	{ 0xbd, 0x89, 0x86, 0x3b, 0xbe, 0xf8, 0x23, 0x25 }
};

struct mock_context {
	char actions[32];
	UINTN used;
	UINT32 fail_stage;
};

static void record(struct mock_context *mock, char action)
{
	mock->actions[mock->used++] = action;
}

static EFI_STATUS stage(struct mock_context *mock, char action, UINT32 number)
{
	record(mock, action);
	return mock->fail_stage == number ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS register_security(void *context)
{
	return stage(context, 'R', 1);
}

static EFI_STATUS unregister_security(void *context)
{
	record(context, 'U');
	return EFI_SUCCESS;
}

static EFI_STATUS create_variable(void *context, void **event)
{
	*event = (void *)(UINTN)1;
	return stage(context, 'V', 2);
}

static EFI_STATUS register_notify(void *context, void *event)
{
	if (event != (void *)(UINTN)1)
		return EFI_INVALID_PARAMETER;
	return stage(context, 'N', 3);
}

static EFI_STATUS create_exit(void *context, void **event)
{
	*event = (void *)(UINTN)2;
	return stage(context, 'E', 4);
}

static EFI_STATUS close_event(void *context, void *event)
{
	record(context, event == (void *)(UINTN)2 ? 'X' : 'v');
	return EFI_SUCCESS;
}

static EFI_STATUS install_config(void *context, cdk2_const_guid_ptr guid,
	void *interface)
{
	(void)guid;
	if (interface == NULL) {
		record(context, 'c');
		return EFI_SUCCESS;
	}
	return stage(context, 'C', 5);
}

static EFI_STATUS install_protocol(void *context, cdk2_const_guid_ptr guid,
	void *interface)
{
	(void)guid; (void)interface;
	return stage(context, 'P', 6);
}

static void release_service(void *context, struct cdk2_tcg2_service *service)
{
	(void)service;
	record(context, 'F');
}

static const struct cdk2_tcg2_entry_ops ops = {
	.register_security = register_security,
	.unregister_security = unregister_security,
	.create_variable_event = create_variable,
	.register_variable_notify = register_notify,
	.create_exit_event = create_exit,
	.close_event = close_event,
	.install_config = install_config,
	.install_protocol = install_protocol,
	.release_service = release_service,
};

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "tcg2-entry test: %s\n", message);
	return !condition;
}

int main(void)
{
	static const char *const expected[] = {
		"RVNECP", "RF", "RVUF", "RVNvUF", "RVNEvUF",
		"RVNECXvUF", "RVNECPcXvUF",
	};
	struct cdk2_tcg2_service service = {0};
	struct mock_context mock;
	UINT32 failure;
	EFI_STATUS status;
	int failures = 0;

	service.final_table = (void *)(UINTN)0x1000;
	for (failure = 0; failure <= 6; failure++) {
		mock = (struct mock_context){ .fail_stage = failure };
		status = cdk2_tcg2_entry_publish(&service, &mock, &ops);
		failures += expect((failure == 0 && status == EFI_SUCCESS) ||
			(failure != 0 && status == EFI_DEVICE_ERROR),
			"fault status was not preserved");
		failures += expect(strcmp(mock.actions, expected[failure]) == 0,
			"failure did not unwind resources in reverse order exactly once");
	}
	return failures == 0 ? 0 : 1;
}
