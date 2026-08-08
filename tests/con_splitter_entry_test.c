/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter_entry.h>
#include <stdarg.h>
#include <stdio.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINTN, UINTN, void **);
typedef void CDK2_MS_ABI event_notify_fn(void *, void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN, event_notify_fn *,
	void *, void **);
typedef EFI_STATUS CDK2_MS_ABI event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_protocol_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_protocol_fn(void *, const EFI_GUID *, void *,
	void *);
typedef event_notify_fn * event_notify_ptr;
typedef const EFI_GUID * guid_ptr;
struct boot_services_view {
	UINT8 header[24];
	void *first_five[5];
	allocate_pool_fn *allocate_pool;
	void *free_pool;
	create_event_fn *create_event;
	void *set_timer, *wait_for_event;
	event_fn *signal_event, *close_event, *check_event;
	void *through_disconnect[19];
	open_protocol_fn *open_protocol;
	close_protocol_fn *close_protocol;
	void *through_locate_protocol[4];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct cdk2_split_system_table {
	UINT8 header[24];
	CHAR16 *vendor;
	UINT32 revision, padding;
	void *input_handle; struct cdk2_split_text_in_protocol *input;
	void *output_handle; struct cdk2_split_text_out_protocol *output;
	void *error_handle; struct cdk2_split_text_out_protocol *error;
	void *runtime; struct boot_services_view *boot;
};
static UINTN installs, uninstalls, fail_at, fail_event;
static UINTN events, event_closes, event_signals;
static void *event_handles[4];
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{
	installs++;
	if (*handle == NULL)
		*handle = (void *)(installs + 10U);
	return installs == fail_at ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{ if (handle == NULL) return EFI_INVALID_PARAMETER; uninstalls++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	event_notify_ptr notify,
	void *context,
	void **event)
{
	(void)context;
	if (type != 0x100U || tpl != 16U || notify == NULL)
		return EFI_INVALID_PARAMETER;
	events++;
	if (events == fail_event)
		return EFI_DEVICE_ERROR;
	*event = (void *)(events + 100U);
	(void)context;
	event_handles[events - 1U] = *event;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI signal_event(void *event)
{ if (event == NULL) return EFI_INVALID_PARAMETER; event_signals++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{ if (event == NULL) return EFI_INVALID_PARAMETER; event_closes++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI check_event(void *event)
{ return event == (void *)999 ? EFI_SUCCESS : EFI_NOT_READY; }
static EFI_STATUS CDK2_MS_ABI open_protocol(void *controller,
	guid_ptr protocol,
	void **interface,
	void *agent, void *child,
	UINT32 attributes)
{
	(void)controller; (void)protocol; (void)interface; (void)agent; (void)child;
	(void)attributes; return EFI_UNSUPPORTED;
}
static EFI_STATUS CDK2_MS_ABI close_protocol(void *controller,
	guid_ptr protocol,
	void *agent, void *child)
{
	(void)controller; (void)protocol; (void)agent; (void)child;
	return EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "con splitter entry test: %s\n", message); return !condition; }

int main(void)
{
	struct boot_services_view boot = { .install_multiple = install,
		.uninstall_multiple = uninstall, .create_event = create_event,
		.signal_event = signal_event, .close_event = close_event,
		.check_event = check_event, .open_protocol = open_protocol,
		.close_protocol = close_protocol };
	struct cdk2_split_system_table system = { .boot = &boot };
	UINTN columns, rows, index;
	int failures = 0;

	failures += expect(cdk2_con_splitter_entry((void *)1, &system) == EFI_SUCCESS &&
		installs == 12U && system.input != NULL && system.output != NULL &&
		system.error != NULL, "virtual console protocols were not published");
	failures += expect(system.output->query(system.output, 0U, &columns, &rows) ==
		EFI_SUCCESS && columns == 80U && rows == 25U &&
		system.output->output(system.output, L"A") == EFI_SUCCESS &&
		system.output->mode->cursor_column == 1,
		"virtual SimpleTextOut ABI did not delegate to the model");
	{
		void *physical_events[] = { (void *)998, (void *)999 };
		failures += expect(cdk2_split_wait_poll(event_handles[0], physical_events,
			2U, check_event, signal_event) == EFI_SUCCESS && event_signals == 1U,
			"physical wait event did not signal the virtual wait event");
	}
	for (index = 1; index <= 12; index++) {
		installs = uninstalls = events = 0U; fail_at = index;
		failures += expect(cdk2_con_splitter_entry((void *)1, &system) ==
			EFI_DEVICE_ERROR && uninstalls == index - 1U,
			"partial virtual protocol publication was not rolled back");
	}
	for (index = 1; index <= 4; index++) {
		installs = uninstalls = events = event_closes = 0U;
		fail_at = 0U; fail_event = index;
		failures += expect(cdk2_con_splitter_entry((void *)1, &system) ==
			EFI_DEVICE_ERROR && installs == 0U && event_closes == index - 1U,
			"partial virtual wait-event creation was not rolled back");
	}
	return failures == 0 ? 0 : 1;
}
