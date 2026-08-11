/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter_entry.h>
#include <cdk2/con_splitter_binding.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI calculate_crc32_fn(void *, UINTN, UINT32 *);
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
typedef UINT8 * uint8_ptr;
typedef struct cdk2_split_key_data *key_data_ptr;
typedef cdk2_split_key_notify_fn * key_notify_ptr;
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
	calculate_crc32_fn *calculate_crc32;
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
static UINTN crc_calls;
static void *event_handles[4];
static struct cdk2_split_driver_binding *drivers[5];
static struct cdk2_split_text_in_ex_protocol *virtual_ex;
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{
	__builtin_ms_va_list arguments;
	void *guid, *interface;

	installs++;
	__builtin_ms_va_start(arguments, handle);
	guid = __builtin_va_arg(arguments, void *);
	interface = __builtin_va_arg(arguments, void *);
	__builtin_ms_va_end(arguments);
	(void)guid;
	if (installs >= 8U && installs <= 12U)
		drivers[installs - 8U] = interface;
	if (installs == 3U)
		virtual_ex = interface;
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
static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{ (void)type; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI calculate_crc32(void *data, UINTN size, UINT32 *crc)
{ if (data == NULL || size != 24U || crc == NULL) return EFI_INVALID_PARAMETER; crc_calls++; *crc = 0x12345678U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{ free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_input_reset(
	struct cdk2_split_text_in_protocol *protocol, BOOLEAN extended)
{ (void)protocol; (void)extended; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_input_read(
	struct cdk2_split_text_in_protocol *protocol,
	struct cdk2_split_input_key *key)
{ (void)protocol; (void)key; return EFI_NOT_READY; }
static struct cdk2_split_text_in_protocol physical_input = {
	physical_input_reset, physical_input_read, (void *)999
};
static UINTN ex_sets, ex_registers, ex_unregisters, ex_opens, ex_closes;
static BOOLEAN fail_ex_register, fail_gop_close;
static EFI_STATUS CDK2_MS_ABI physical_ex_reset(
	struct cdk2_split_text_in_ex_protocol *protocol, BOOLEAN extended)
{ (void)protocol; (void)extended; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_ex_read(
	struct cdk2_split_text_in_ex_protocol *protocol,
	struct cdk2_split_key_data *key)
{ (void)protocol; *key = (struct cdk2_split_key_data) { { 0U, L'X' }, { 2U, 4U } }; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_ex_set(
	struct cdk2_split_text_in_ex_protocol *protocol, uint8_ptr state)
{ (void)protocol; (void)state; ex_sets++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_ex_register(
	struct cdk2_split_text_in_ex_protocol *protocol,
	key_data_ptr key, key_notify_ptr notify,
	void **handle)
{
	(void)protocol; (void)key; (void)notify; ex_registers++;
	if (fail_ex_register)
		return EFI_DEVICE_ERROR;
	*handle = (void *)77; return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI physical_ex_unregister(
	struct cdk2_split_text_in_ex_protocol *protocol, void *handle)
{ (void)protocol; (void)handle; ex_unregisters++; return EFI_SUCCESS; }
static struct cdk2_split_text_in_ex_protocol physical_ex = {
	physical_ex_reset, physical_ex_read, (void *)999, physical_ex_set,
	physical_ex_register, physical_ex_unregister
};
static struct cdk2_split_text_out_mode physical_text_mode = { 1, 0, 7, 0, 0, TRUE };
static EFI_STATUS CDK2_MS_ABI physical_text_reset(
	struct cdk2_split_text_out_protocol *protocol, BOOLEAN extended)
{ (void)protocol; (void)extended; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_text_string(
	struct cdk2_split_text_out_protocol *protocol, CHAR16 *string)
{ (void)protocol; (void)string; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_text_query(
	struct cdk2_split_text_out_protocol *protocol, UINTN mode,
	UINTN *columns, UINTN *rows)
{ (void)protocol; if (mode != 0U) return EFI_UNSUPPORTED; *columns = 80U; *rows = 25U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_text_value(
	struct cdk2_split_text_out_protocol *protocol, UINTN value)
{ (void)protocol; (void)value; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_text_clear(
	struct cdk2_split_text_out_protocol *protocol)
{ (void)protocol; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_text_cursor(
	struct cdk2_split_text_out_protocol *protocol, UINTN column, UINTN row)
{ (void)protocol; (void)column; (void)row; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_text_visible(
	struct cdk2_split_text_out_protocol *protocol, BOOLEAN visible)
{ (void)protocol; (void)visible; return EFI_SUCCESS; }
static struct cdk2_split_text_out_protocol physical_text = {
	physical_text_reset, physical_text_string, physical_text_string,
	physical_text_query, physical_text_value, physical_text_value,
	physical_text_clear, physical_text_cursor, physical_text_visible,
	&physical_text_mode
};
static struct cdk2_split_gop_mode_info physical_gop_info = {
	.horizontal_resolution = 800U, .vertical_resolution = 600U,
	.pixel_format = 1U, .pixels_per_scan_line = 800U
};
static struct cdk2_split_gop_protocol_mode physical_gop_mode = {
	.max_mode = 1U, .info = &physical_gop_info,
	.size_of_info = sizeof(physical_gop_info)
};
static EFI_STATUS CDK2_MS_ABI physical_gop_query(
	struct cdk2_split_gop_protocol *protocol, UINT32 mode, UINTN *size,
	struct cdk2_split_gop_mode_info **information)
{ (void)protocol; if (mode != 0U) return EFI_UNSUPPORTED; *size = sizeof(**information); *information = malloc(*size); **information = physical_gop_info; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_gop_set(
	struct cdk2_split_gop_protocol *protocol, UINT32 mode)
{ (void)protocol; (void)mode; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI physical_gop_blt(
	struct cdk2_split_gop_protocol *protocol, void *buffer, UINTN operation,
	UINTN sx, UINTN sy, UINTN dx, UINTN dy, UINTN width, UINTN height, UINTN delta)
{ (void)protocol; (void)buffer; (void)operation; (void)sx; (void)sy; (void)dx; (void)dy; (void)width; (void)height; (void)delta; return EFI_SUCCESS; }
static struct cdk2_split_gop_protocol physical_gop = {
	physical_gop_query, physical_gop_set, physical_gop_blt, &physical_gop_mode
};
static UINTN gop_opens, gop_closes;
static EFI_STATUS CDK2_MS_ABI open_protocol(void *controller,
	guid_ptr protocol,
	void **interface,
	void *agent, void *child,
	UINT32 attributes)
{
	(void)controller; (void)agent; (void)child;
	if (attributes != CDK2_CON_SPLITTER_OPEN_BY_DRIVER)
		return EFI_INVALID_PARAMETER;
	if (protocol->data1 == 0x387477c1U) {
		*interface = &physical_input;
	} else if (protocol->data1 == 0xdd9e7534U) {
		*interface = &physical_ex;
		ex_opens++;
	} else if (protocol->data1 == 0x387477c2U) {
		*interface = &physical_text;
	} else if (protocol->data1 == 0x9042a9deU) {
		*interface = &physical_gop;
		gop_opens++;
	} else {
		return EFI_UNSUPPORTED;
	}
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI close_protocol(void *controller,
	guid_ptr protocol,
	void *agent, void *child)
{
	(void)controller; (void)agent; (void)child;
	if (protocol->data1 == 0xdd9e7534U)
		ex_closes++;
	if (protocol->data1 == 0x9042a9deU) {
		gop_closes++;
		if (fail_gop_close)
			return EFI_DEVICE_ERROR;
	}
	return EFI_SUCCESS;
}
static UINTN notifications;
static EFI_STATUS notified(struct cdk2_split_key_data *key)
{ notifications++; return key->key.unicode == L'X' ? EFI_SUCCESS : EFI_DEVICE_ERROR; }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "con splitter entry test: %s\n", message); return !condition; }

int main(void)
{
	struct boot_services_view boot = { .install_multiple = install,
		.uninstall_multiple = uninstall, .allocate_pool = allocate_pool,
		.free_pool = free_pool, .create_event = create_event,
		.signal_event = signal_event, .close_event = close_event,
		.check_event = check_event, .open_protocol = open_protocol,
		.close_protocol = close_protocol, .calculate_crc32 = calculate_crc32 };
	struct cdk2_split_system_table system = { .boot = &boot };
	UINTN columns, rows, index;
	struct cdk2_split_key_data ex_key = { 0 };
	struct cdk2_split_key_data match = { .key = { 0U, L'X' } };
	void *notify_handle;
	UINT8 toggle = 4U;
	int failures = 0;
	*(UINT32 *)&system.header[12] = 24U;

	failures += expect(cdk2_con_splitter_entry((void *)1, &system) == EFI_SUCCESS &&
		installs == 12U && system.input != NULL && system.output != NULL &&
		system.error != NULL && crc_calls == 1U &&
		*(UINT32 *)&system.header[16] == 0x12345678U,
		"virtual console protocols or SystemTable CRC were not published");
	failures += expect(system.output->query(system.output, 0U, &columns, &rows) ==
		EFI_SUCCESS && columns == 80U && rows == 25U &&
		system.output->output(system.output, L"A") == EFI_SUCCESS &&
		system.output->mode->cursor_column == 1,
		"virtual SimpleTextOut ABI did not delegate to the model");
	failures += expect(drivers[0] != NULL && drivers[0]->start(drivers[0],
		(void *)55, NULL) == EFI_SUCCESS &&
		virtual_ex != NULL && virtual_ex->set_state(virtual_ex, &toggle) ==
			EFI_SUCCESS && ex_sets == 1U &&
		virtual_ex->register_notify(virtual_ex, &match, notified,
			&notify_handle) == EFI_SUCCESS && ex_registers == 1U &&
		virtual_ex->read(virtual_ex, &ex_key) == EFI_SUCCESS &&
		ex_key.state.shift_state == 2U && notifications == 1U &&
		virtual_ex->unregister_notify(virtual_ex, notify_handle) == EFI_SUCCESS &&
		ex_unregisters == 1U,
		"ConIn did not forward physical TextInEx state and notifications");
	failures += expect(drivers[0]->stop(drivers[0], (void *)55, 0U, NULL) ==
		EFI_SUCCESS && ex_opens == 1U && ex_closes == 1U,
		"ConIn Stop did not release physical TextInEx ownership");
	failures += expect(virtual_ex->register_notify(virtual_ex, &match, notified,
		&notify_handle) == EFI_SUCCESS, "virtual notification setup failed");
	fail_ex_register = TRUE;
	failures += expect(drivers[0]->start(drivers[0], (void *)56, NULL) ==
		EFI_DEVICE_ERROR && ex_closes == 2U,
		"physical TextInEx notification failure did not roll back Start");
	fail_ex_register = FALSE;
	failures += expect(virtual_ex->unregister_notify(virtual_ex, notify_handle) ==
		EFI_SUCCESS, "virtual notification cleanup failed");
	failures += expect(drivers[3] != NULL && drivers[3]->start(drivers[3],
		(void *)66, NULL) == EFI_SUCCESS && gop_opens == 1U,
		"ConOut did not co-open physical GOP");
	fail_gop_close = TRUE;
	failures += expect(drivers[3]->stop(drivers[3], (void *)66, 0U, NULL) ==
		EFI_DEVICE_ERROR, "GOP close failure did not preserve ownership");
	fail_gop_close = FALSE;
	failures += expect(drivers[3]->stop(drivers[3], (void *)66, 0U, NULL) ==
		EFI_SUCCESS && gop_closes == 2U,
		"ConOut did not release physical GOP after retry");
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
