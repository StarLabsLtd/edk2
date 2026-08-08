/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_splitter_entry.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
struct boot_services_view {
	UINT8 header[24];
	void *slots[38];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct cdk2_split_system_table {
	UINT8 header[24];
	CHAR16 *firmware_vendor;
	UINT32 firmware_revision, padding;
	void *console_in_handle;
	struct cdk2_split_text_in_protocol *con_in;
	void *console_out_handle;
	struct cdk2_split_text_out_protocol *con_out;
	void *standard_error_handle;
	struct cdk2_split_text_out_protocol *standard_error;
	void *runtime;
	struct boot_services_view *boot;
};
struct splitter_entry {
	struct cdk2_split_text_in input_model;
	struct cdk2_split_pointer pointer_model;
	struct cdk2_split_absolute absolute_model;
	struct cdk2_split_text_out output_model, error_model;
	struct cdk2_split_text_in_protocol input;
	struct cdk2_split_text_out_protocol output, error;
	struct cdk2_split_pointer_protocol pointer;
	struct cdk2_split_absolute_protocol absolute;
	struct cdk2_split_pointer_mode pointer_mode;
	struct cdk2_split_absolute_mode absolute_mode;
	struct cdk2_split_text_out_mode output_mode, error_mode;
	struct boot_services_view *boot;
	void *input_handle, *output_handle, *error_handle;
	void *pointer_handle, *absolute_handle;
};
static struct splitter_entry entry;
static const EFI_GUID text_in_guid = { 0x387477c1, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID text_out_guid = { 0x387477c2, 0x69c7, 0x11d2,
	{ 0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const EFI_GUID pointer_guid = { 0x31878c87, 0x0b75, 0x11d5,
	{ 0x9a, 0x4f, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID absolute_guid = { 0x8d59d32b, 0xc655, 0x4ae9,
	{ 0x9b, 0x15, 0xf2, 0x59, 0x04, 0x99, 0x2a, 0x43 } };

static struct cdk2_split_text_out *output_model(
	struct cdk2_split_text_out_protocol *protocol)
{
	return protocol == &entry.output ? &entry.output_model : &entry.error_model;
}

static struct cdk2_split_text_out_mode *output_mode(
	struct cdk2_split_text_out_protocol *protocol)
{
	return protocol == &entry.output ? &entry.output_mode : &entry.error_mode;
}

static void sync_mode(struct cdk2_split_text_out_protocol *protocol)
{
	struct cdk2_split_text_out *model = output_model(protocol);
	struct cdk2_split_text_out_mode *mode = output_mode(protocol);

	mode->max_mode = (INT32)model->mode_count;
	mode->mode = (INT32)model->mode;
	mode->attribute = (INT32)model->attribute;
	mode->cursor_column = (INT32)model->column;
	mode->cursor_row = (INT32)model->row;
	mode->cursor_visible = model->cursor_visible;
}

static EFI_STATUS CDK2_MS_ABI text_reset(struct cdk2_split_text_out_protocol *protocol,
	BOOLEAN extended)
{
	EFI_STATUS status;
	(void)extended;
	status = cdk2_split_text_out_set_attribute(output_model(protocol), 7U);
	if (!EFI_ERROR(status))
		status = cdk2_split_text_out_clear(output_model(protocol));
	sync_mode(protocol);
	return status;
}
static EFI_STATUS CDK2_MS_ABI text_output(struct cdk2_split_text_out_protocol *protocol,
	CHAR16 *string)
{ EFI_STATUS status = cdk2_split_text_out_output(output_model(protocol), string); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_test(struct cdk2_split_text_out_protocol *protocol,
	CHAR16 *string)
{ return cdk2_split_text_out_test(output_model(protocol), string); }
static EFI_STATUS CDK2_MS_ABI text_query(struct cdk2_split_text_out_protocol *protocol,
	UINTN mode, UINTN *columns, UINTN *rows)
{ return cdk2_split_text_out_query_mode(output_model(protocol), mode, columns, rows); }
static EFI_STATUS CDK2_MS_ABI text_set_mode(struct cdk2_split_text_out_protocol *protocol,
	UINTN mode)
{ EFI_STATUS status = cdk2_split_text_out_set_mode(output_model(protocol), mode); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_attribute(struct cdk2_split_text_out_protocol *protocol,
	UINTN attribute)
{ EFI_STATUS status = cdk2_split_text_out_set_attribute(output_model(protocol), attribute); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_clear(struct cdk2_split_text_out_protocol *protocol)
{ EFI_STATUS status = cdk2_split_text_out_clear(output_model(protocol)); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_cursor(struct cdk2_split_text_out_protocol *protocol,
	UINTN column, UINTN row)
{ EFI_STATUS status = cdk2_split_text_out_set_cursor(output_model(protocol), column, row); sync_mode(protocol); return status; }
static EFI_STATUS CDK2_MS_ABI text_visible(struct cdk2_split_text_out_protocol *protocol,
	BOOLEAN visible)
{ EFI_STATUS status = cdk2_split_text_out_enable_cursor(output_model(protocol), visible); sync_mode(protocol); return status; }

static EFI_STATUS CDK2_MS_ABI input_reset(struct cdk2_split_text_in_protocol *protocol,
	BOOLEAN extended)
{ (void)protocol; return cdk2_split_text_in_reset(&entry.input_model, extended); }
static EFI_STATUS CDK2_MS_ABI input_read(struct cdk2_split_text_in_protocol *protocol,
	struct cdk2_split_input_key *key)
{
	(void)protocol;
	return cdk2_split_text_in_read(&entry.input_model, (struct cdk2_split_key *)key);
}

static EFI_STATUS CDK2_MS_ABI pointer_reset(
	struct cdk2_split_pointer_protocol *protocol, BOOLEAN extended)
{
	(void)protocol;
	(void)extended;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI pointer_get_state(
	struct cdk2_split_pointer_protocol *protocol,
	struct cdk2_split_pointer_state *state)
{
	(void)protocol;
	return cdk2_split_pointer_get_state(&entry.pointer_model, state);
}

static EFI_STATUS CDK2_MS_ABI absolute_reset(
	struct cdk2_split_absolute_protocol *protocol, BOOLEAN extended)
{
	(void)protocol;
	(void)extended;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI absolute_get_state(
	struct cdk2_split_absolute_protocol *protocol,
	struct cdk2_split_absolute_state *state)
{
	(void)protocol;
	return cdk2_split_absolute_get_state(&entry.absolute_model, state);
}

static void prepare_output(struct cdk2_split_text_out_protocol *protocol,
	struct cdk2_split_text_out_mode *mode)
{
	*protocol = (struct cdk2_split_text_out_protocol) {
		text_reset, text_output, text_test, text_query, text_set_mode, text_attribute,
		text_clear, text_cursor, text_visible, mode
	};
}

EFI_STATUS CDK2_MS_ABI cdk2_con_splitter_entry(void *image,
	struct cdk2_split_system_table *system)
{
	EFI_STATUS status;

	if (image == NULL || system == NULL || system->boot == NULL ||
	    system->boot->install_multiple == NULL || system->boot->uninstall_multiple == NULL)
		return EFI_INVALID_PARAMETER;
	__builtin_memset(&entry, 0, sizeof(entry));
	entry.boot = system->boot;
	(void)cdk2_split_text_out_init(&entry.output_model, 80U, 25U);
	(void)cdk2_split_text_out_init(&entry.error_model, 80U, 25U);
	entry.input = (struct cdk2_split_text_in_protocol) { input_reset, input_read, NULL };
	entry.pointer = (struct cdk2_split_pointer_protocol) {
		pointer_reset, pointer_get_state, NULL, &entry.pointer_mode
	};
	entry.absolute = (struct cdk2_split_absolute_protocol) {
		absolute_reset, absolute_get_state, NULL, &entry.absolute_mode
	};
	prepare_output(&entry.output, &entry.output_mode);
	prepare_output(&entry.error, &entry.error_mode);
	sync_mode(&entry.output);
	sync_mode(&entry.error);
	status = entry.boot->install_multiple(&entry.input_handle, &text_in_guid,
		&entry.input, NULL);
	if (EFI_ERROR(status))
		return status;
	status = entry.boot->install_multiple(&entry.output_handle, &text_out_guid,
		&entry.output, NULL);
	if (EFI_ERROR(status))
		goto rollback_input;
	status = entry.boot->install_multiple(&entry.error_handle, &text_out_guid,
		&entry.error, NULL);
	if (EFI_ERROR(status))
		goto rollback_output;
	status = entry.boot->install_multiple(&entry.pointer_handle, &pointer_guid,
		&entry.pointer, NULL);
	if (EFI_ERROR(status))
		goto rollback_error;
	status = entry.boot->install_multiple(&entry.absolute_handle, &absolute_guid,
		&entry.absolute, NULL);
	if (EFI_ERROR(status))
		goto rollback_pointer;
	system->console_in_handle = entry.input_handle;
	system->con_in = &entry.input;
	system->console_out_handle = entry.output_handle;
	system->con_out = &entry.output;
	system->standard_error_handle = entry.error_handle;
	system->standard_error = &entry.error;
	return EFI_SUCCESS;

rollback_pointer:
	(void)entry.boot->uninstall_multiple(entry.pointer_handle, &pointer_guid,
		&entry.pointer, NULL);
rollback_error:
	(void)entry.boot->uninstall_multiple(entry.error_handle, &text_out_guid,
		&entry.error, NULL);

rollback_output:
	(void)entry.boot->uninstall_multiple(entry.output_handle, &text_out_guid,
		&entry.output, NULL);
rollback_input:
	(void)entry.boot->uninstall_multiple(entry.input_handle, &text_in_guid,
		&entry.input, NULL);
	return status;
}
