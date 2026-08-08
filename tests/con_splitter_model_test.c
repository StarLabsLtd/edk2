/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter.h>
#include <stdio.h>

static UINTN calls;
static EFI_STATUS statuses[2];
static UINTN last_value, last_column, last_row;
static BOOLEAN last_visible;
static EFI_STATUS output(void *context, const CHAR16 *string)
{
	UINTN index = (UINTN)context - 1U;
	if (string == NULL)
		return EFI_INVALID_PARAMETER;
	calls++;
	return statuses[index];
}
static EFI_STATUS query(void *context, UINTN mode, UINTN *columns, UINTN *rows)
{ (void)context; (void)mode; *columns = 80; *rows = 25; return EFI_SUCCESS; }
static EFI_STATUS value(void *context, UINTN value)
{ (void)context; last_value = value; return EFI_SUCCESS; }
static EFI_STATUS clear(void *context)
{ (void)context; return EFI_SUCCESS; }
static EFI_STATUS cursor(void *context, UINTN column, UINTN row)
{ (void)context; last_column = column; last_row = row; return EFI_SUCCESS; }
static EFI_STATUS visible(void *context, BOOLEAN enabled)
{ (void)context; last_visible = enabled; return EFI_SUCCESS; }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "con splitter model test: %s\n", message); return !condition; }

int main(void)
{
	static const struct cdk2_split_text_out_ops ops = {
		output, output, query, value, value, clear, cursor, visible
	};
	struct cdk2_split_text_out splitter;
	int failures = 0;

	failures += expect(cdk2_split_text_out_init(&splitter, 2U, 2U) == EFI_SUCCESS,
		"initialization failed");
	failures += expect(cdk2_split_text_out_output(&splitter, L"abc\b\r\n") == EFI_SUCCESS &&
		splitter.column == 0U && splitter.row == 1U, "device-null cursor model diverged");
	failures += expect(cdk2_split_text_out_add(&splitter, &ops, (void *)1) == EFI_SUCCESS &&
		cdk2_split_text_out_add(&splitter, &ops, (void *)2) == EFI_SUCCESS &&
		cdk2_split_text_out_add(&splitter, &ops, (void *)1) ==
		CDK2_CON_SPLITTER_ALREADY_STARTED,
		"device ownership is wrong");
	statuses[0] = EFI_DEVICE_ERROR; statuses[1] = EFI_UNSUPPORTED; calls = 0U;
	failures += expect(cdk2_split_text_out_output(&splitter, L"x") == EFI_UNSUPPORTED &&
		calls == 2U, "fanout did not visit every output and return the last error");
	failures += expect(cdk2_split_text_out_remove(&splitter, (void *)1) == EFI_SUCCESS &&
		splitter.device_count == 1U && splitter.devices[0].context == (void *)2,
		"device removal corrupted the compact list");
	statuses[1] = EFI_SUCCESS;
	failures += expect(cdk2_split_text_out_set_attribute(&splitter, 0x17U) == EFI_SUCCESS &&
		last_value == 0x17U && splitter.attribute == 0x17U,
		"attribute did not fan out or update virtual state");
	failures += expect(cdk2_split_text_out_set_cursor(&splitter, 1U, 1U) == EFI_SUCCESS &&
		last_column == 1U && last_row == 1U &&
		cdk2_split_text_out_set_cursor(&splitter, 2U, 0U) == EFI_UNSUPPORTED,
		"cursor bounds/fanout are wrong");
	failures += expect(cdk2_split_text_out_enable_cursor(&splitter, FALSE) == EFI_SUCCESS &&
		!last_visible && !splitter.cursor_visible &&
		cdk2_split_text_out_clear(&splitter) == EFI_SUCCESS && splitter.column == 0U &&
		splitter.row == 0U, "cursor visibility or clear state is wrong");
	return failures == 0 ? 0 : 1;
}
