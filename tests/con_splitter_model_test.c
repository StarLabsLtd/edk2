/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter.h>
#include <stdio.h>

static UINTN calls;
static EFI_STATUS statuses[2];
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
{ (void)context; (void)value; return EFI_SUCCESS; }
static EFI_STATUS clear(void *context)
{ (void)context; return EFI_SUCCESS; }
static EFI_STATUS cursor(void *context, UINTN column, UINTN row)
{ (void)context; (void)column; (void)row; return EFI_SUCCESS; }
static EFI_STATUS visible(void *context, BOOLEAN enabled)
{ (void)context; (void)enabled; return EFI_SUCCESS; }
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
	return failures == 0 ? 0 : 1;
}
