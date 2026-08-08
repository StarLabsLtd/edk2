/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_platform.h>
#include <stdio.h>
#include <stdlib.h>

static UINTN reads, writes, edits, frees;
static EFI_STATUS read_var(void *context, const CHAR16 *name, void **data, UINTN *size)
{
	(void)context; (void)name; reads++; *size = 4; *data = malloc(4); return EFI_SUCCESS;
}
static EFI_STATUS write_var(void *context, const CHAR16 *name, const void *data, UINTN size)
{ (void)context; (void)name; writes++; return data != NULL && size == 8 ? EFI_SUCCESS : EFI_INVALID_PARAMETER; }
static EFI_STATUS edit_path(void *context, const void *old, UINTN old_size,
	const void *path, UINTN path_size, enum cdk2_con_variable_operation operation,
	void **result, UINTN *result_size)
{
	(void)context; (void)old; (void)old_size; (void)path; (void)path_size; edits++;
	if (operation == CDK2_CON_APPEND && edits == 2U)
		return CDK2_CON_ALREADY_STARTED;
	*result = malloc(8); *result_size = 8; return *result == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static void release(void *context, void *buffer)
{ (void)context; frees++; free(buffer); }
static int expect(int value, const char *message)
{ if (!value) fprintf(stderr, "con policy test: %s\n", message); return !value; }

int main(void)
{
	static const CHAR16 name[] = { 'C', 0 };
	static const struct cdk2_con_variable_ops ops = { read_var, write_var, edit_path, release };
	UINT8 path[4] = { 0 };
	int failures = 0;

	failures += expect(cdk2_con_update_variable(&ops, NULL, name, path, sizeof(path),
		CDK2_CON_APPEND) == EFI_SUCCESS && reads == 1U && writes == 1U && frees == 2U,
		"append did not replace variable transactionally");
	failures += expect(cdk2_con_update_variable(&ops, NULL, name, path, sizeof(path),
		CDK2_CON_APPEND) == EFI_SUCCESS && writes == 1U,
		"duplicate append rewrote variable");
	failures += expect(cdk2_con_update_variable(&ops, NULL, name, path, sizeof(path),
		CDK2_CON_DELETE) == EFI_SUCCESS && writes == 2U,
		"delete did not commit edited path");
	return failures == 0 ? 0 : 1;
}
