/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter_entry.h>
#include <stdarg.h>
#include <stdio.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
struct boot_services_view {
	UINT8 header[24]; void *slots[38];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct cdk2_split_system_table {
	UINT8 header[24]; CHAR16 * vendor; UINT32 revision, padding;
	void *input_handle; struct cdk2_split_text_in_protocol *input;
	void *output_handle; struct cdk2_split_text_out_protocol *output;
	void *error_handle; struct cdk2_split_text_out_protocol *error;
	void *runtime; struct boot_services_view *boot;
};
static UINTN installs, uninstalls, fail_at;
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{ installs++; if (*handle == NULL) *handle = (void *)(installs + 10U); return installs == fail_at ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{ if (handle == NULL) return EFI_INVALID_PARAMETER; uninstalls++; return EFI_SUCCESS; }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "con splitter entry test: %s\n", message); return !condition; }

int main(void)
{
	struct boot_services_view boot = { .install_multiple = install,
		.uninstall_multiple = uninstall };
	struct cdk2_split_system_table system = { .boot = &boot };
	UINTN columns, rows, index;
	int failures = 0;

	failures += expect(cdk2_con_splitter_entry((void *)1, &system) == EFI_SUCCESS &&
		installs == 7U && system.input != NULL && system.output != NULL &&
		system.error != NULL, "virtual console protocols were not published");
	failures += expect(system.output->query(system.output, 0U, &columns, &rows) ==
		EFI_SUCCESS && columns == 80U && rows == 25U &&
		system.output->output(system.output, L"A") == EFI_SUCCESS &&
		system.output->mode->cursor_column == 1,
		"virtual SimpleTextOut ABI did not delegate to the model");
	for (index = 1; index <= 7; index++) {
		installs = uninstalls = 0U; fail_at = index;
		failures += expect(cdk2_con_splitter_entry((void *)1, &system) ==
			EFI_DEVICE_ERROR && uninstalls == index - 1U,
			"partial virtual protocol publication was not rolled back");
	}
	return failures == 0 ? 0 : 1;
}
