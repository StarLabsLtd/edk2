/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_platform_entry.h>
#include <stdarg.h>
#include <stdio.h>

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
struct cdk2_con_boot_services {
	UINT8 header[24]; void *slots[38];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
static UINTN installs, uninstalls, fail_at;
static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{ installs++; if (*handle == NULL) *handle = (void *)(UINTN)(installs + 10U); return installs == fail_at ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle, ...)
{ if (handle == NULL) return EFI_INVALID_PARAMETER; uninstalls++; return EFI_SUCCESS; }

int main(void)
{
	struct cdk2_con_boot_services boot = { { 0 }, { 0 }, install_multiple, uninstall_multiple };
	struct cdk2_con_system_table system = {
		.runtime = (void *)1,
		.boot = (void *)&boot,
	};
	UINTN index;

	if (cdk2_con_platform_entry((void *)1, &system) != EFI_SUCCESS || installs != 6U) {
		fprintf(stderr, "entry success path: installs=%llu\n",
			(unsigned long long)installs);
		return 1;
	}
	for (index = 1; index <= 6; index++) {
		installs = uninstalls = 0U; fail_at = index;
		if (cdk2_con_platform_entry((void *)1, &system) != EFI_DEVICE_ERROR ||
		    uninstalls != index - 1U) {
			fprintf(stderr, "entry fault %llu: installs=%llu uninstalls=%llu\n",
				(unsigned long long)index, (unsigned long long)installs,
				(unsigned long long)uninstalls);
			return 1;
		}
	}
	return 0;
}
