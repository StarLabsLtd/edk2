/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/fat_binding.h>
#include <stdlib.h>
typedef EFI_STATUS CDK2_MS_ABI alloc_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, ...);
struct boot_view { UINT8 hdr[24]; void *a[5]; alloc_fn *allocate; free_fn *release;
	void *slots[31]; install_fn *install; void *uninstall; };
struct system_view { UINT8 pad[96]; struct boot_view *boot; };
static unsigned protocols; static EFI_STATUS failure;
static EFI_STATUS CDK2_MS_ABI allocate(UINT32 t, UINTN s, void **p)
{ (void)t; *p = malloc(s); return *p == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI release(void *p) { free(p); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{
	if (handle == NULL) return EFI_INVALID_PARAMETER;
	protocols = 3U; return failure;
}
int main(void)
{
	struct boot_view boot = { 0 }; struct system_view system = { { 0 }, &boot };
	boot.allocate = allocate; boot.release = release; boot.install = install;
	if (cdk2_fat_entry(NULL, &system) != EFI_INVALID_PARAMETER) return 1;
	if (cdk2_fat_entry((void *)1, &system) != EFI_SUCCESS || protocols != 3U) return 1;
	failure = EFI_DEVICE_ERROR;
	return cdk2_fat_entry((void *)1, &system) == EFI_DEVICE_ERROR ? 0 : 1;
}
