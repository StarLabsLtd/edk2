/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <assert.h>
#include <cdk2/capsule_runtime_abi.h>
static EFI_STATUS CDK2_MS_ABI crc(void *p, UINTN n, UINT32 *v) { (void)p; (void)n; *v=0x12345678; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI fail(void *p, UINTN n, UINT32 *v) { (void)p; (void)n; (void)v; return EFI_DEVICE_ERROR; }
int main(void) {
	struct cdk2_runtime_services_view rt = { .header.size=sizeof(rt), .header.crc32=7, .update_capsule=(void *)1, .query_capsule=(void *)2 };
	struct cdk2_boot_services_view bs = { .calculate_crc32=crc };
	assert(cdk2_capsule_install_runtime_slots(&rt,&bs,(void *)3,(void *)4)==EFI_SUCCESS);
	assert(rt.update_capsule==(void *)3 && rt.query_capsule==(void *)4 && rt.header.crc32==0x12345678);
	bs.calculate_crc32=fail; rt.header.crc32=9;
	assert(cdk2_capsule_install_runtime_slots(&rt,&bs,(void *)5,(void *)6)==EFI_DEVICE_ERROR);
	assert(rt.update_capsule==(void *)3 && rt.query_capsule==(void *)4 && rt.header.crc32==9);
	return 0;
}
