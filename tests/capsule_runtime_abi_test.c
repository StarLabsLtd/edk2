/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <assert.h>
#include <cdk2/capsule_runtime_abi.h>

static EFI_STATUS CDK2_MS_ABI crc(void *pointer, UINTN size, cdk2_uint32_ptr value)
{
	(void)pointer;
	(void)size;
	*value = 0x12345678U;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI fail(void *pointer, UINTN size, cdk2_uint32_ptr value)
{
	(void)pointer;
	(void)size;
	(void)value;
	return EFI_DEVICE_ERROR;
}

int main(void)
{
	struct cdk2_runtime_services_view runtime = {
		.header.size = sizeof(runtime),
		.header.crc32 = 7U,
		.update_capsule = (void *)1,
		.query_capsule = (void *)2,
	};
	struct cdk2_boot_services_view boot = { .calculate_crc32 = crc };

	assert(cdk2_capsule_install_runtime_slots(&runtime, &boot, (void *)3,
		(void *)4) == EFI_SUCCESS);
	assert(runtime.update_capsule == (void *)3 &&
		runtime.query_capsule == (void *)4 &&
		runtime.header.crc32 == 0x12345678U);
	boot.calculate_crc32 = fail;
	runtime.header.crc32 = 9U;
	assert(cdk2_capsule_install_runtime_slots(&runtime, &boot, (void *)5,
		(void *)6) == EFI_DEVICE_ERROR);
	assert(runtime.update_capsule == (void *)3 &&
		runtime.query_capsule == (void *)4 && runtime.header.crc32 == 9U);
	return 0;
}
