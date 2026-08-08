/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_CAPSULE_RUNTIME_ENTRY_H
#define CDK2_CAPSULE_RUNTIME_ENTRY_H

#include <cdk2/capsule_runtime_abi.h>

struct cdk2_system_table_view {
	struct cdk2_table_header header;
	CHAR16 *vendor;
	UINT32 revision;
	UINT32 padding;
	void *console_fields[6];
	struct cdk2_runtime_services_view *runtime;
	struct cdk2_boot_services_view *boot;
};

EFI_STATUS CDK2_MS_ABI cdk2_capsule_runtime_entry(void *,
	struct cdk2_system_table_view *);
EFI_STATUS cdk2_capsule_cache_writeback_range_all_cpus(UINT64 address,
	UINT64 length);

#endif
