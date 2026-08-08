/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GUID_SMM_REGISTER_INFO_H_
#define CDK2_GUID_SMM_REGISTER_INFO_H_

#include <industry_standard/acpi.h>

#define CDK2_SMM_REGISTER_INFO_REVISION 1U
#define CDK2_SMM_REGISTER_MAX_COUNT 16U
#define CDK2_SMM_REGISTER_ID_GLOBAL_ENABLE 1U
#define CDK2_SMM_REGISTER_ID_APM_ENABLE 4U
#define CDK2_ACPI_SYSTEM_IO 1U
#define CDK2_ACPI_ACCESS_DWORD 3U

struct cdk2_smm_generic_register {
	UINT64 id;
	UINT64 value;
	EFI_ACPI_3_0_GENERIC_ADDRESS_STRUCTURE address;
} __packed;

struct cdk2_smm_register_info {
	UINT16 revision;
	UINT16 reserved;
	UINT32 count;
	struct cdk2_smm_generic_register registers[];
} __packed;

#endif
