/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GUID_LOCAL_APIC_TIMER_INFO_H_
#define CDK2_GUID_LOCAL_APIC_TIMER_INFO_H_

#include <uefi.h>

#define CDK2_LOCAL_APIC_TIMER_INFO_REVISION 1U

struct cdk2_local_apic_timer_info {
	UINT16 revision;
	UINT16 reserved;
	UINT64 frequency_hz;
} __packed;

#endif
