/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PCAT_RTC_H_
#define CDK2_PCAT_RTC_H_

#include <uefi.h>

typedef struct {
	UINT16 year;
	UINT8 month;
	UINT8 day;
	UINT8 hour;
	UINT8 minute;
	UINT8 second;
	UINT8 pad1;
	UINT32 nanosecond;
	INT16 timezone;
	UINT8 daylight;
	UINT8 pad2;
} CDK2_EFI_TIME;

typedef struct {
	UINT32 resolution;
	UINT32 accuracy;
	BOOLEAN sets_to_zero;
} CDK2_TIME_CAPABILITIES;

#endif
