/* SPDX-License-Identifier: GPL-2.0-only */

#define CDK2_PCAT_RTC_TEST
#include "../src/modules/pcat_rtc/pcat_rtc.c"

#include <stdio.h>
#include <string.h>

static UINT8 cmos[128];
static UINT8 selected_register;
static UINTN install_count;

UINT8 cdk2_pcat_rtc_test_in8(UINT16 port)
{
	return port == RTC_DATA_PORT ? cmos[selected_register] : 0xff;
}

void cdk2_pcat_rtc_test_out8(UINT16 port, UINT8 value)
{
	if (port == RTC_INDEX_PORT)
		selected_register = value & 0x7fU;
	else if (port == RTC_DATA_PORT)
		cmos[selected_register] = value;
}

static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{
	__builtin_ms_va_list arguments;
	const EFI_GUID *guid;
	void *interface;

	*handle = (void *)1;
	__builtin_ms_va_start(arguments, handle);
	guid = __builtin_va_arg(arguments, const EFI_GUID *);
	interface = __builtin_va_arg(arguments, void *);
	install_count = guid == &rtc_arch_guid && interface == NULL;
	guid = __builtin_va_arg(arguments, const EFI_GUID *);
	__builtin_ms_va_end(arguments);
	return guid == NULL ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "pcat-rtc test: %s\n", message);
	return !condition;
}

static void set_bcd_clock(void)
{
	memset(cmos, 0, sizeof(cmos));
	cmos[RTC_REGISTER_B] = RTC_HOUR_MODE_24;
	cmos[RTC_SECONDS] = 0x56;
	cmos[RTC_MINUTES] = 0x34;
	cmos[RTC_HOURS] = 0x12;
	cmos[RTC_DAY_OF_MONTH] = 0x29;
	cmos[RTC_MONTH] = 0x02;
	cmos[RTC_YEAR] = 0x28;
	cmos[RTC_CENTURY] = 0x20;
}

int main(void)
{
	struct runtime_services_view runtime;
	struct boot_services_view boot;
	struct system_table_view system;
	CDK2_EFI_TIME time;
	CDK2_TIME_CAPABILITIES capabilities;
	BOOLEAN enabled;
	BOOLEAN pending;
	int failures = 0;

	memset(&runtime, 0, sizeof(runtime));
	memset(&boot, 0, sizeof(boot));
	memset(&system, 0, sizeof(system));
	boot.install_multiple = install_multiple;
	system.runtime_services = &runtime;
	system.boot_services = &boot;
	failures += expect(cdk2_pcat_rtc_entry(NULL, NULL) == EFI_INVALID_PARAMETER,
		"NULL system table was accepted");
	failures += expect(cdk2_pcat_rtc_entry(NULL, &system) == EFI_SUCCESS,
		"entry failed");
	failures += expect(install_count == 1U && runtime.get_time == get_time &&
		runtime.set_time == set_time && runtime.get_wakeup_time == get_wakeup_time &&
		runtime.set_wakeup_time == set_wakeup_time,
		"runtime services or architectural protocol were not installed");

	set_bcd_clock();
	failures += expect(runtime.get_time(&time, &capabilities) == EFI_SUCCESS,
		"BCD GetTime failed");
	failures += expect(time.year == 2028U && time.month == 2U && time.day == 29U &&
		time.hour == 12U && time.minute == 34U && time.second == 56U,
		"BCD time decoded incorrectly");
	failures += expect(capabilities.resolution == 1U &&
		capabilities.accuracy == 50000000U, "capabilities are wrong");

	time = (CDK2_EFI_TIME){ 2024, 12, 31, 23, 59, 58, 0, 0,
		EFI_UNSPECIFIED_TIMEZONE, 0, 0 };
	failures += expect(runtime.set_time(&time) == EFI_SUCCESS,
		"valid SetTime failed");
	failures += expect(cmos[RTC_YEAR] == 0x24 && cmos[RTC_CENTURY] == 0x20 &&
		cmos[RTC_HOURS] == 0x23 && cmos[RTC_SECONDS] == 0x58,
		"SetTime encoded BCD incorrectly");
	time = (CDK2_EFI_TIME){ 2023, 2, 29, 0, 0, 0, 0, 0,
		EFI_UNSPECIFIED_TIMEZONE, 0, 0 };
	failures += expect(runtime.set_time(&time) == EFI_INVALID_PARAMETER,
		"invalid leap day was accepted");

	cmos[RTC_REGISTER_B] = RTC_DATA_MODE_BINARY | RTC_HOUR_MODE_24;
	time = (CDK2_EFI_TIME){ 0, 0, 0, 7, 8, 9, 0, 0,
		EFI_UNSPECIFIED_TIMEZONE, 0, 0 };
	failures += expect(runtime.set_wakeup_time(TRUE, &time) == EFI_SUCCESS &&
		cmos[RTC_SECONDS_ALARM] == 9U && cmos[RTC_MINUTES_ALARM] == 8U &&
		cmos[RTC_HOURS_ALARM] == 7U &&
		(cmos[RTC_REGISTER_B] & RTC_ALARM_INTERRUPT_ENABLE) != 0U,
		"alarm was not programmed");
	cmos[RTC_REGISTER_C] = RTC_ALARM_FLAG;
	failures += expect(runtime.get_wakeup_time(&enabled, &pending, &time) == EFI_SUCCESS &&
		enabled == TRUE && pending == TRUE && time.hour == 7U,
		"alarm status was read incorrectly");
	failures += expect(runtime.set_wakeup_time(FALSE, NULL) == EFI_SUCCESS &&
		(cmos[RTC_REGISTER_B] & RTC_ALARM_INTERRUPT_ENABLE) == 0U,
		"alarm disable failed");

	cmos[RTC_REGISTER_A] = RTC_UPDATE_IN_PROGRESS;
	failures += expect(runtime.get_time(&time, NULL) == EFI_DEVICE_ERROR,
		"stuck update-in-progress was accepted");
	return failures == 0 ? 0 : 1;
}
