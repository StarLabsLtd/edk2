/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Native PC/AT-compatible real-time clock runtime services. */

#include <cdk2/pcat_rtc.h>
#include <stddef.h>
#include <stdint.h>

#define RTC_INDEX_PORT 0x70U
#define RTC_DATA_PORT 0x71U
#define RTC_SECONDS 0x00U
#define RTC_SECONDS_ALARM 0x01U
#define RTC_MINUTES 0x02U
#define RTC_MINUTES_ALARM 0x03U
#define RTC_HOURS 0x04U
#define RTC_HOURS_ALARM 0x05U
#define RTC_DAY_OF_MONTH 0x07U
#define RTC_MONTH 0x08U
#define RTC_YEAR 0x09U
#define RTC_REGISTER_A 0x0aU
#define RTC_REGISTER_B 0x0bU
#define RTC_REGISTER_C 0x0cU
#define RTC_CENTURY 0x32U
#define RTC_UPDATE_IN_PROGRESS BIT7
#define RTC_ALARM_INTERRUPT_ENABLE BIT5
#define RTC_DATA_MODE_BINARY BIT2
#define RTC_HOUR_MODE_24 BIT1
#define RTC_SET BIT7
#define RTC_ALARM_FLAG BIT5
#define RTC_MAX_UPDATE_POLLS 100000U
#define EFI_TIME_ADJUST_DAYLIGHT BIT0
#define EFI_TIME_IN_DAYLIGHT BIT1
#define EFI_UNSPECIFIED_TIMEZONE 0x07ff

typedef EFI_STATUS get_time_function(CDK2_EFI_TIME * time,
	CDK2_TIME_CAPABILITIES * capabilities) CDK2_MS_ABI;
typedef EFI_STATUS set_time_function(CDK2_EFI_TIME * time) CDK2_MS_ABI;
typedef EFI_STATUS get_wakeup_time_function(BOOLEAN * enabled,
	BOOLEAN * pending, CDK2_EFI_TIME * time) CDK2_MS_ABI;
typedef EFI_STATUS set_wakeup_time_function(BOOLEAN enable,
	CDK2_EFI_TIME * time) CDK2_MS_ABI;
typedef EFI_STATUS install_multiple_function(void **handle, ...) CDK2_MS_ABI;

struct runtime_services_view {
	UINT8 header[24];
	get_time_function *get_time;
	set_time_function *set_time;
	get_wakeup_time_function *get_wakeup_time;
	set_wakeup_time_function *set_wakeup_time;
};

struct boot_services_view {
	UINT8 unused[328];
	install_multiple_function *install_multiple;
};

struct system_table_view {
	UINT8 unused[88];
	struct runtime_services_view *runtime_services;
	struct boot_services_view *boot_services;
};

static const EFI_GUID rtc_arch_guid = {
	0x27cfac87, 0x46cc, 0x11d4,
	{ 0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static void *driver_handle;

#ifdef CDK2_PCAT_RTC_TEST
extern UINT8 cdk2_pcat_rtc_test_in8(UINT16 port);
extern void cdk2_pcat_rtc_test_out8(UINT16 port, UINT8 value);
#define io_in8 cdk2_pcat_rtc_test_in8
#define io_out8 cdk2_pcat_rtc_test_out8
#else
static UINT8 io_in8(UINT16 port)
{
	UINT8 value;

	__asm__ volatile("inb %w1, %b0" : "=a"(value) : "Nd"(port));
	return value;
}

static void io_out8(UINT16 port, UINT8 value)
{
	__asm__ volatile("outb %b0, %w1" : : "a"(value), "Nd"(port));
}
#endif

static UINT8 rtc_read(UINT8 index)
{
	io_out8(RTC_INDEX_PORT, index);
	return io_in8(RTC_DATA_PORT);
}

static void rtc_write(UINT8 index, UINT8 value)
{
	io_out8(RTC_INDEX_PORT, index);
	io_out8(RTC_DATA_PORT, value);
}

static UINT8 bcd_to_binary(UINT8 value)
{
	return (UINT8)((value >> 4) * 10U + (value & 0x0fU));
}

static UINT8 binary_to_bcd(UINT8 value)
{
	return (UINT8)(((value / 10U) << 4) | (value % 10U));
}

static int leap_year(UINT16 year)
{
	return (year % 4U == 0U && year % 100U != 0U) || year % 400U == 0U;
}

static UINT8 days_in_month(UINT16 year, UINT8 month)
{
	static const UINT8 days[] = { 31, 28, 31, 30, 31, 30,
		31, 31, 30, 31, 30, 31 };

	if (month == 2U && leap_year(year))
		return 29;
	return month >= 1U && month <= ARRAY_SIZE(days) ? days[month - 1U] : 0;
}

static int valid_time(const CDK2_EFI_TIME *time)
{
	if (time == NULL || time->year < 1900U || time->year > 2099U ||
	    time->month < 1U || time->month > 12U || time->day < 1U ||
	    time->day > days_in_month(time->year, time->month) ||
	    time->hour > 23U || time->minute > 59U || time->second > 59U ||
	    time->nanosecond > 999999999U)
		return 0;
	if (time->timezone != EFI_UNSPECIFIED_TIMEZONE &&
	    (time->timezone < -1440 || time->timezone > 1440))
		return 0;
	return (time->daylight & ~(EFI_TIME_ADJUST_DAYLIGHT | EFI_TIME_IN_DAYLIGHT)) == 0U;
}

static int wait_for_update(void)
{
	UINTN count;

	for (count = 0; count < RTC_MAX_UPDATE_POLLS; count++) {
		if ((rtc_read(RTC_REGISTER_A) & RTC_UPDATE_IN_PROGRESS) == 0U)
			return 1;
	}
	return 0;
}

static UINT8 decode_value(UINT8 value, UINT8 register_b)
{
	return (register_b & RTC_DATA_MODE_BINARY) != 0U ? value : bcd_to_binary(value);
}

static UINT8 encode_value(UINT8 value, UINT8 register_b)
{
	return (register_b & RTC_DATA_MODE_BINARY) != 0U ? value : binary_to_bcd(value);
}

static UINT8 decode_hour(UINT8 value, UINT8 register_b)
{
	UINT8 pm = value & BIT7;
	UINT8 hour = decode_value(value & ~BIT7, register_b);

	if ((register_b & RTC_HOUR_MODE_24) != 0U)
		return hour;
	if (hour == 12U)
		hour = 0;
	return (UINT8)(hour + (pm != 0U ? 12U : 0U));
}

static UINT8 encode_hour(UINT8 hour, UINT8 register_b)
{
	UINT8 pm;

	if ((register_b & RTC_HOUR_MODE_24) != 0U)
		return encode_value(hour, register_b);
	pm = hour >= 12U ? BIT7 : 0U;
	hour %= 12U;
	if (hour == 0U)
		hour = 12U;
	return encode_value(hour, register_b) | pm;
}

static EFI_STATUS read_clock(CDK2_EFI_TIME *time, int alarm)
{
	UINT8 register_b;
	UINT8 century;
	UINT8 year;

	if (time == NULL)
		return EFI_INVALID_PARAMETER;
	if (!wait_for_update())
		return EFI_DEVICE_ERROR;
	register_b = rtc_read(RTC_REGISTER_B);
	time->second = decode_value(rtc_read(alarm ? RTC_SECONDS_ALARM : RTC_SECONDS),
		register_b);
	time->minute = decode_value(rtc_read(alarm ? RTC_MINUTES_ALARM : RTC_MINUTES),
		register_b);
	time->hour = decode_hour(rtc_read(alarm ? RTC_HOURS_ALARM : RTC_HOURS), register_b);
	if (alarm) {
		time->year = 0;
		time->month = 0;
		time->day = 0;
	} else {
		time->day = decode_value(rtc_read(RTC_DAY_OF_MONTH), register_b);
		time->month = decode_value(rtc_read(RTC_MONTH), register_b);
		year = decode_value(rtc_read(RTC_YEAR), register_b);
		century = decode_value(rtc_read(RTC_CENTURY), register_b);
		time->year = (UINT16)century * 100U + year;
	}
	time->nanosecond = 0;
	time->timezone = EFI_UNSPECIFIED_TIMEZONE;
	time->daylight = 0;
	time->pad1 = 0;
	time->pad2 = 0;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_time(CDK2_EFI_TIME *time,
	CDK2_TIME_CAPABILITIES *capabilities)
{
	EFI_STATUS status = read_clock(time, 0);

	if (!EFI_ERROR(status) && capabilities != NULL) {
		capabilities->resolution = 1;
		capabilities->accuracy = 50000000;
		capabilities->sets_to_zero = FALSE;
	}
	return status;
}

static EFI_STATUS CDK2_MS_ABI set_time(CDK2_EFI_TIME *time)
{
	UINT8 register_b;

	if (!valid_time(time))
		return EFI_INVALID_PARAMETER;
	if (!wait_for_update())
		return EFI_DEVICE_ERROR;
	register_b = rtc_read(RTC_REGISTER_B);
	rtc_write(RTC_REGISTER_B, register_b | RTC_SET);
	rtc_write(RTC_SECONDS, encode_value(time->second, register_b));
	rtc_write(RTC_MINUTES, encode_value(time->minute, register_b));
	rtc_write(RTC_HOURS, encode_hour(time->hour, register_b));
	rtc_write(RTC_DAY_OF_MONTH, encode_value(time->day, register_b));
	rtc_write(RTC_MONTH, encode_value(time->month, register_b));
	rtc_write(RTC_YEAR, encode_value((UINT8)(time->year % 100U), register_b));
	rtc_write(RTC_CENTURY, encode_value((UINT8)(time->year / 100U), register_b));
	rtc_write(RTC_REGISTER_B, register_b);
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_wakeup_time(BOOLEAN *enabled,
	BOOLEAN *pending, CDK2_EFI_TIME *time)
{
	UINT8 register_b;
	EFI_STATUS status;

	if (enabled == NULL || pending == NULL || time == NULL)
		return EFI_INVALID_PARAMETER;
	register_b = rtc_read(RTC_REGISTER_B);
	*enabled = (register_b & RTC_ALARM_INTERRUPT_ENABLE) != 0U;
	*pending = (rtc_read(RTC_REGISTER_C) & RTC_ALARM_FLAG) != 0U;
	status = read_clock(time, 1);
	return status;
}

static EFI_STATUS CDK2_MS_ABI set_wakeup_time(BOOLEAN enable, CDK2_EFI_TIME *time)
{
	UINT8 register_b;

	register_b = rtc_read(RTC_REGISTER_B);
	if (!enable) {
		rtc_write(RTC_REGISTER_B, register_b & ~RTC_ALARM_INTERRUPT_ENABLE);
		(void)rtc_read(RTC_REGISTER_C);
		return EFI_SUCCESS;
	}
	if (time == NULL || time->hour > 23U || time->minute > 59U ||
	    time->second > 59U)
		return EFI_INVALID_PARAMETER;
	rtc_write(RTC_SECONDS_ALARM, encode_value(time->second, register_b));
	rtc_write(RTC_MINUTES_ALARM, encode_value(time->minute, register_b));
	rtc_write(RTC_HOURS_ALARM, encode_hour(time->hour, register_b));
	(void)rtc_read(RTC_REGISTER_C);
	rtc_write(RTC_REGISTER_B, register_b | RTC_ALARM_INTERRUPT_ENABLE);
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_pcat_rtc_entry(void *image,
	struct system_table_view *system)
{
	(void)image;
	if (system == NULL || system->runtime_services == NULL ||
	    system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	system->runtime_services->get_time = get_time;
	system->runtime_services->set_time = set_time;
	system->runtime_services->get_wakeup_time = get_wakeup_time;
	system->runtime_services->set_wakeup_time = set_wakeup_time;
	return system->boot_services->install_multiple(&driver_handle,
		&rtc_arch_guid, NULL, NULL);
}
