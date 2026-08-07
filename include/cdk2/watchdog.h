/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_WATCHDOG_H_
#define CDK2_WATCHDOG_H_

#include <stdint.h>
#include <uefi.h>

struct cdk2_watchdog;

typedef void CDK2_MS_ABI cdk2_watchdog_notify_fn(uint64_t period);
typedef uint64_t CDK2_MS_ABI cdk2_watchdog_register_fn(
	struct cdk2_watchdog *watchdog, cdk2_watchdog_notify_fn notify);
typedef uint64_t CDK2_MS_ABI cdk2_watchdog_set_period_fn(
	struct cdk2_watchdog *watchdog, uint64_t period);
typedef uint64_t CDK2_MS_ABI cdk2_watchdog_get_period_fn(
	struct cdk2_watchdog *watchdog, uint64_t *period);

struct cdk2_watchdog {
	cdk2_watchdog_register_fn *register_handler;
	cdk2_watchdog_set_period_fn *set_timer_period;
	cdk2_watchdog_get_period_fn *get_timer_period;
};

#endif
