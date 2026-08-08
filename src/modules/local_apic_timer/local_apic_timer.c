/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Hardware-independent LocalApicTimerDxe policy over explicit APIC operations. */

#include <cdk2/local_apic_timer.h>

#define TPL_HIGH_LEVEL 31U
#define EFI_ALREADY_STARTED EFIERR(20)
#define TICKS_PER_SECOND_100NS 10000000ULL
#define APIC_TIMER_DIVIDE 2U
#define APIC_TIMER_COUNT_DENOMINATOR (TICKS_PER_SECOND_100NS * APIC_TIMER_DIVIDE)

static const struct cdk2_local_apic_timer_ops *timer_ops;
static cdk2_timer_notify_fn *timer_notify;
static UINT64 timer_period;
static UINT32 timer_bus_clock_hz;

static EFI_STATUS CDK2_MS_ABI register_handler(
	struct cdk2_timer_arch_protocol *protocol, cdk2_timer_notify_fn *notify)
{
	(void)protocol;
	if (notify == NULL && timer_notify == NULL)
		return EFI_INVALID_PARAMETER;
	if (notify != NULL && timer_notify != NULL)
		return EFI_ALREADY_STARTED;
	timer_notify = notify;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI set_period(
	struct cdk2_timer_arch_protocol *protocol, UINT64 period)
{
	UINT64 count;

	(void)protocol;
	if (period == 0U) {
		timer_ops->set_interrupt(FALSE);
		timer_period = 0;
		return EFI_SUCCESS;
	}
	if (period > MAX_UINT64 / timer_bus_clock_hz)
		count = MAX_UINT64;
	else {
		count = period * timer_bus_clock_hz;
		count = count / APIC_TIMER_COUNT_DENOMINATOR +
			(count % APIC_TIMER_COUNT_DENOMINATOR != 0U);
		if (count == 0U)
			count = 1U;
	}
	if (count > MAX_UINT32) {
		count = MAX_UINT32;
		period = ((UINT64)MAX_UINT32 * APIC_TIMER_COUNT_DENOMINATOR +
			timer_bus_clock_hz - 1U) / timer_bus_clock_hz;
	}
	timer_ops->program(1, (UINT32)count, TRUE, CDK2_LOCAL_APIC_TIMER_VECTOR);
	timer_period = period;
	timer_ops->set_interrupt(TRUE);
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_period(
	struct cdk2_timer_arch_protocol *protocol, UINT64 *period)
{
	(void)protocol;
	if (period == NULL)
		return EFI_INVALID_PARAMETER;
	*period = timer_period;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI generate_soft_interrupt(
	struct cdk2_timer_arch_protocol *protocol)
{
	UINTN old_tpl;

	(void)protocol;
	if (!timer_ops->interrupt_enabled())
		return EFI_UNSUPPORTED;
	old_tpl = timer_ops->raise_tpl(TPL_HIGH_LEVEL);
	if (timer_notify != NULL)
		timer_notify(timer_period);
	timer_ops->restore_tpl(old_tpl);
	return EFI_SUCCESS;
}

static struct cdk2_timer_arch_protocol timer_protocol = {
	register_handler, set_period, get_period, generate_soft_interrupt
};

EFI_STATUS cdk2_local_apic_timer_init(
	const struct cdk2_local_apic_timer_ops *ops, UINT32 bus_clock_hz)
{
	if (ops == NULL || ops->program == NULL || ops->set_interrupt == NULL ||
	    ops->interrupt_enabled == NULL || ops->send_eoi == NULL ||
	    ops->raise_tpl == NULL || ops->restore_tpl == NULL || bus_clock_hz == 0U)
		return EFI_INVALID_PARAMETER;
	timer_ops = ops;
	timer_bus_clock_hz = bus_clock_hz;
	timer_notify = NULL;
	timer_period = 0;
	return set_period(&timer_protocol, CDK2_LOCAL_APIC_DEFAULT_PERIOD);
}

void cdk2_local_apic_timer_interrupt(void)
{
	timer_ops->send_eoi();
	if (timer_notify != NULL)
		timer_notify(timer_period);
}

struct cdk2_timer_arch_protocol *cdk2_local_apic_timer_protocol(void)
{
	return &timer_protocol;
}
