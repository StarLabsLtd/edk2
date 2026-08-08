/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/local_apic_timer.h>
#include <stdio.h>

#define EFI_ALREADY_STARTED EFIERR(20)

static UINT32 programmed_count;
static UINT8 programmed_vector;
static BOOLEAN interrupt_state;
static UINTN raised_tpl;
static UINTN restored_tpl;
static UINTN eoi_count;
static UINT64 notified_period;
static UINT64 enabled_period;

static void program(UINT32 divide, UINT32 count, BOOLEAN periodic, UINT8 vector)
{
	if (divide == 1U && periodic)
		programmed_count = count;
	programmed_vector = vector;
}

static void set_interrupt(BOOLEAN enabled)
{
	UINT64 period;

	if (enabled && cdk2_local_apic_timer_protocol()->get_period(
		cdk2_local_apic_timer_protocol(), &period) == EFI_SUCCESS)
		enabled_period = period;
	interrupt_state = enabled;
}
static BOOLEAN interrupt_enabled(void) { return interrupt_state; }
static void send_eoi(void) { eoi_count++; }
static UINTN raise_tpl(UINTN tpl) { raised_tpl = tpl; return 7U; }
static void restore_tpl(UINTN tpl) { restored_tpl = tpl; }
static void CDK2_MS_ABI notify(UINT64 period) { notified_period = period; }

static const struct cdk2_local_apic_timer_ops ops = {
	program, set_interrupt, interrupt_enabled, send_eoi, raise_tpl, restore_tpl
};

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "local-apic-timer test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct cdk2_timer_arch_protocol *timer = cdk2_local_apic_timer_protocol();
	UINT64 period;
	int failures = 0;

	failures += expect(cdk2_local_apic_timer_init(NULL, 100000000U) ==
		EFI_INVALID_PARAMETER, "missing hardware contract accepted");
	failures += expect(cdk2_local_apic_timer_init(&ops, 100000000U) == EFI_SUCCESS &&
		programmed_count == 500000U && programmed_vector == 32U && interrupt_state &&
		enabled_period == CDK2_LOCAL_APIC_DEFAULT_PERIOD,
		"default ten-millisecond period was not programmed");
	failures += expect(timer->get_period(timer, &period) == EFI_SUCCESS &&
		period == CDK2_LOCAL_APIC_DEFAULT_PERIOD, "reported period is wrong");
	failures += expect(timer->register_handler(timer, notify) == EFI_SUCCESS &&
		timer->register_handler(timer, notify) == EFI_ALREADY_STARTED,
		"handler registration state is wrong");
	cdk2_local_apic_timer_interrupt();
	failures += expect(eoi_count == 1U && notified_period == period,
		"hardware interrupt ordering is wrong");
	notified_period = 0;
	failures += expect(timer->generate_soft_interrupt(timer) == EFI_SUCCESS &&
		raised_tpl == 31U && restored_tpl == 7U && notified_period == period,
		"soft interrupt semantics are wrong");
	failures += expect(timer->set_period(timer, 0) == EFI_SUCCESS && !interrupt_state &&
		timer->generate_soft_interrupt(timer) == EFI_UNSUPPORTED,
		"disabled timer accepted soft interrupt");
	failures += expect(timer->register_handler(timer, NULL) == EFI_SUCCESS &&
		timer->register_handler(timer, NULL) == EFI_INVALID_PARAMETER,
		"handler removal state is wrong");
	failures += expect(timer->set_period(timer, 1U) == EFI_SUCCESS &&
		programmed_count == 5U && enabled_period == 1U,
		"period rounding or publish-before-unmask ordering is wrong");
	failures += expect(cdk2_local_apic_timer_init(&ops, 1U) == EFI_SUCCESS &&
		timer->set_period(timer, 1U) == EFI_SUCCESS && programmed_count == 1U,
		"minimum nonzero period programmed zero ticks");
	failures += expect(cdk2_local_apic_timer_init(&ops, 100000000U) == EFI_SUCCESS,
		"timer could not be restored for overflow testing");
	failures += expect(timer->set_period(timer, MAX_UINT64) == EFI_SUCCESS &&
		programmed_count == MAX_UINT32, "period overflow was not clamped");
	failures += expect(timer->get_period(timer, &period) == EFI_SUCCESS &&
		period == 858993459ULL, "clamped period omitted the APIC divide-by-two");
	return failures == 0 ? 0 : 1;
}
