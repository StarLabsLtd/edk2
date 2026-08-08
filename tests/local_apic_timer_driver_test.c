/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/local_apic_timer.h>
#include <stdio.h>

typedef void CDK2_MS_ABI test_restore_tpl_fn(UINTN tpl);

struct test_boot_services {
	UINT8 before_restore[32];
	test_restore_tpl_fn *restore_tpl;
};
struct test_context { UINT8 before_rflags[616]; UINT64 rflags; };

static UINTN restore_count;
static UINTN restored_tpl;

void cdk2_local_apic_timer_test_set_boot_services(void *services);
void cdk2_local_apic_timer_test_set_nested_state(UINTN tpl, BOOLEAN deferred);
void cdk2_local_apic_timer_test_nested_restore(UINTN tpl, void *context);
void cdk2_local_apic_timer_interrupt(void) { }
EFI_STATUS cdk2_local_apic_timer_init(const struct cdk2_local_apic_timer_ops *ops,
	UINT32 frequency)
{
	(void)ops;
	(void)frequency;
	return EFI_SUCCESS;
}
struct cdk2_timer_arch_protocol *cdk2_local_apic_timer_protocol(void) { return NULL; }

static void CDK2_MS_ABI restore_tpl(UINTN tpl)
{
	restore_count++;
	restored_tpl = tpl;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "local-apic-timer driver test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct test_boot_services services = { .restore_tpl = restore_tpl };
	struct test_context context = { .rflags = 1ULL << 9 };
	int failures = 0;

	cdk2_local_apic_timer_test_set_boot_services(&services);
	cdk2_local_apic_timer_test_set_nested_state(0, FALSE);
	cdk2_local_apic_timer_test_nested_restore(4, &context);
	failures += expect(restore_count == 1U && restored_tpl == 4U,
		"ordinary interrupt did not restore its interrupted TPL");
	cdk2_local_apic_timer_test_set_nested_state(4, FALSE);
	cdk2_local_apic_timer_test_nested_restore(4, &context);
	failures += expect(restore_count == 1U && (context.rflags & (1ULL << 9)) == 0U,
		"nested interrupt was not deferred with IRET interrupts disabled");
	return failures == 0 ? 0 : 1;
}
