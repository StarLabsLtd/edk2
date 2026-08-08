/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_LOCAL_APIC_TIMER_H_
#define CDK2_LOCAL_APIC_TIMER_H_

#include <uefi.h>

#define CDK2_LOCAL_APIC_TIMER_VECTOR 32U
#define CDK2_LOCAL_APIC_DEFAULT_PERIOD 100000ULL

struct cdk2_timer_arch_protocol;

typedef void CDK2_MS_ABI cdk2_timer_notify_fn(UINT64 period);
typedef EFI_STATUS CDK2_MS_ABI cdk2_timer_register_fn(
	struct cdk2_timer_arch_protocol *protocol, cdk2_timer_notify_fn * notify);
typedef EFI_STATUS CDK2_MS_ABI cdk2_timer_set_period_fn(
	struct cdk2_timer_arch_protocol *protocol, UINT64 period);
typedef EFI_STATUS CDK2_MS_ABI cdk2_timer_get_period_fn(
	struct cdk2_timer_arch_protocol *protocol, UINT64 * period);
typedef EFI_STATUS CDK2_MS_ABI cdk2_timer_soft_interrupt_fn(
	struct cdk2_timer_arch_protocol *protocol);

struct cdk2_timer_arch_protocol {
	cdk2_timer_register_fn *register_handler;
	cdk2_timer_set_period_fn *set_period;
	cdk2_timer_get_period_fn *get_period;
	cdk2_timer_soft_interrupt_fn *generate_soft_interrupt;
};

typedef void cdk2_apic_program_fn(UINT32 divide, UINT32 count,
	BOOLEAN periodic, UINT8 vector);
typedef void cdk2_apic_set_interrupt_fn(BOOLEAN enabled);
typedef BOOLEAN cdk2_apic_interrupt_enabled_fn(void);
typedef void cdk2_apic_send_eoi_fn(void);
typedef UINTN cdk2_apic_raise_tpl_fn(UINTN tpl);
typedef void cdk2_apic_restore_tpl_fn(UINTN tpl);

struct cdk2_local_apic_timer_ops {
	cdk2_apic_program_fn *program;
	cdk2_apic_set_interrupt_fn *set_interrupt;
	cdk2_apic_interrupt_enabled_fn *interrupt_enabled;
	cdk2_apic_send_eoi_fn *send_eoi;
	cdk2_apic_raise_tpl_fn *raise_tpl;
	cdk2_apic_restore_tpl_fn *restore_tpl;
};

EFI_STATUS cdk2_local_apic_timer_init(
	const struct cdk2_local_apic_timer_ops *ops, UINT32 bus_clock_hz);
void cdk2_local_apic_timer_interrupt(void);
struct cdk2_timer_arch_protocol *cdk2_local_apic_timer_protocol(void);

#endif
