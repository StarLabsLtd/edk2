/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/local_apic_timer.h>
#include <guid/local_apic_timer_info.h>
#include <stddef.h>

#define HOB_TYPE_GUID_EXTENSION 4U
#define HOB_TYPE_END_OF_LIST 0xffffU
#define MAX_HOB_LIST_SIZE SIZE_1MB
#define IA32_APIC_BASE_MSR 0x1bU
#define IA32_APIC_BASE_X2APIC (1ULL << 10)
#define IA32_APIC_BASE_MASK 0x000ffffffffff000ULL
#define APIC_EOI 0xb0U
#define APIC_LVT_TIMER 0x320U
#define APIC_INITIAL_COUNT 0x380U
#define APIC_DIVIDE_CONFIG 0x3e0U
#define APIC_LVT_MASK (1U << 16)
#define APIC_LVT_PERIODIC (1U << 17)

struct table_header { UINT64 signature; UINT32 revision, header_size, crc32, reserved; };
struct config_table { EFI_GUID guid; void *table; };
struct hob_header { UINT16 type, length; UINT32 reserved; };
struct guid_hob { struct hob_header header; EFI_GUID name; };
typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef UINTN CDK2_MS_ABI raise_tpl_fn(UINTN);
typedef void CDK2_MS_ABI restore_tpl_fn(UINTN);
struct boot_services_view {
	UINT8 header[24];
	raise_tpl_fn *raise_tpl;
	restore_tpl_fn *restore_tpl;
	UINT8 before_locate_protocol[280];
	locate_protocol_fn *locate_protocol;
	install_multiple_fn *install_multiple;
};
struct system_table_view {
	struct table_header header;
	CHAR16 *vendor;
	UINT32 revision, padding;
	void *console_fields[6];
	void *runtime_services;
	struct boot_services_view *boot_services;
	UINTN table_count;
	struct config_table *tables;
};
typedef void CDK2_MS_ABI interrupt_handler_fn(INTN, void *);
typedef EFI_STATUS CDK2_MS_ABI register_interrupt_fn(void *, INTN,
	interrupt_handler_fn *);
struct cpu_arch_protocol {
	void *functions[5];
	register_interrupt_fn *register_interrupt;
};
struct x64_system_context {
	UINT8 before_rflags[616];
	UINT64 rflags;
};
struct nested_interrupt_state {
	UINTN in_progress_restore_tpl;
	BOOLEAN deferred_restore_tpl;
};

static const EFI_GUID hob_list_guid = { 0x7739f24c, 0x93d7, 0x11d4,
	{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const EFI_GUID timer_info_guid = { 0x18c7a13d, 0x9a71, 0x4f5d,
	{ 0x91, 0x68, 0x44, 0x7b, 0x69, 0x8c, 0x12, 0x56 } };
static const EFI_GUID cpu_arch_guid = { 0x26baccb1, 0x6f42, 0x11d4,
	{ 0xbc, 0xe7, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 } };
static const EFI_GUID timer_arch_guid = { 0x26baccb3, 0x6f42, 0x11d4,
	{ 0xbc, 0xe7, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 } };
static struct boot_services_view *boot_services;
static void *timer_handle;
static struct nested_interrupt_state interrupt_state;

#ifdef CDK2_LOCAL_APIC_TIMER_DRIVER_TEST
void cdk2_local_apic_timer_test_set_boot_services(void *services)
{
	boot_services = services;
}

void cdk2_local_apic_timer_test_set_nested_state(UINTN tpl, BOOLEAN deferred)
{
	interrupt_state.in_progress_restore_tpl = tpl;
	interrupt_state.deferred_restore_tpl = deferred;
}
#endif

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	const UINT8 *left = (const void *)a;
	const UINT8 *right = (const void *)b;
	UINTN index;

	for (index = 0; index < sizeof(*a); index++)
		if (left[index] != right[index])
			return 0;
	return 1;
}

static const void *find_timer_info(const struct system_table_view *system,
	UINTN *payload_size)
{
	const UINT8 *list = NULL;
	const struct hob_header *hob;
	UINTN i, walked = 0;

	for (i = 0; i < system->table_count; i++)
		if (guid_equal(&system->tables[i].guid, &hob_list_guid))
			list = system->tables[i].table;
	if (list == NULL)
		return NULL;
	hob = (const void *)list;
	while (walked + sizeof(*hob) <= MAX_HOB_LIST_SIZE) {
		const struct guid_hob *guid_hob = (const void *)hob;
		if (hob->type == HOB_TYPE_END_OF_LIST || hob->length < sizeof(*hob) ||
		    hob->length > MAX_HOB_LIST_SIZE - walked)
			return NULL;
		if (hob->type == HOB_TYPE_GUID_EXTENSION && hob->length >= sizeof(*guid_hob) &&
		    guid_equal(&guid_hob->name, &timer_info_guid)) {
			*payload_size = hob->length - sizeof(*guid_hob);
			return guid_hob + 1;
		}
		walked += hob->length;
		hob = (const void *)(list + walked);
	}
	return NULL;
}

static UINT64 rdmsr(UINT32 msr)
{
	UINT32 lo, hi;

	__asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
	return ((UINT64)hi << 32) | lo;
}

static void wrmsr(UINT32 msr, UINT64 value)
{
	__asm__ volatile("wrmsr" : : "c"(msr), "a"((UINT32)value),
		"d"((UINT32)(value >> 32)));
}

static UINT32 apic_read(UINT32 reg)
{
	UINT64 base = rdmsr(IA32_APIC_BASE_MSR);

	if ((base & IA32_APIC_BASE_X2APIC) != 0U)
		return (UINT32)rdmsr(0x800U + reg / 16U);
	return *(volatile UINT32 *)(UINTN)((base & IA32_APIC_BASE_MASK) + reg);
}

static void apic_write(UINT32 reg, UINT32 value)
{
	UINT64 base = rdmsr(IA32_APIC_BASE_MSR);

	if ((base & IA32_APIC_BASE_X2APIC) != 0U)
		wrmsr(0x800U + reg / 16U, value);
	else
		*(volatile UINT32 *)(UINTN)((base & IA32_APIC_BASE_MASK) + reg) = value;
}

static void program(UINT32 divide, UINT32 count, BOOLEAN periodic, UINT8 vector)
{
	(void)divide;
	apic_write(APIC_DIVIDE_CONFIG, 0U);
	apic_write(APIC_LVT_TIMER, APIC_LVT_MASK | vector |
		(periodic ? APIC_LVT_PERIODIC : 0U));
	apic_write(APIC_INITIAL_COUNT, count);
}

static void set_interrupt(BOOLEAN enabled)
{
	UINT32 lvt = apic_read(APIC_LVT_TIMER);

	apic_write(APIC_LVT_TIMER, enabled ? lvt & ~APIC_LVT_MASK : lvt | APIC_LVT_MASK);
}

static BOOLEAN interrupt_enabled(void)
{
	return (apic_read(APIC_LVT_TIMER) & APIC_LVT_MASK) == 0U;
}

static void send_eoi(void) { apic_write(APIC_EOI, 0); }
static UINTN raise_tpl(UINTN tpl) { return boot_services->raise_tpl(tpl); }
static void restore_tpl(UINTN tpl) { boot_services->restore_tpl(tpl); }
static void nested_restore_tpl(UINTN interrupted_tpl, void *context)
{
	UINTN saved_tpl;
	BOOLEAN deferred;

	if (interrupted_tpl == interrupt_state.in_progress_restore_tpl) {
		interrupt_state.deferred_restore_tpl = TRUE;
		((struct x64_system_context *)context)->rflags &= ~(1ULL << 9);
		return;
	}
	do {
		saved_tpl = interrupt_state.in_progress_restore_tpl;
		interrupt_state.in_progress_restore_tpl = interrupted_tpl;
		boot_services->restore_tpl(interrupted_tpl);
#ifndef CDK2_LOCAL_APIC_TIMER_DRIVER_TEST
		__asm__ volatile("cli" : : : "memory");
#endif
		interrupt_state.in_progress_restore_tpl = saved_tpl;
		deferred = interrupt_state.deferred_restore_tpl;
		interrupt_state.deferred_restore_tpl = FALSE;
	} while (deferred);
}

#ifdef CDK2_LOCAL_APIC_TIMER_DRIVER_TEST
void cdk2_local_apic_timer_test_nested_restore(UINTN tpl, void *context)
{
	nested_restore_tpl(tpl, context);
}
#endif

static void CDK2_MS_ABI interrupt_handler(INTN type, void *context)
{
	UINTN old_tpl;

	(void)type;
	old_tpl = boot_services->raise_tpl(31U);
	cdk2_local_apic_timer_interrupt();
	nested_restore_tpl(old_tpl, context);
}

EFI_STATUS CDK2_MS_ABI cdk2_local_apic_timer_entry(void *image,
	struct system_table_view *system)
{
	const struct cdk2_local_apic_timer_info *info;
	struct cpu_arch_protocol *cpu;
	static const struct cdk2_local_apic_timer_ops ops = {
		program, set_interrupt, interrupt_enabled, send_eoi, raise_tpl, restore_tpl
	};
	UINTN size;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	info = find_timer_info(system, &size);
	if (info == NULL)
		return EFI_UNSUPPORTED;
	if (size < sizeof(*info) || info->revision != CDK2_LOCAL_APIC_TIMER_INFO_REVISION ||
	    info->reserved != 0U || info->frequency_hz == 0U || info->frequency_hz > MAX_UINT32)
		return EFI_COMPROMISED_DATA;
	boot_services = system->boot_services;
	status = boot_services->locate_protocol(&cpu_arch_guid, NULL, (void **)&cpu);
	if (EFI_ERROR(status))
		return status;
	status = cpu->register_interrupt(cpu, CDK2_LOCAL_APIC_TIMER_VECTOR, interrupt_handler);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_local_apic_timer_init(&ops, (UINT32)info->frequency_hz);
	if (EFI_ERROR(status)) {
		cpu->register_interrupt(cpu, CDK2_LOCAL_APIC_TIMER_VECTOR, NULL);
		return status;
	}
	status = boot_services->install_multiple(&timer_handle, &timer_arch_guid,
		cdk2_local_apic_timer_protocol(), NULL);
	if (EFI_ERROR(status)) {
		set_interrupt(FALSE);
		cpu->register_interrupt(cpu, CDK2_LOCAL_APIC_TIMER_VECTOR, NULL);
	}
	return status;
}
