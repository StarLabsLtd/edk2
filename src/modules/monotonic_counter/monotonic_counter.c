/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Derived from the pre-standalone MonotonicCounterRuntimeDxe implementation.
 * Copyright (c) 2006-2018 Intel Corporation. */

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define EFI_VARIABLE_NON_VOLATILE 0x1U
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x2U
#define EFI_VARIABLE_RUNTIME_ACCESS 0x4U
#define TPL_HIGH_LEVEL 31U
#define TPL_CALLBACK 8U
#define EVT_SIGNAL_EXIT_BOOT_SERVICES 0x00000201U

struct guid { uint32_t d1; uint16_t d2, d3; uint8_t d4[8]; };
typedef uint64_t CDK2_MS_ABI raise_tpl_type(uint64_t);
typedef void CDK2_MS_ABI restore_tpl_type(uint64_t);
typedef raise_tpl_type * raise_tpl_fn;
typedef restore_tpl_type * restore_tpl_fn;
typedef uint64_t (CDK2_MS_ABI *create_event_fn)(uint32_t, uint64_t,
		void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef uint64_t (CDK2_MS_ABI *get_variable_fn)(const uint16_t *, const struct guid *,
						uint32_t *, size_t *, void *);
typedef uint64_t (CDK2_MS_ABI *set_variable_fn)(const uint16_t *, const struct guid *,
						uint32_t, size_t, const void *);
typedef uint64_t (CDK2_MS_ABI *install_multiple_fn)(void **, const struct guid *, void *, ...);

struct boot_services_view {
	uint8_t header[24];
	raise_tpl_fn raise_tpl;
	restore_tpl_fn restore_tpl;
	uint8_t unused0[80 - 40];
	create_event_fn create_event;
	uint8_t unused1[240 - 88];
	void *get_next_monotonic_count;
	uint8_t unused2[328 - 248];
	install_multiple_fn install_multiple;
};
struct runtime_services_view {
	uint8_t unused0[72];
	get_variable_fn get_variable;
	uint8_t unused1[8];
	set_variable_fn set_variable;
	void *get_next_high_monotonic_count;
};
struct system_table_view {
	uint8_t unused[88];
	struct runtime_services_view *runtime;
	struct boot_services_view *boot;
};

static const struct guid mtc_guid = { 0xeb704011, 0x1402, 0x11d3,
	{ 0x8e, 0x77, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid monotonic_guid = { 0x1da97072, 0xbddc, 0x4b30,
	{ 0x99, 0xf1, 0x72, 0xa0, 0xb5, 0x6f, 0xff, 0x2a } };
static const uint16_t mtc_name[] = { 'M', 'T', 'C', 0 };
static struct boot_services_view *boot_services;
static struct runtime_services_view *runtime_services;
static uint64_t counter;
static int at_runtime;

static void CDK2_MS_ABI exit_boot_services(void *event, void *context)
{
	(void)event;
	(void)context;
	at_runtime = 1;
}

uint64_t CDK2_MS_ABI monotonic_get_next(uint64_t *value)
{
	uint64_t tpl;

	if (value == NULL)
		return EFI_INVALID_PARAMETER;
	if (at_runtime)
		return EFI_UNSUPPORTED;
	tpl = at_runtime ? 0 : boot_services->raise_tpl(TPL_HIGH_LEVEL);
	*value = counter++;
	if (!at_runtime)
		boot_services->restore_tpl(tpl);
	return EFI_SUCCESS;
}

uint64_t CDK2_MS_ABI monotonic_get_next_high(uint32_t *value)
{
	uint64_t tpl;

	if (value == NULL)
		return EFI_INVALID_PARAMETER;
	tpl = boot_services->raise_tpl(TPL_HIGH_LEVEL);
	*value = (uint32_t)(counter >> 32) + 1U;
	counter = (uint64_t)*value << 32;
	boot_services->restore_tpl(tpl);
	return runtime_services->set_variable(mtc_name, &mtc_guid,
		EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
		EFI_VARIABLE_RUNTIME_ACCESS, sizeof(*value), value);
}

uint64_t CDK2_MS_ABI monotonic_counter_entry(void *image,
					     struct system_table_view *system)
{
	uint32_t high = 0;
	size_t size = sizeof(high);
	void *handle = NULL;
	void *event;

	(void)image;
	if (system == NULL || system->boot == NULL || system->runtime == NULL)
		return EFI_INVALID_PARAMETER;
	boot_services = system->boot;
	runtime_services = system->runtime;
	if (runtime_services->get_variable(mtc_name, &mtc_guid, NULL, &size, &high) != 0)
		high = 0;
	counter = (uint64_t)high << 32;
	(void)monotonic_get_next_high(&high);
	if (boot_services->create_event(EVT_SIGNAL_EXIT_BOOT_SERVICES, TPL_CALLBACK,
			exit_boot_services, NULL, &event) != EFI_SUCCESS)
		return EFI_UNSUPPORTED;
	boot_services->get_next_monotonic_count = monotonic_get_next;
	runtime_services->get_next_high_monotonic_count = monotonic_get_next_high;
	return boot_services->install_multiple(&handle, &monotonic_guid, NULL, NULL);
}
