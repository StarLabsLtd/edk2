/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <string.h>
#include "../src/modules/monotonic_counter/monotonic_counter.c"

static uint32_t saved;
static uint64_t CDK2_MS_ABI raise(uint64_t tpl) { return tpl - 1; }
static void CDK2_MS_ABI restore(uint64_t tpl) { (void)tpl; }
static uint64_t CDK2_MS_ABI create(uint32_t type, uint64_t priority,
	void (CDK2_MS_ABI *function)(void *, void *), void *context, void **event)
{
	(void)type; (void)priority; (void)function; (void)context;
	*event = (void *)1;
	return 0;
}
static uint64_t CDK2_MS_ABI get(const uint16_t *name, const struct guid *guid,
	uint32_t *attributes, size_t *size, void *value)
{
	(void)name; (void)guid; (void)attributes; (void)size;
	*(uint32_t *)value = 4;
	return 0;
}
static uint64_t CDK2_MS_ABI set(const uint16_t *name, const struct guid *guid,
	uint32_t attributes, size_t size, const void *value)
{
	(void)name; (void)guid; (void)attributes; (void)size;
	saved = *(const uint32_t *)value;
	return 0;
}
static uint64_t CDK2_MS_ABI install(void **handle, const struct guid *guid,
	void *interface, ...)
{
	(void)handle; (void)guid; (void)interface;
	return 0;
}
int main(void)
{
	struct boot_services_view bs = { 0 };
	struct runtime_services_view rt = { 0 };
	struct system_table_view st = { 0 };
	uint64_t value;
	uint32_t high;

	bs.raise_tpl = raise; bs.restore_tpl = restore; bs.create_event = create;
	bs.install_multiple = install; rt.get_variable = get; rt.set_variable = set;
	st.boot = &bs; st.runtime = &rt;
	if (monotonic_counter_entry(NULL, &st) || saved != 5 ||
	    monotonic_get_next(&value) || value != (5ULL << 32) ||
	    monotonic_get_next_high(&high) || high != 6 || saved != 6 ||
	    monotonic_get_next(NULL) != EFI_INVALID_PARAMETER)
		return 1;
	return 0;
}
