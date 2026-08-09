/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <cdk2/esrt_abi.h>
#include "../src/modules/esrt/entry.c"

static EFI_STATUS install_status, event_status;
static EFI_STATUS empty_set_status, lock_set_status, policy_status;
static EFI_STATUS policy_close_status, notify_status;
static EFI_STATUS timer_status;
static EFI_STATUS ready_close_status;
static unsigned int installs, uninstalls, sets, closes, policies, publications;
static unsigned int handle_mode, alloc_calls, fail_alloc_call;
static unsigned int descriptor_mode, policy_missing, notifications;
static unsigned int reverse_fmp_order;
static unsigned int timers;
static unsigned int probe_names, probe_name_frees;
static void *probe_name[8];
static UINTN last_store_bytes;
static struct cdk2_esrt_entry last_store[2];
static UINT32 last_alloc_type;
static struct cdk2_fmp_protocol fmp_protocols[2];
typedef void CDK2_MS_ABI ready_callback_fn(void *, void *);
static ready_callback_fn *ready_callback;
static void *ready_context;
static ready_callback_fn *policy_callback;
static struct cdk2_variable_policy_protocol policy;
static EFI_STATUS CDK2_MS_ABI mock_install(void **handle, ...)
{
	installs++;
	if (EFI_ERROR(install_status))
		return install_status;
	*handle = (void *)7;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_uninstall(void *handle, ...)
{
	assert(handle == (void *)7);
	uninstalls++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_event(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context,
	const EFI_GUID *group, void **event)

{
	ready_callback = notify;
	ready_context = context;
	(void)group;
	assert(type == 0x200 && tpl == 8);
	if (EFI_ERROR(event_status))
		return event_status;
	*event = (void *)9;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_timer(void *event, UINTN type, UINT64 delay)
{
	assert(event == (void *)10 && type == 2 && delay == 10000);
	timers++;
	return timer_status;
}
static EFI_STATUS CDK2_MS_ABI mock_close(void *event)
{
	assert(event == (void *)9 || event == (void *)10);
	closes++;
	if (event == (void *)10 && EFI_ERROR(policy_close_status))
		return policy_close_status;
	if (event == (void *)9 && EFI_ERROR(ready_close_status))
		return ready_close_status;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_policy_event(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context, void **event)
{
	(void)context;
	assert(type == 0x80000200U && tpl == 8);
	policy_callback = notify;
	*event = (void *)10;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_register_notify(EFI_GUID *guid, void *event,
	void **registration)
{
	assert(!memcmp(guid, &policy_guid, sizeof(*guid)) && event == (void *)10);
	*registration = (void *)11;
	notifications++;
	return notify_status;
}
static EFI_STATUS CDK2_MS_ABI mock_set(CHAR16 *name, EFI_GUID *guid, UINT32 attrs,
	UINTN bytes, void *data)
{
	(void)guid;
	(void)data;
	sets++;
	if (name == lock_name) {
		assert(attrs == 2 && bytes == 1);
		return lock_set_status;
	}
	assert(attrs == 2);
	last_store_bytes = bytes;
	if (bytes <= sizeof(last_store) && data != NULL)
		memcpy(last_store, data, bytes);
	if (bytes == 0)
		return empty_set_status;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_get(CHAR16 *name, EFI_GUID *guid, UINT32 *attrs,
	UINTN *bytes, void *data)
{
	(void)name;
	(void)guid;
	(void)attrs;
	(void)bytes;
	(void)data;
	return EFI_NOT_FOUND;
}
static EFI_STATUS CDK2_MS_ABI mock_policy(
	const struct cdk2_variable_policy_entry *rule)
{
	const struct cdk2_variable_lock_state_policy *state;
	const CHAR16 *name, *target;

	policies++;
	assert(rule->version == 0x10000 && rule->size == 102 &&
		rule->offset_to_name == 80 && rule->lock_policy_type == 3);
	assert(!memcmp(&rule->name_space, &caller, sizeof(caller)));
	state = (const void *)(rule + 1);
	assert(!memcmp(&state->name_space, &lock_state_guid, sizeof(lock_state_guid)) &&
		state->value == 1);
	name = (const void *)(state + 1);
	assert(!memcmp(name, lock_name, sizeof(lock_name)));
	target = (const void *)((const UINT8 *)rule + rule->offset_to_name);
	assert(!memcmp(target, non_name, sizeof(non_name)) &&
		(const UINT8 *)(target + 11) == (const UINT8 *)rule + rule->size);
	return policy_status;
}
static EFI_STATUS CDK2_MS_ABI mock_locate(EFI_GUID *guid, void *registration,
	void **interface)
{
	(void)registration;
	assert(!memcmp(guid, &policy_guid, sizeof(*guid)));
	if (policy_missing) {
		policy_missing--;
		return EFI_NOT_FOUND;
	}
	*interface = &policy;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_alloc(UINT32 type, UINTN bytes, void **buffer)
{
	assert(type == 4 || type == 6);
	last_alloc_type = type;
	alloc_calls++;
	if (fail_alloc_call && alloc_calls == fail_alloc_call)
		return EFI_OUT_OF_RESOURCES;
	*buffer = malloc(bytes);
	return *buffer ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}
static EFI_STATUS CDK2_MS_ABI mock_free(void *buffer)
{
	unsigned int index;

	for (index = 0; index < probe_names; index++)
		if (buffer == probe_name[index]) {
			probe_name_frees++;
			probe_name[index] = NULL;
		}
	free(buffer);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_config(EFI_GUID *guid, void *table)
{
	struct cdk2_esrt_table *esrt = table;

	assert(!memcmp(guid, &esrt_table_guid, sizeof(*guid)));
	assert(esrt->resource_count == 0 && esrt->resource_count_max == 0 &&
		esrt->resource_version == 1);
	publications++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_locate_handles(UINTN kind, EFI_GUID *guid,
	void *key, UINTN *count, void ***handles)
{
	void **found;

	(void)guid;
	(void)key;
	assert(kind == 2);
	if (!handle_mode)
		return EFI_NOT_FOUND;
	found = malloc(2 * sizeof(*found));
	assert(found != NULL);
	found[0] = (void *)1; found[1] = (void *)2;
	*count = handle_mode == 2 ? 1 : 2; *handles = found;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_fmp_info(struct cdk2_fmp_protocol *self,
	UINTN *bytes, struct cdk2_fmp_descriptor *descriptors, UINT32 *version,
	UINT8 *count, UINTN *descriptor_size, UINT32 *package, CHAR16 **package_name)
{
	UINTN size = descriptor_mode == 3 ? sizeof(struct cdk2_fmp_descriptor) :
		offsetof(struct cdk2_fmp_descriptor, lowest_supported_version);
	UINTN descriptors_count =
		(descriptor_mode == 1 || descriptor_mode == 2) ? 65 : 1, index;

	if (!descriptors) {
		assert(version != NULL && count != NULL && descriptor_size != NULL &&
		package != NULL && package_name != NULL);
		*version = descriptor_mode == 3 ? 3 : 1;
		*count = descriptors_count; *descriptor_size = size; *package = 0;
		*package_name = malloc(sizeof(CHAR16));
		assert(*package_name != NULL && probe_names < ARRAY_SIZE(probe_name));
		probe_name[probe_names++] = *package_name;
		*bytes = descriptors_count * size;
		return EFI_BUFFER_TOO_SMALL;
	}
	assert(*bytes >= descriptors_count * size);
	memset(descriptors, 0, descriptors_count * size);
	for (index = 0; index < descriptors_count; index++) {
		struct cdk2_fmp_descriptor *d =
			(void *)((UINT8 *)descriptors + index * size);
		d->image_type_id.data1 = descriptor_mode ? 0x11 :
			(self == &fmp_protocols[0] ? 0x11 : 0x22);
		d->version = self == &fmp_protocols[0] ? 3 : 4;
		if (descriptor_mode == 3) {
			d->image_type_id.data1 = 0x33;
			d->version = self == &fmp_protocols[0] ? 8 : 10;
			d->lowest_supported_version = self == &fmp_protocols[0] ? 5 : 7;
			d->last_attempt_version = d->version;
			d->last_attempt_status = self == &fmp_protocols[0] ? 8 : 10;
			if (self == &fmp_protocols[1]) {
				d->attributes_supported = CDK2_ESRT_IMAGE_RESET_REQUIRED;
				d->attributes_setting = CDK2_ESRT_IMAGE_RESET_REQUIRED;
			}
		}
		if (descriptor_mode == 2)
			d->attributes_supported = CDK2_ESRT_IMAGE_IN_USE;
	}
	*version = descriptor_mode == 3 ? 3 : 1;
	*count = descriptors_count; *descriptor_size = size; *package = 0;
	*package_name = NULL; *bytes = descriptors_count * size;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI mock_handle(void *handle, EFI_GUID *guid, void **interface)
{
	(void)guid;
	assert(handle == (void *)1 || handle == (void *)2);
	*interface = &fmp_protocols[((UINTN)handle - 1) ^ reverse_fmp_order];
	return EFI_SUCCESS;
}

int main(void)
{
	EFI_GUID parsed;
	struct cdk2_boot_services_view boot = { 0 };
	struct cdk2_runtime_services_view runtime = { 0 };
	struct cdk2_system_table_view system = { 0 };
	boot.install_multiple = mock_install; boot.uninstall_multiple = mock_uninstall;
	boot.create_event_ex = mock_event; boot.close_event = mock_close;
	boot.create_event = mock_policy_event;
	boot.set_timer = mock_timer;
	boot.register_protocol_notify = mock_register_notify;
	boot.locate_handle_buffer = mock_locate_handles;
	boot.handle_protocol = mock_handle; boot.allocate_pool = mock_alloc;
	boot.free_pool = mock_free; boot.locate_protocol = mock_locate;
	boot.install_configuration_table = mock_config;
	runtime.get_variable = mock_get; runtime.set_variable = mock_set;
	system.boot = &boot; system.runtime = &runtime;
	policy.register_policy = mock_policy;
	assert(parse_guid("00112233-4455-6677-8899-aabbccddeeff", &parsed) &&
		parsed.data1 == 0x00112233 && parsed.data2 == 0x4455 &&
		parsed.data3 == 0x6677 && parsed.data4[0] == 0x88 &&
		parsed.data4[7] == 0xff);
	assert(!parse_guid("00112233-4455-6677-8899-aabbccddeefg", &parsed));
	install_status = EFI_DEVICE_ERROR;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_DEVICE_ERROR && installs == 1 &&
		!uninstalls && closes == 1);
	install_status = 0; event_status = EFI_OUT_OF_RESOURCES;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_OUT_OF_RESOURCES &&
		installs == 1 && !uninstalls);
	event_status = 0;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS && instance.ready_event == (void *)9);
	assert(instance.reboot_capsule_flags == 0x00050000U);
	empty_set_status = EFI_NOT_FOUND;
	assert(management.sync_fmp() == EFI_SUCCESS);
	assert(ready_callback != NULL && ready_context == &instance);
	ready_callback((void *)9, ready_context);
	assert(instance.locked && publications == 1 && instance.ready_event == NULL &&
		closes == 2 && last_alloc_type == 6);
	assert(policies == 3);
	/* An early management lock freezes inventory but cannot suppress publication. */
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS);
	assert(management.lock() == EFI_SUCCESS);
	{
		unsigned int before = sets;
		ready_callback((void *)9, ready_context);
		assert(sets == before && publications == 2 && instance.ready_event == NULL);
	}
	/* Policy availability may lag DXE dispatch without changing admitted DEPEX. */
	policy_missing = 2;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS && notifications == 1 &&
		policy_callback != NULL && policy_event == (void *)10);
	install_status = EFI_DEVICE_ERROR;
	policy_callback((void *)10, NULL);
	assert(policy_event == (void *)10 && !instance.management_installed && timers == 1);
	install_status = EFI_SUCCESS;
	/* The one-shot timer, not a second protocol installation, drives retry. */
	policy_callback((void *)10, NULL);
	assert(policy_event == NULL && instance.management_installed);
	{
		unsigned int before = installs;
		policy_callback((void *)10, NULL);
		assert(installs == before);
	}
	/* A policy installed in the Locate/Register window activates synchronously. */
	policy_missing = 1;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS && policy_event == NULL &&
		instance.management_installed);
	/* Fatal synchronous setup errors fully unwind, or retain the live image. */
	policy_missing = 1; policy_status = EFI_DEVICE_ERROR;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_DEVICE_ERROR && policy_event == NULL);
	policy_missing = 1; policy_close_status = EFI_DEVICE_ERROR;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS && policy_event == (void *)10);
	policy_close_status = EFI_SUCCESS; policy_status = EFI_SUCCESS;
	policy_callback((void *)10, NULL);
	assert(policy_event == NULL && instance.management_installed);
	policy_missing = 1; notify_status = EFI_DEVICE_ERROR;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_DEVICE_ERROR && policy_event == NULL);
	policy_missing = 1; policy_close_status = EFI_DEVICE_ERROR;
	{
		unsigned int before = timers;
		assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS &&
			policy_event == (void *)10);
		assert(timers == before + 1);
	}
	policy_close_status = EFI_SUCCESS; notify_status = EFI_SUCCESS;
	policy_callback((void *)10, NULL);
	assert(policy_event == NULL && instance.management_installed);
	/* A failed timer arm tears down when possible without a dangling callback. */
	policy_missing = 2; timer_status = EFI_DEVICE_ERROR;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS);
	install_status = EFI_DEVICE_ERROR;
	policy_callback((void *)10, NULL);
	assert(policy_event == NULL);
	install_status = EFI_SUCCESS; timer_status = EFI_SUCCESS;
	/* Transient activation retries are bounded even when every timer fires. */
	policy_missing = 2; install_status = EFI_DEVICE_ERROR;
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS);
	{
		unsigned int before = timers;
		policy_callback((void *)10, NULL);
		policy_callback((void *)10, NULL);
		policy_callback((void *)10, NULL);
		assert(timers == before + 3 && policy_event == (void *)10);
		policy_callback((void *)10, NULL);
		assert(timers == before + 3 && policy_event == NULL);
	}
	install_status = EFI_SUCCESS;
	/* A later enumeration failure must not commit an earlier FMP descriptor. */
	instance.locked = FALSE;
	fmp_protocols[0].get_image_info = mock_fmp_info;
	fmp_protocols[1].get_image_info = mock_fmp_info;
	handle_mode = 1; alloc_calls = 0; fail_alloc_call = 2;
	{
		unsigned int before = sets;
		assert(management.sync_fmp() == EFI_OUT_OF_RESOURCES && sets == before);
	}
	probe_names = probe_name_frees = 0;
	/* Version-one descriptors end before LowestSupportedVersion and remain valid. */
	alloc_calls = 0; fail_alloc_call = 0; last_store_bytes = 0;
	assert(management.sync_fmp() == EFI_SUCCESS &&
		last_store_bytes == 2 * sizeof(struct cdk2_esrt_entry) &&
		probe_names == 2 && probe_name_frees == 2);
	/* Filter duplicate and inactive descriptors before enforcing scratch capacity. */
	handle_mode = 2; descriptor_mode = 1; alloc_calls = 0; last_store_bytes = 0;
	assert(management.sync_fmp() == EFI_SUCCESS &&
		last_store_bytes == sizeof(struct cdk2_esrt_entry));
	descriptor_mode = 2; last_store_bytes = ~(UINTN)0;
	assert(management.sync_fmp() == EFI_SUCCESS && last_store_bytes == 0);
	/* api_sync must not discard restrictive metadata on a higher-version duplicate. */
	handle_mode = 3; descriptor_mode = 3; last_store_bytes = 0;
	assert(management.sync_fmp() == EFI_SUCCESS &&
		last_store_bytes == sizeof(struct cdk2_esrt_entry) &&
		last_store[0].firmware_version == 8 &&
		last_store[0].lowest_supported_version == 7 &&
		last_store[0].capsule_flags == 0x00050000U &&
		last_store[0].last_attempt_version == 8 &&
		last_store[0].last_attempt_status == 8);
	reverse_fmp_order = 1; last_store_bytes = 0;
	assert(management.sync_fmp() == EFI_SUCCESS &&
		last_store_bytes == sizeof(struct cdk2_esrt_entry) &&
		last_store[0].firmware_version == 8 &&
		last_store[0].lowest_supported_version == 7 &&
		last_store[0].capsule_flags == 0x00050000U &&
		last_store[0].last_attempt_version == 8 &&
		last_store[0].last_attempt_status == 8);
	reverse_fmp_order = 0;
	descriptor_mode = 0;
	handle_mode = 0;
	/* Every stage is fail-closed: sync, lock, then publication. */
	assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS);
	empty_set_status = EFI_DEVICE_ERROR;
	ready_callback((void *)9, ready_context);
	assert(publications == 2 && !instance.locked);
	empty_set_status = EFI_NOT_FOUND;
	lock_set_status = EFI_WRITE_PROTECTED;
	ready_callback((void *)9, ready_context);
	assert(publications == 2 && !instance.locked);
	lock_set_status = EFI_SUCCESS;
	/* Failed activation rollback remains resident and retries install at Ready. */
	{
		unsigned int before = publications;

		install_status = EFI_DEVICE_ERROR; ready_close_status = EFI_DEVICE_ERROR;
		assert(cdk2_esrt_entry(NULL, &system) == EFI_SUCCESS &&
			!instance.management_installed && instance.ready_event == (void *)9);
		install_status = EFI_SUCCESS; ready_close_status = EFI_SUCCESS;
		ready_callback((void *)9, ready_context);
		assert(instance.management_installed && instance.ready_event == NULL &&
			publications == before + 1 && last_alloc_type == 6);
	}
	assert(cdk2_esrt_entry(NULL, NULL) == EFI_INVALID_PARAMETER);
	return 0;
}
