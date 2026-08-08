/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/esrt.h>
#include <cdk2/esrt_abi.h>
#include <cdk2/config.h>

#define BS_ONLY 2U
#define ALREADY_STARTED EFIERR(20)
#define EVT_TIMER 0x80000000U
#define EVT_NOTIFY_SIGNAL 0x200U
#define TPL_CALLBACK 8U
#define TIMER_RELATIVE 2U
#define POLICY_RETRY_DELAY_100NS 10000ULL
#define POLICY_RETRY_MAX 3U
#define BY_PROTOCOL 2U
#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET 0x00010000U
#define CAPSULE_FLAGS_INITIATE_RESET 0x00040000U
#if CONFIG_CDK2_CAPSULE
#define CDK2_ESRT_MAIN_FW_GUID CONFIG_CDK2_CAPSULE_MAIN_FW_GUID
#else
#define CDK2_ESRT_MAIN_FW_GUID ""
#endif
typedef EFI_STATUS CDK2_MS_ABI get_variable_fn(CHAR16 *, EFI_GUID *, UINT32 *, UINTN *, void *);
typedef EFI_STATUS CDK2_MS_ABI set_variable_fn(CHAR16 *, EFI_GUID *, UINT32, UINTN, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI install_config_fn(EFI_GUID *, void *);
typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI locate_handle_buffer_fn(UINTN, EFI_GUID *, void *,
	UINTN *, void ***);
typedef EFI_STATUS CDK2_MS_ABI handle_protocol_fn(void *, EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI register_protocol_notify_fn(EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI set_timer_fn(void *, UINTN, UINT64);

static const EFI_GUID caller = { 0x999bd818, 0x7df7, 0x4a9a,
	{ 0xa5, 0x02, 0x9b, 0x75, 0x03, 0x3e, 0x6a, 0x0f } };
static const EFI_GUID esrt_table_guid = { 0xb122a263, 0x3661, 0x4f68,
	{ 0x99, 0x29, 0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80 } };
static const EFI_GUID management_guid = { 0xa340c064, 0x723c, 0x4a9c,
	{ 0xa4, 0xdd, 0xd5, 0xb4, 0x7a, 0x26, 0xfb, 0xb0 } };
static const EFI_GUID ready_guid = { 0x7ce88fb3, 0x4bd7, 0x4679,
	{ 0x87, 0xa8, 0xa8, 0xd8, 0xde, 0xe5, 0x0d, 0x2b } };
static const EFI_GUID policy_guid = { 0x81d1675c, 0x86f6, 0x48df,
	{ 0xbd, 0x95, 0x9a, 0x6e, 0x4f, 0x09, 0x25, 0xc3 } };
static const EFI_GUID fmp_guid = { 0x86c77a67, 0x0b97, 0x4633,
	{ 0xa1, 0x87, 0x49, 0x10, 0x4d, 0x06, 0x85, 0xc7 } };
static const EFI_GUID lock_state_guid = { 0x5b2f6f36, 0x17e5, 0x47af,
	{ 0x9e, 0x8d, 0x29, 0xe0, 0xa3, 0xe9, 0x63, 0x65 } };
static CHAR16 fmp_name[] = L"EsrtFmp", non_name[] = L"EsrtNonFmp";
static CHAR16 lock_name[] = L"EsrtLock";
struct cdk2_esrt_lock_rule {
	struct cdk2_variable_policy_entry p;
	struct cdk2_variable_lock_state_policy state;
	CHAR16 state_name[9];
	CHAR16 target_name[11];
} __packed;
typedef char lock_rule_size_check[sizeof(struct cdk2_esrt_lock_rule) == 102 ? 1 : -1];
typedef char lock_rule_state_check[
	offsetof(struct cdk2_esrt_lock_rule, state) == 44 ? 1 : -1];
typedef char lock_rule_name_check[
	offsetof(struct cdk2_esrt_lock_rule, state_name) == 62 ? 1 : -1];
typedef char lock_rule_target_check[
	offsetof(struct cdk2_esrt_lock_rule, target_name) == 80 ? 1 : -1];
static struct cdk2_system_table_view *st;
static struct cdk2_esrt instance;
static EFI_GUID system_class_guid;
static void *management_handle;
static void *policy_event, *policy_registration;
static BOOLEAN policy_started;
static UINTN policy_retries;
static EFI_STATUS CDK2_MS_ABI api_sync(void);

struct esrt_management_protocol {
	EFI_STATUS(CDK2_MS_ABI *get)(EFI_GUID *, struct cdk2_esrt_entry *);
	EFI_STATUS(CDK2_MS_ABI *update)(struct cdk2_esrt_entry *);
	EFI_STATUS(CDK2_MS_ABI *register_entry)(struct cdk2_esrt_entry *);
	EFI_STATUS(CDK2_MS_ABI *unregister_entry)(EFI_GUID *);
	EFI_STATUS(CDK2_MS_ABI *sync_fmp)(void);
	EFI_STATUS(CDK2_MS_ABI *lock)(void);
};

static CHAR16 *store_name(enum cdk2_esrt_store which)
{ return which == CDK2_ESRT_FMP ? fmp_name : non_name; }
static EFI_STATUS read_store(void *context, enum cdk2_esrt_store which,
	struct cdk2_esrt_entry *entries, UINTN capacity,
	UINTN count[static 1])
{
	get_variable_fn *get = (void *)st->runtime->get_variable;
	UINTN bytes;
	EFI_STATUS status;

	(void)context;
	if (!get)
		return EFI_UNSUPPORTED;
	bytes = capacity * sizeof(*entries);
	status = get(store_name(which), (EFI_GUID *)&caller, NULL, &bytes, entries);
	if (!EFI_ERROR(status) && bytes % sizeof(*entries))
		return EFI_COMPROMISED_DATA;
	if (!EFI_ERROR(status))
		*count = bytes / sizeof(*entries);
	return status;
}
static EFI_STATUS write_store(void *context, enum cdk2_esrt_store which,
	const struct cdk2_esrt_entry *entries, UINTN count)
{
	set_variable_fn *set = (void *)st->runtime->set_variable; (void)context;
	EFI_STATUS status;

	if (!set)
		return EFI_UNSUPPORTED;
	status = set(store_name(which), (EFI_GUID *)&caller, BS_ONLY,
		count * sizeof(*entries), (void *)entries);
	/* Deleting an absent empty store is already the desired synchronized state. */
	return count == 0 && status == EFI_NOT_FOUND ? EFI_SUCCESS : status;
}
static EFI_STATUS lock_one(void *context, enum cdk2_esrt_store which)
{
	set_variable_fn *set = (void *)st->runtime->set_variable;
	UINT8 locked = 1;

	(void)context;
	if (which == CDK2_ESRT_FMP)
		return EFI_SUCCESS;
	return set ? set(lock_name, (EFI_GUID *)&lock_state_guid, BS_ONLY,
		sizeof(locked), &locked) : EFI_UNSUPPORTED;
}

static EFI_STATUS register_lock_policy(void)
{
	struct cdk2_esrt_lock_rule rule = { 0 };
	struct cdk2_variable_policy_protocol *policy;
	locate_protocol_fn *locate = (void *)st->boot->locate_protocol;
	UINTN i;
	EFI_STATUS status;

	if (!locate)
		return EFI_UNSUPPORTED;
	status = locate((EFI_GUID *)&policy_guid, NULL, (void **)&policy);
	if (EFI_ERROR(status))
		return status;
	rule.p.version = 0x10000;
	rule.p.size = sizeof(rule);
	rule.p.offset_to_name = offsetof(struct cdk2_esrt_lock_rule, target_name);
	rule.p.name_space = caller;
	rule.p.max_size = MAX_UINT32;
	rule.p.lock_policy_type = 3;
	rule.state.name_space = lock_state_guid;
	rule.state.value = 1;
	for (i = 0; i < ARRAY_SIZE(rule.state_name); i++)
		rule.state_name[i] = lock_name[i];
	for (i = 0; i < ARRAY_SIZE(rule.target_name); i++)
		rule.target_name[i] = non_name[i];
	status = policy->register_policy(&rule.p);
	return status == ALREADY_STARTED ? EFI_SUCCESS : status;
}
static EFI_STATUS publish_table(void *context, const struct cdk2_esrt_table *table, UINTN bytes)
{
	allocate_pool_fn *alloc = (void *)st->boot->allocate_pool;
	install_config_fn *install;
	UINT8 *copy, *d; const UINT8 *s; UINTN i; (void)context;
	install = (void *)st->boot->install_configuration_table;
	if (!alloc || !install)
		return EFI_UNSUPPORTED;
	EFI_STATUS status = alloc(6U, bytes, (void **)&copy);

	if (EFI_ERROR(status))
		return status;
	d = copy; s = (const UINT8 *)table; for (i = 0; i < bytes; i++) d[i] = s[i];
	status = install((EFI_GUID *)&esrt_table_guid, copy);
	if (EFI_ERROR(status) && st->boot->free_pool)
		((free_pool_fn *)st->boot->free_pool)(copy);
	return status;
}
static struct esrt_management_protocol management;
static EFI_STATUS install_management(void *c, void *p)
{
	install_multiple_fn *fn = st->boot->install_multiple;

	(void)c;
	(void)p;
	return fn ? fn(&management_handle, &management_guid, &management, NULL) :
		EFI_UNSUPPORTED;
}
static EFI_STATUS uninstall_management(void *c, void *p)
{
	uninstall_multiple_fn *fn = st->boot->uninstall_multiple;

	(void)c;
	(void)p;
	return fn ? fn(management_handle, &management_guid, &management, NULL) :
		EFI_UNSUPPORTED;
}
static void CDK2_MS_ABI ready_notify(void *event, void *context)
{
	EFI_STATUS status;

	(void)event;
	if (!instance.management_installed) {
		status = install_management(NULL, context);
		if (EFI_ERROR(status))
			return;
		instance.management_installed = TRUE;
	}
	if (!instance.locked) {
		status = api_sync();
		if (EFI_ERROR(status))
			return;
		status = cdk2_esrt_lock(context);
		if (EFI_ERROR(status))
			return;
	}
	(void)cdk2_esrt_ready_to_boot(context);
}
static EFI_STATUS create_ready(void *c, void *context, void **event)

{
	create_event_ex_fn *fn = (void *)st->boot->create_event_ex;

	(void)c;
	return fn ? fn(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, ready_notify, context,
		(EFI_GUID *)&ready_guid, event) : EFI_UNSUPPORTED;
}
static EFI_STATUS close_ready(void *c, void *event)
{
	close_event_fn *fn = (void *)st->boot->close_event;

	(void)c;
	return fn ? fn(event) : EFI_UNSUPPORTED;
}
static const struct cdk2_esrt_ops ops = { read_store, write_store, lock_one, publish_table,
	install_management, uninstall_management, create_ready, close_ready };

static EFI_STATUS CDK2_MS_ABI api_get(EFI_GUID *id, struct cdk2_esrt_entry *entry)
{ return cdk2_esrt_get(&instance, id, entry); }
static EFI_STATUS CDK2_MS_ABI api_update(struct cdk2_esrt_entry *entry)
{ return cdk2_esrt_update(&instance, entry); }
static EFI_STATUS CDK2_MS_ABI api_register(struct cdk2_esrt_entry *entry)
{ return cdk2_esrt_register(&instance, entry); }
static EFI_STATUS CDK2_MS_ABI api_unregister(EFI_GUID *id)
{ return cdk2_esrt_unregister(&instance, id); }
static EFI_STATUS CDK2_MS_ABI api_lock(void) { return cdk2_esrt_lock(&instance); }

static int hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static BOOLEAN parse_hex(const char **cursor, UINTN digits, UINT64 *value)
{
	UINTN i;
	int digit;

	*value = 0;
	for (i = 0; i < digits; i++) {
		digit = hex_digit((*cursor)[i]);
		if (digit < 0)
			return FALSE;
		*value = (*value << 4) | (UINTN)digit;
	}
	*cursor += digits;
	return TRUE;
}

static BOOLEAN parse_guid(const char *text, EFI_GUID *guid)
{
	const char *p = text;
	UINT64 value;
	UINTN i;

	if (!text || !text[0] || !parse_hex(&p, 8, &value) || *p++ != '-')
		return FALSE;
	guid->data1 = (UINT32)value;
	if (!parse_hex(&p, 4, &value) || *p++ != '-')
		return FALSE;
	guid->data2 = (UINT16)value;
	if (!parse_hex(&p, 4, &value) || *p++ != '-')
		return FALSE;
	guid->data3 = (UINT16)value;
	for (i = 0; i < 2; i++) {
		if (!parse_hex(&p, 2, &value))
			return FALSE;
		guid->data4[i] = (UINT8)value;
	}
	if (*p++ != '-')
		return FALSE;
	for (; i < ARRAY_SIZE(guid->data4); i++) {
		if (!parse_hex(&p, 2, &value))
			return FALSE;
		guid->data4[i] = (UINT8)value;
	}
	return *p == '\0';
}

static BOOLEAN descriptor_fits(UINT32 version, UINTN size)
{
	UINTN required;

	if (version < 1)
		return FALSE;
	required = offsetof(struct cdk2_fmp_descriptor, lowest_supported_version);
	if (version >= 2)
		required = offsetof(struct cdk2_fmp_descriptor, lowest_supported_version) +
			sizeof(((struct cdk2_fmp_descriptor *)0)->lowest_supported_version);
	if (version >= 3)
		required = offsetof(struct cdk2_fmp_descriptor, last_attempt_status) +
			sizeof(((struct cdk2_fmp_descriptor *)0)->last_attempt_status);
	return size >= required;
}

static BOOLEAN same_guid(const EFI_GUID *a, const EFI_GUID *b)
{
	const UINT8 *x = (const UINT8 *)a, *y = (const UINT8 *)b;
	UINTN i;

	for (i = 0; i < sizeof(*a); i++)
		if (x[i] != y[i])
			return FALSE;
	return TRUE;
}

static EFI_STATUS CDK2_MS_ABI api_sync(void)
{
	locate_handle_buffer_fn *locate = (void *)st->boot->locate_handle_buffer;
	handle_protocol_fn *handle = (void *)st->boot->handle_protocol;
	allocate_pool_fn *alloc = (void *)st->boot->allocate_pool;
	free_pool_fn *free = (void *)st->boot->free_pool;
	struct cdk2_esrt_fmp_image images[64]; void **handles = NULL; UINTN handle_count = 0;
	UINTN total = 0, h, i, info_size, descriptor_size; UINT32 version, package;
	UINT8 count; CHAR16 *package_name; EFI_STATUS status;
	if (!locate || !handle || !alloc || !free)
		return EFI_UNSUPPORTED;
	status = locate(BY_PROTOCOL, (EFI_GUID *)&fmp_guid, NULL, &handle_count, &handles);
	if (status == EFI_NOT_FOUND)
		return cdk2_esrt_sync_fmp(&instance, NULL, 0, NULL);
	if (EFI_ERROR(status))
		return status;
	for (h = 0; h < handle_count; h++) {
		struct cdk2_fmp_protocol *fmp; struct cdk2_fmp_descriptor *descriptors = NULL;
		status = handle(handles[h], (EFI_GUID *)&fmp_guid, (void **)&fmp);
		if (EFI_ERROR(status))
			break;
		if (!fmp || !fmp->get_image_info) {
			status = EFI_COMPROMISED_DATA;
			break;
		}
		info_size = 0; package_name = NULL; count = 0; descriptor_size = 0;
		version = 0; package = 0;
		status = fmp->get_image_info(fmp, &info_size, NULL, &version, &count,
			&descriptor_size, &package, &package_name);
		if (package_name != NULL) {
			(void)free(package_name);
			package_name = NULL;
		}
		if (status != EFI_BUFFER_TOO_SMALL || !info_size) {
			status = EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
			break;
		}
		status = alloc(4U, info_size, (void **)&descriptors);
		if (EFI_ERROR(status))
			break;
		package_name = NULL; count = 0; descriptor_size = 0; version = 0;
		status = fmp->get_image_info(fmp, &info_size, descriptors, &version, &count,
			&descriptor_size, &package, &package_name);
		if (!EFI_ERROR(status) && descriptor_fits(version, descriptor_size) &&
		    count <= info_size / descriptor_size) {
			for (i = 0; i < count; i++) {
				struct cdk2_fmp_descriptor *d =
					(void *)((UINT8 *)descriptors + i * descriptor_size);
				UINTN existing;

				if ((d->attributes_supported & CDK2_ESRT_IMAGE_IN_USE) &&
				    !(d->attributes_setting & CDK2_ESRT_IMAGE_IN_USE))
					continue;
				for (existing = 0; existing < total; existing++)
					if (same_guid(&images[existing].image_type_id,
					    &d->image_type_id))
						break;
				if (existing < total) {
					if (images[existing].version <= d->version)
						continue;
				} else {
					existing = total;
				}
				if (existing == total && total == ARRAY_SIZE(images)) {
					status = EFI_OUT_OF_RESOURCES;
					break;
				}
				images[existing] = (struct cdk2_esrt_fmp_image){
					d->image_type_id, d->version, d->attributes_supported,
					d->attributes_setting,
					version >= 2 ? d->lowest_supported_version : 0,
					version >= 3 ? d->last_attempt_version : 0,
					version >= 3 ? d->last_attempt_status : 0, version };
				if (existing == total)
					total++;
			}
		} else if (!EFI_ERROR(status)) {
			status = EFI_COMPROMISED_DATA;
		}
		if (package_name)
			(void)free(package_name);
		(void)free(descriptors);
		if (EFI_ERROR(status))
			break;
	}
	(void)free(handles);
	if (EFI_ERROR(status))
		return status;
	return cdk2_esrt_sync_fmp(&instance, images, total, NULL);
}

static EFI_STATUS start_after_policy(void *event)
{
	close_event_fn *close = (void *)st->boot->close_event;
	EFI_STATUS status;

	if (!policy_started) {
		status = register_lock_policy();
		if (EFI_ERROR(status))
			return status;
		status = cdk2_esrt_activate(&instance);
		if (EFI_ERROR(status))
			return status;
		policy_started = TRUE;
	}
	if (close && !EFI_ERROR(close(event)))
		policy_event = NULL;
	return EFI_SUCCESS;
}

static void schedule_policy_retry(void *event)
{
	set_timer_fn *set_timer = (void *)st->boot->set_timer;
	close_event_fn *close = (void *)st->boot->close_event;

	if (policy_retries < POLICY_RETRY_MAX && set_timer &&
	    !EFI_ERROR(set_timer(event, TIMER_RELATIVE, POLICY_RETRY_DELAY_100NS))) {
		policy_retries++;
		return;
	}
	/* If teardown fails, the successfully loaded image remains resident and safe. */
	if (close && !EFI_ERROR(close(event)))
		policy_event = NULL;
}

static void CDK2_MS_ABI policy_notify(void *event, void *context)
{
	EFI_STATUS status;

	(void)context;
	status = start_after_policy(event);
	if (EFI_ERROR(status))
		schedule_policy_retry(event);
}

EFI_STATUS CDK2_MS_ABI cdk2_esrt_entry(void *image, struct cdk2_system_table_view *system)
{
	EFI_STATUS status;

	(void)image;
	if (!system || !system->boot || !system->runtime)
		return EFI_INVALID_PARAMETER;
	st = system; management_handle = NULL; policy_event = NULL; policy_registration = NULL;
	policy_started = FALSE; policy_retries = 0;
	instance = (struct cdk2_esrt){ &ops, NULL, 32, 32,
		CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET,
		NULL, 0, FALSE, FALSE, NULL };
	if (CDK2_ESRT_MAIN_FW_GUID[0]) {
		if (!parse_guid(CDK2_ESRT_MAIN_FW_GUID, &system_class_guid))
			return EFI_INVALID_PARAMETER;
		instance.system_classes = &system_class_guid;
		instance.system_class_count = 1;
	}
	management = (struct esrt_management_protocol){ api_get, api_update, api_register,
		api_unregister, api_sync, api_lock };
	status = register_lock_policy();
	if (status == EFI_NOT_FOUND) {
		create_event_fn *create = (void *)st->boot->create_event;
		register_protocol_notify_fn *notify =
			(void *)st->boot->register_protocol_notify;

		if (!create || !notify)
			return EFI_UNSUPPORTED;
		status = create(EVT_TIMER | EVT_NOTIFY_SIGNAL, TPL_CALLBACK, policy_notify, NULL,
			&policy_event);
		if (EFI_ERROR(status))
			return status;
		status = notify((EFI_GUID *)&policy_guid, policy_event,
			&policy_registration);
		if (EFI_ERROR(status)) {
			EFI_STATUS close_status = st->boot->close_event ?
				((close_event_fn *)st->boot->close_event)(policy_event) :
				EFI_UNSUPPORTED;

			if (EFI_ERROR(close_status))
				return EFI_SUCCESS;
			policy_event = NULL;
			return status;
		}
		/* Close the Locate/Register race if installation preceded registration. */
		status = register_lock_policy();
		if (status == EFI_NOT_FOUND)
			return EFI_SUCCESS;
		if (EFI_ERROR(status)) {
			EFI_STATUS close_status = st->boot->close_event ?
				((close_event_fn *)st->boot->close_event)(policy_event) :
				EFI_UNSUPPORTED;

			if (EFI_ERROR(close_status))
				return EFI_SUCCESS;
			policy_event = NULL;
			return status;
		}
		status = start_after_policy(policy_event);
		if (EFI_ERROR(status)) {
			schedule_policy_retry(policy_event);
			/* A live callback requires the image to remain resident for retry. */
			return EFI_SUCCESS;
		}
		return status;
	}
	if (EFI_ERROR(status))
		return status;
	return cdk2_esrt_activate(&instance);
}
