/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ftw_entry.h>
#include <cdk2/ftw_fvb.h>
#include <cdk2/ftw_geometry.h>
#include <cdk2/ftw_pi.h>

#define HOB_TYPE_GUID_EXTENSION 0x0004U
#define HOB_TYPE_END_OF_LIST 0xffffU
#define MAX_HOB_LIST_SIZE SIZE_1MB
#define EVT_NOTIFY_SIGNAL 0x200U
#define TPL_CALLBACK 8U
#define BY_PROTOCOL 2U
#define POOL_BOOT_SERVICES_DATA 4U
#define EFI_LBA_LIST_TERMINATOR MAX_UINT64
#define EFI_ALREADY_STARTED EFIERR(20)

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI register_notify_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI handle_protocol_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI locate_handles_fn(UINT32, const EFI_GUID *, void *,
	UINTN *, void ***);
typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_protocol_fn(void **, const EFI_GUID *, UINT32, void *);

struct hob_header {
	UINT16 type, length;
	UINT32 reserved;
};
struct guid_hob {
	struct hob_header header;
	EFI_GUID name;
};

struct ftw_entry_context {
	struct cdk2_boot_services_view *boot;
	void *image, *protocol_handle, *notify_event, *notify_registration;
	struct cdk2_ftw_geometry geometry;
	struct cdk2_ftw_fvb adapter;
	struct cdk2_fvb_protocol_view *fvb;
	UINT64 fvb_base;
	UINT8 *scratch, *workspace;
	BOOLEAN workspace_loaded, installed;
	struct cdk2_ftw_protocol_view protocol;
};

static struct ftw_entry_context entry;
static const EFI_GUID hob_list_guid = { 0x7739f24c, 0x93d7, 0x11d4,
	{ 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID smmstore_guid = { 0xf585ca19, 0x881b, 0x44fb,
	{ 0x3f, 0x3d, 0x81, 0x89, 0x7c, 0x57, 0xbb, 0x01 }
};
static const EFI_GUID fvb_guid = { 0x8f644fa9, 0xe850, 0x4db1,
	{ 0x9c, 0xe2, 0x0b, 0x44, 0x69, 0x8e, 0x8d, 0xa4 }
};
static const EFI_GUID runtime_arch_guid = { 0xb7dfb4e1, 0x052f, 0x449f,
	{ 0x87, 0xbe, 0x98, 0x18, 0xfc, 0x91, 0xb7, 0x33 }
};
static const EFI_GUID ftw_guid = { 0x3ebd9e82, 0x2c78, 0x4de6,
	{ 0x97, 0x86, 0x8d, 0x4b, 0xfc, 0xb7, 0xc8, 0x81 }
};

static void *boot_slot(UINTN offset)
{
	return *(void **)((UINT8 *)entry.boot + offset);
}

static BOOLEAN guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	const UINT8 *left = (const void *)a, *right = (const void *)b;
	UINTN index;
	for (index = 0; index < sizeof(*a); index++)
		if (left[index] != right[index])
			return FALSE;
	return TRUE;
}

static const SMMSTORE_INFO *find_smmstore(const struct cdk2_ftw_system_table_view *system)
{
	const UINT8 *list = NULL;
	const struct hob_header *hob;
	UINTN index, walked = 0;
	for (index = 0; index < system->table_count; index++)
		if (guid_equal(&system->tables[index].guid, &hob_list_guid)) {
			list = system->tables[index].table;
			break;
		}
	if (list == NULL)
		return NULL;
	hob = (const void *)list;
	while (walked + sizeof(*hob) <= MAX_HOB_LIST_SIZE) {
		const struct guid_hob *guid;
		if (hob->type == HOB_TYPE_END_OF_LIST)
			return NULL;
		if (hob->length < sizeof(*hob) || hob->length > MAX_HOB_LIST_SIZE - walked)
			return NULL;
		guid = (const void *)hob;
		if (hob->type == HOB_TYPE_GUID_EXTENSION &&
		   hob->length >= sizeof(*guid) + sizeof(SMMSTORE_INFO) &&
		   guid_equal(&guid->name, &smmstore_guid))
			return (const void *)(guid + 1);
		walked += hob->length;
		hob = (const void *)(list + walked);
	}
	return NULL;
}

static EFI_STATUS block_size(void *context, void *volume, UINT64 lba, UINTN *size)
{
	UINTN blocks;
	(void)context;
	return ((struct cdk2_fvb_protocol_view *)volume)->get_block_size(volume, lba,
									 size, &blocks);
}
static EFI_STATUS block_read(void *context, void *volume, UINT64 lba,
			     void *buffer, UINTN size)
{
	UINTN bytes = size;
	EFI_STATUS status;
	(void)context;
	status = ((struct cdk2_fvb_protocol_view *)volume)->read(volume, lba, 0, &bytes,
		 buffer);
	return !EFI_ERROR(status) && bytes != size ? EFI_DEVICE_ERROR : status;
}
static EFI_STATUS block_write(void *context, void *volume, UINT64 lba,
			      const void *buffer, UINTN size)
{
	UINTN bytes = size;
	EFI_STATUS status;
	(void)context;
	status = ((struct cdk2_fvb_protocol_view *)volume)->write(volume, lba, 0, &bytes,
		 buffer);
	return !EFI_ERROR(status) && bytes != size ? EFI_DEVICE_ERROR : status;
}
static EFI_STATUS block_erase(void *context, void *volume, UINT64 lba, UINTN count)
{
	(void)context;
	return ((struct cdk2_fvb_protocol_view *)volume)->erase_blocks(volume, lba,
								       count, EFI_LBA_LIST_TERMINATOR);
}
static BOOLEAN is_boot(void *context, void *volume)
{
	(void)context;
	(void)volume;
	return FALSE;
}

static EFI_STATUS workspace_load(void)
{
	UINTN bytes = entry.geometry.working_size;
	EFI_STATUS status = entry.fvb->read(entry.fvb, entry.adapter.working_lba, 0,
					    &bytes, entry.workspace);
	if (!EFI_ERROR(status) && bytes != entry.geometry.working_size)
		return EFI_DEVICE_ERROR;
	if (!EFI_ERROR(status))
		entry.workspace_loaded = TRUE;
	return status;
}
static EFI_STATUS journal_read(void *context, struct cdk2_ftw_journal *journal)
{
	UINTN index;
	BOOLEAN erased = TRUE;
	EFI_STATUS status;
	(void)context;
	if (!entry.workspace_loaded) {
		status = workspace_load();
		if (EFI_ERROR(status))
			return status;
	}
	for (index = 0; index < entry.geometry.working_size; index++)
		if (entry.workspace[index] != 0xffU) {
			erased = FALSE;
			break;
		}
	if (erased)
		return EFI_NOT_FOUND;
	return cdk2_ftw_pi_decode(entry.workspace, entry.geometry.working_size, journal);
}
static EFI_STATUS journal_write(void *context, const struct cdk2_ftw_journal *journal)
{
	UINTN index, bytes;
	BOOLEAN erase = FALSE;
	EFI_STATUS status;
	(void)context;
	if (!entry.workspace_loaded) {
		status = workspace_load();
		if (EFI_ERROR(status))
			return status;
	}
	for (index = 0; index < entry.geometry.working_size; index++)
		entry.scratch[index] = entry.workspace[index];
	if (entry.workspace[0] == 0xffU)
		status = cdk2_ftw_pi_initialize(entry.workspace, entry.geometry.working_size);
	else
		status = EFI_SUCCESS;
	if (!EFI_ERROR(status))
		status = cdk2_ftw_pi_encode(entry.workspace,
			entry.geometry.working_size, journal);
	if (EFI_ERROR(status))
		return status;
	for (index = 0; index < entry.geometry.working_size; index++)
		if ((entry.scratch[index] & entry.workspace[index]) != entry.workspace[index]) {
			erase = TRUE;
			break;
		}
	if (erase) {
		status = entry.fvb->erase_blocks(entry.fvb, entry.adapter.working_lba, 1U,
						 EFI_LBA_LIST_TERMINATOR);
		if (EFI_ERROR(status))
			return status;
	}
	bytes = entry.geometry.working_size;
	status = entry.fvb->write(entry.fvb, entry.adapter.working_lba, 0, &bytes,
				  entry.workspace);
	return !EFI_ERROR(status) && bytes != entry.geometry.working_size ?
	       EFI_DEVICE_ERROR : status;
}

static const struct cdk2_ftw_fvb_ops fvb_ops = { block_size, block_read, block_write,
	       block_erase, NULL, is_boot, journal_read, journal_write
};

static EFI_STATUS CDK2_MS_ABI protocol_max(void *self, UINTN *size)
{
	(void)self;
	if (size == NULL)
		return EFI_INVALID_PARAMETER;
	*size = entry.adapter.core.block_size;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI protocol_allocate(void *self, EFI_GUID *caller,
	UINTN private_size, UINTN writes)
{
	(void)self;
	return cdk2_ftw_allocate(&entry.adapter.core, caller, private_size, writes);
}
static EFI_STATUS CDK2_MS_ABI protocol_write(void *self, UINT64 lba, UINTN offset,
	UINTN length, void *private_data, void *handle, void *buffer)
{
	handle_protocol_fn *handle_protocol = (void *)boot_slot(152U);
	struct cdk2_fvb_protocol_view *target;
	UINT64 base;
	UINTN block, count;
	EFI_STATUS status;
	(void)self;
	if (handle_protocol == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	status = handle_protocol(handle, &fvb_guid, (void **)&target);
	if (EFI_ERROR(status))
		return status;
	status = target->get_physical_address(target, &base);
	if (!EFI_ERROR(status))
		status = target->get_block_size(target, lba, &block, &count);
	if (EFI_ERROR(status))
		return status;
	if (!block || lba > (MAX_UINT64 - base) / block)
		return EFI_BAD_BUFFER_SIZE;
	cdk2_ftw_set_relative_offset(&entry.adapter.core,
				     (INT64)(base + lba * block) - (INT64)entry.geometry.spare_base);
	status = cdk2_ftw_fvb_select_target(&entry.adapter, target, lba);
	if (EFI_ERROR(status))
		return status;
	return cdk2_ftw_fvb_write(&entry.adapter, lba, offset, length, private_data, buffer);
}
static EFI_STATUS CDK2_MS_ABI protocol_restart(void *self, void *handle)
{
	(void)self;
	(void)handle;
	return cdk2_ftw_restart(&entry.adapter.core);
}
static EFI_STATUS CDK2_MS_ABI protocol_abort(void *self)
{
	(void)self;
	return cdk2_ftw_abort(&entry.adapter.core);
}
static EFI_STATUS CDK2_MS_ABI protocol_last(void *self, EFI_GUID *caller, UINT64 *lba,
	UINTN *offset, UINTN *length, UINTN *private_size, void *private_data, BOOLEAN *complete)
{
	(void)self;
	return cdk2_ftw_get_last_write(&entry.adapter.core, caller, lba, offset,
				       length, private_size, private_data, complete);
}

static void release_buffers(void)
{
	free_pool_fn *free_pool = (void *)boot_slot(72U);
	if (free_pool != NULL && entry.workspace != NULL)
		(void)free_pool(entry.workspace);
	if (free_pool != NULL && entry.scratch != NULL)
		(void)free_pool(entry.scratch);
	entry.workspace = NULL;
	entry.scratch = NULL;
}

static EFI_STATUS discover_and_install(void)
{
	locate_handles_fn *locate_handles = (void *)boot_slot(312U);
	handle_protocol_fn *handle_protocol = (void *)boot_slot(152U);
	locate_protocol_fn *locate_protocol = (void *)entry.boot->locate_protocol;
	install_protocol_fn *install_protocol = (void *)boot_slot(128U);
	allocate_pool_fn *allocate_pool = (void *)boot_slot(64U);
	free_pool_fn *free_pool = (void *)boot_slot(72U);
	void **handles = NULL, *runtime_arch;
	UINTN count = 0, index;
	EFI_STATUS status = EFI_NOT_FOUND;
	if (entry.installed)
		return EFI_ALREADY_STARTED;
	if (!locate_handles || !handle_protocol || !locate_protocol || !install_protocol ||
	    !allocate_pool || !free_pool)
		return EFI_UNSUPPORTED;
	status = locate_protocol(&runtime_arch_guid, NULL, &runtime_arch);
	if (EFI_ERROR(status))
		return status == EFI_NOT_FOUND ? EFI_NOT_READY : status;
	status = locate_handles(BY_PROTOCOL, &fvb_guid, NULL, &count, &handles);
	if (EFI_ERROR(status))
		return status;
	for (index = 0; index < count; index++) {
		struct cdk2_fvb_protocol_view *candidate;
		UINT64 base;
		status = handle_protocol(handles[index], &fvb_guid, (void **)&candidate);
		if (EFI_ERROR(status) || EFI_ERROR(candidate->get_physical_address(candidate, &base)))
			continue;
		if (base <= entry.geometry.working_base &&
		    entry.geometry.storage_size <= MAX_UINT64 - base &&
		    entry.geometry.spare_size <= MAX_UINT64 - entry.geometry.spare_base &&
		    entry.geometry.spare_base + entry.geometry.spare_size <=
		    base + entry.geometry.storage_size) {
			entry.fvb = candidate;
			entry.fvb_base = base;
			break;
		}
	}
	if (handles != NULL)
		(void)free_pool(handles);
	if (entry.fvb == NULL)
		return EFI_NOT_FOUND;
	status = allocate_pool(POOL_BOOT_SERVICES_DATA, entry.geometry.spare_size,
			       (void **)&entry.scratch);
	if (!EFI_ERROR(status))
		status = allocate_pool(POOL_BOOT_SERVICES_DATA,
			entry.geometry.working_size, (void **)&entry.workspace);
	if (EFI_ERROR(status)) {
		release_buffers();
		return status;
	}
	entry.adapter = (struct cdk2_ftw_fvb) {
		.ops = &fvb_ops, .context = &entry,
		.working_volume = entry.fvb, .spare_volume = entry.fvb,
		.target_volume = entry.fvb,
		.working_lba = (entry.geometry.working_base - entry.fvb_base) /
			       entry.geometry.block_size,
			       .spare_lba = (entry.geometry.spare_base - entry.fvb_base) /
					    entry.geometry.block_size,
					    .block_count = entry.geometry.spare_size / entry.geometry.block_size
	};
	status = cdk2_ftw_fvb_initialize(&entry.adapter, entry.scratch);
	if (EFI_ERROR(status)) {
		release_buffers();
		return status;
	}
	entry.protocol = (struct cdk2_ftw_protocol_view) {
		protocol_max, protocol_allocate,
			      protocol_write, protocol_restart, protocol_abort, protocol_last
	};
	entry.protocol_handle = NULL;
	status = install_protocol(&entry.protocol_handle, &ftw_guid, 0U, &entry.protocol);
	if (EFI_ERROR(status)) {
		release_buffers();
		return status;
	}
	entry.installed = TRUE;
	return EFI_SUCCESS;
}

static void CDK2_MS_ABI fvb_available(void *event, void *context)
{
	close_event_fn *close_event = (void *)boot_slot(112U);
	(void)event;
	(void)context;
	if (!EFI_ERROR(discover_and_install()) && close_event != NULL) {
		(void)close_event(entry.notify_event);
		entry.notify_event = NULL;
	}
}

EFI_STATUS CDK2_MS_ABI cdk2_ftw_entry(void *image, struct cdk2_ftw_system_table_view *system)
{
	const SMMSTORE_INFO *info;
	create_event_fn *create_event;
	register_notify_fn *register_notify;
	EFI_STATUS status;
	if (system == NULL || system->boot == NULL ||
	    (system->table_count != 0U && system->tables == NULL))
		return EFI_INVALID_PARAMETER;
	entry.boot = system->boot;
	entry.image = image;
	info = find_smmstore(system);
	status = cdk2_ftw_geometry_from_smmstore(info, &entry.geometry);
	if (EFI_ERROR(status))
		return status;
	status = discover_and_install();
	if (status != EFI_NOT_FOUND)
		return status;
	create_event = (void *)boot_slot(80U);
	register_notify = (void *)boot_slot(168U);
	if (create_event == NULL || register_notify == NULL)
		return EFI_UNSUPPORTED;
	status = create_event(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, fvb_available, NULL,
			      &entry.notify_event);
	if (EFI_ERROR(status))
		return status;
	status = register_notify(&fvb_guid, entry.notify_event, &entry.notify_registration);
	if (EFI_ERROR(status)) {
		close_event_fn *close_event = (void *)boot_slot(112U);
		if (close_event != NULL)
			(void)close_event(entry.notify_event);
		entry.notify_event = NULL;
	}
	return status;
}

void cdk2_ftw_entry_reset_for_test(void)
{
	entry = (struct ftw_entry_context) {
		0
	};
}
