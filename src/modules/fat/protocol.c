/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/fat_binding.h>

#define FAT_FILE_REVISION2 0x00020000ULL
#define FAT_SIMPLE_FS_REVISION 0x00010000ULL
#define FAT_FILE_MODE_CREATE 0x8000000000000000ULL
#define FAT_WARN_DELETE_FAILURE 2U
#define FAT_ACCESS_DENIED EFIERR(15)
#define FAT_VOLUME_CORRUPTED EFIERR(10)

const EFI_GUID cdk2_fat_file_info_guid = {
	0x09576e92U, 0x6d3fU, 0x11d2U, {0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU}};
const EFI_GUID cdk2_fat_fs_info_guid = {
	0x09576e93U, 0x6d3fU, 0x11d2U, {0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU}};
const EFI_GUID cdk2_fat_volume_label_info_guid = {
	0xdb47d7d3U, 0xfe81U, 0x11d3U, {0x9aU, 0x35U, 0x00U, 0x90U, 0x27U, 0x3fU, 0xc1U, 0x4dU}};

struct efi_time {
	UINT16 year;
	UINT8 month, day, hour, minute, second, pad1;
	UINT32 nanosecond;
	INT16 timezone;
	UINT8 daylight, pad2;
};
struct efi_file_info {
	UINT64 size, file_size, physical_size;
	struct efi_time create, access, modify;
	UINT64 attribute;
	CHAR16 file_name[1];
};
struct efi_fs_info {
	UINT64 size;
	BOOLEAN read_only;
	UINT8 pad[7];
	UINT64 volume_size, free_space;
	UINT32 block_size;
	CHAR16 label[1];
};
struct efi_label_info {
	CHAR16 label[1];
};
struct async_task;
struct fat_handle {
	struct cdk2_fat_file_protocol protocol;
	struct cdk2_fat_protocol_volume *owner;
	struct cdk2_fat_file file;
	UINT64 mode;
	UINTN pending;
	struct async_task *tasks;
};
static void drain_tasks(struct fat_handle *h);

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	return __builtin_memcmp(a, b, sizeof(*a)) == 0;
}
static struct fat_handle *handle_of(struct cdk2_fat_file_protocol *p)
{
	return (struct fat_handle *)((UINT8 *)p - offsetof(struct fat_handle, protocol));
}
static UINTN string_size(const CHAR16 *s)
{
	UINTN n = 0;
	while (s[n] != 0U)
		n++;
	return (n + 1U) * sizeof(*s);
}
static BOOLEAN bounded_string(const CHAR16 *text, UINTN bytes)
{
	UINTN index;
	if (text == NULL || bytes < sizeof(*text))
		return FALSE;
	for (index = 0U; index < bytes / sizeof(*text); index++)
		if (text[index] == 0U)
			return TRUE;
	return FALSE;
}
BOOLEAN cdk2_fat_time_is_valid(const void *raw)
{
	const struct efi_time *time = raw;
	static const struct efi_time zero_time;
	static const UINT8 days[] = {31U, 28U, 31U, 30U, 31U, 30U,
				     31U, 31U, 30U, 31U, 30U, 31U};
	UINTN limit;
	if (__builtin_memcmp(time, &zero_time, sizeof(*time)) == 0)
		return TRUE;
	if (time->year < 1980U || time->year > 2107U || time->month < 1U || time->month > 12U ||
	    time->hour > 23U || time->minute > 59U || time->second > 59U ||
	    time->nanosecond > 999999999U ||
	    (time->timezone != 0x07ff && (time->timezone < -1440 || time->timezone > 1440)) ||
	    (time->daylight & ~3U) != 0U)
		return FALSE;
	limit = days[time->month - 1U];
	if (time->month == 2U && (time->year % 4U == 0U) &&
	    (time->year % 100U != 0U || time->year % 400U == 0U))
		limit++;
	return time->day >= 1U && time->day <= limit;
}
static void fat_time(UINT16 date, UINT16 time, struct efi_time *out)
{
	*out = (struct efi_time){.year = (UINT16)(1980U + (date >> 9)),
				 .month = (UINT8)((date >> 5) & 15U),
				 .day = (UINT8)(date & 31U),
				 .hour = (UINT8)(time >> 11),
				 .minute = (UINT8)((time >> 5) & 63U),
				 .second = (UINT8)((time & 31U) * 2U),
				 .timezone = 0x07ff};
}

static EFI_STATUS CDK2_MS_ABI file_close(struct cdk2_fat_file_protocol *protocol)
{
	struct fat_handle *h;
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	h = handle_of(protocol);
	drain_tasks(h);
	if (h->pending != 0U)
		return FAT_ACCESS_DENIED;
	cdk2_fat_binding_close_handle(h->owner->mount);
	h->owner->binding->ops->release(h->owner->binding->context, h);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_open(struct cdk2_fat_file_protocol *protocol,
					struct cdk2_fat_file_protocol **result, CHAR16 *name,
					UINT64 mode, UINT64 attr)
{
	struct fat_handle *parent, *child = NULL;
	EFI_STATUS status;
	if (protocol == NULL || result == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	*result = NULL;
	if (mode != 1U && mode != 3U && mode != (3U | FAT_FILE_MODE_CREATE))
		return EFI_INVALID_PARAMETER;
	if ((mode & FAT_FILE_MODE_CREATE) != 0U && (attr & (1U | ~0x37ULL)) != 0U)
		return EFI_INVALID_PARAMETER;
	parent = handle_of(protocol);
	drain_tasks(parent);
	status = cdk2_fat_binding_open_handle(parent->owner->mount);
	if (EFI_ERROR(status))
		return status;
	status = parent->owner->binding->ops->allocate(parent->owner->binding->context,
						       sizeof(*child), (void **)&child);
	if (!EFI_ERROR(status)) {
		__builtin_memset(child, 0, sizeof(*child));
		status = cdk2_fat_open(&parent->file, name, &child->file);
	}
	if (!EFI_ERROR(status) && (mode & 2U) != 0U &&
	    (parent->file.volume->read_only || parent->file.volume->write_protected))
		status = CDK2_FAT_WRITE_PROTECTED;
	if (!EFI_ERROR(status) && (mode & 2U) != 0U && !child->file.is_directory &&
	    (child->file.entry.attributes & 1U) != 0U)
		status = FAT_ACCESS_DENIED;
	if (status == EFI_NOT_FOUND && (mode & FAT_FILE_MODE_CREATE) != 0U) {
		struct cdk2_fat_change *changes = NULL;
		size_t count = parent->file.volume->cluster_count;
		status = parent->owner->binding->ops->allocate(parent->owner->binding->context,
							       count * sizeof(*changes),
							       (void **)&changes);
		if (!EFI_ERROR(status))
			status = cdk2_fat_create(&parent->file, name, (UINT8)attr, &child->file,
						 changes, &count);
		if (changes != NULL)
			parent->owner->binding->ops->release(parent->owner->binding->context,
							     changes);
	}
	if (EFI_ERROR(status)) {
		if (child != NULL)
			parent->owner->binding->ops->release(parent->owner->binding->context,
							     child);
		cdk2_fat_binding_close_handle(parent->owner->mount);
		return status;
	}
	child->owner = parent->owner;
	child->protocol = parent->protocol;
	child->mode = mode;
	*result = &child->protocol;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_read(struct cdk2_fat_file_protocol *p, UINTN *size,
					void *buf)
{
	struct fat_handle *h;
	struct cdk2_fat_file_info native;
	struct efi_file_info *wire;
	size_t native_size;
	UINTN needed, name_bytes;
	EFI_STATUS status;
	if (p == NULL || size == NULL)
		return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	drain_tasks(h);
	if (h->file.is_directory) {
		native_size = sizeof(native);
		status = cdk2_fat_file_read(&h->file, &native_size, &native);
		if (EFI_ERROR(status) || native_size == 0U) {
			*size = native_size;
			return status;
		}
		name_bytes = string_size(native.name);
		needed = offsetof(struct efi_file_info, file_name) + name_bytes;
		if (buf == NULL || *size < needed) {
			*size = needed;
			return EFI_BUFFER_TOO_SMALL;
		}
		wire = buf;
		__builtin_memset(wire, 0, needed);
		wire->size = needed;
		wire->file_size = native.size;
		wire->physical_size = native.physical_size;
		wire->attribute = native.attributes;
		__builtin_memcpy(wire->file_name, native.name, name_bytes);
		*size = needed;
		return EFI_SUCCESS;
	}
	native_size = (size_t)*size;
	status = cdk2_fat_file_read(&h->file, &native_size, buf);
	*size = native_size;
	return status;
}
static EFI_STATUS CDK2_MS_ABI file_write(struct cdk2_fat_file_protocol *p, UINTN *size,
					 void *buf)
{
	struct fat_handle *h;
	UINT64 end, status, old_position;
	uint32_t old_size, old_first;
	struct cdk2_fat_change *changes = NULL;
	size_t count, native_size;
	if (p == NULL || size == NULL || (*size != 0U && buf == NULL))
		return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	if ((h->mode & 2U) == 0U)
		return FAT_ACCESS_DENIED;
	drain_tasks(h);
	if (h->file.is_directory || h->file.position > UINT32_MAX ||
	    *size > UINT32_MAX - h->file.position)
		return EFI_UNSUPPORTED;
	old_size = h->file.entry.size;
	old_first = h->file.entry.first_cluster;
	old_position = h->file.position;
	end = h->file.position + *size;
	if (end > h->file.entry.size) {
		count = h->file.volume->cluster_count;
		status = h->owner->binding->ops->allocate(
		    h->owner->binding->context, count * sizeof(*changes), (void **)&changes);
		if (EFI_ERROR(status))
			return status;
		status = cdk2_fat_file_resize(&h->file, (UINT32)end, changes, &count);
		if (EFI_ERROR(status)) {
			h->owner->binding->ops->release(h->owner->binding->context, changes);
			return status;
		}
	}
	native_size = (size_t)*size;
	status = cdk2_fat_write_file((struct cdk2_fat_volume *)h->file.volume,
				     h->file.entry.first_cluster, h->file.entry.size,
				     h->file.position, &native_size, buf);
	*size = native_size;
	if (!EFI_ERROR(status))
		h->file.position += native_size;
	else if (changes != NULL)
		cdk2_fat_file_rollback_resize(&h->file, old_first, old_size, old_position,
					      changes, count);
	if (changes != NULL)
		h->owner->binding->ops->release(h->owner->binding->context, changes);
	return status;
}
static EFI_STATUS CDK2_MS_ABI file_get_position(struct cdk2_fat_file_protocol *p, UINT64 *v)
{
	uint64_t position;
	EFI_STATUS status;
	if (p == NULL || v == NULL)
		return EFI_INVALID_PARAMETER;
	drain_tasks(handle_of(p));
	status = cdk2_fat_file_get_position(&handle_of(p)->file, &position);
	*v = position;
	return status;
}
static EFI_STATUS CDK2_MS_ABI file_set_position(struct cdk2_fat_file_protocol *p, UINT64 v)
{
	if (p == NULL)
		return EFI_INVALID_PARAMETER;
	drain_tasks(handle_of(p));
	return cdk2_fat_file_set_position(&handle_of(p)->file, v);
}
static EFI_STATUS CDK2_MS_ABI file_flush(struct cdk2_fat_file_protocol *p)
{
	struct fat_handle *h;
	if (p == NULL)
		return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	drain_tasks(h);
	return h->file.volume->flush == NULL ? EFI_SUCCESS
					     : h->file.volume->flush(h->file.volume->context);
}
static EFI_STATUS CDK2_MS_ABI file_delete(struct cdk2_fat_file_protocol *p)
{
	struct fat_handle *h;
	struct cdk2_fat_change *changes = NULL;
	size_t count;
	EFI_STATUS status;
	if (p == NULL)
		return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	count = h->file.volume->cluster_count;
	drain_tasks(h);
	if ((h->mode & 2U) == 0U || (h->file.entry.attributes & 1U) != 0U) {
		(void)file_close(p);
		return FAT_WARN_DELETE_FAILURE;
	}
	status = h->owner->binding->ops->allocate(h->owner->binding->context,
						  count * sizeof(*changes), (void **)&changes);
	if (!EFI_ERROR(status))
		status = cdk2_fat_file_delete(&h->file, changes, &count);
	if (changes != NULL)
		h->owner->binding->ops->release(h->owner->binding->context, changes);
	(void)file_close(p);
	return EFI_ERROR(status) ? FAT_WARN_DELETE_FAILURE : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_get_info(struct cdk2_fat_file_protocol *p, EFI_GUID *type,
					    UINTN *size, void *buffer)
{
	struct fat_handle *h;
	struct cdk2_fat_volume_info vi;
	UINTN needed, n;
	EFI_STATUS status;
	if (p == NULL || type == NULL || size == NULL)
		return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	drain_tasks(h);
	if (guid_equal(type, &cdk2_fat_file_info_guid)) {
		struct efi_file_info *i;
		n = string_size(h->file.entry.name);
		needed = offsetof(struct efi_file_info, file_name) + n;
		if (buffer == NULL || *size < needed) {
			*size = needed;
			return EFI_BUFFER_TOO_SMALL;
		}
		i = buffer;
		__builtin_memset(i, 0, needed);
		i->size = needed;
		i->file_size = h->file.entry.size;
		{
			UINT64 cluster_size = (UINT64)h->file.volume->bytes_per_sector *
					      h->file.volume->sectors_per_cluster;
			i->physical_size =
			    h->file.entry.size == 0U
				? 0U
				: ((h->file.entry.size + cluster_size - 1U) / cluster_size) *
				      cluster_size;
		}
		i->attribute = h->file.entry.attributes;
		fat_time(h->file.entry.creation_date, h->file.entry.creation_time, &i->create);
		fat_time(h->file.entry.write_date, h->file.entry.write_time, &i->modify);
		__builtin_memcpy(i->file_name, h->file.entry.name, n);
		*size = needed;
		return EFI_SUCCESS;
	}
	status = cdk2_fat_get_volume_info(h->file.volume, &vi);
	if (EFI_ERROR(status))
		return status;
	n = string_size(vi.label);
	if (guid_equal(type, &cdk2_fat_fs_info_guid)) {
		struct efi_fs_info *i;
		needed = offsetof(struct efi_fs_info, label) + n;
		if (buffer == NULL || *size < needed) {
			*size = needed;
			return EFI_BUFFER_TOO_SMALL;
		}
		i = buffer;
		__builtin_memset(i, 0, needed);
		i->size = needed;
		i->read_only = vi.read_only;
		i->volume_size = vi.volume_size;
		i->free_space = vi.free_space;
		i->block_size = vi.block_size;
		__builtin_memcpy(i->label, vi.label, n);
		*size = needed;
		return EFI_SUCCESS;
	}
	if (!guid_equal(type, &cdk2_fat_volume_label_info_guid))
		return EFI_UNSUPPORTED;
	needed = offsetof(struct efi_label_info, label) + n;
	if (buffer == NULL || *size < needed) {
		*size = needed;
		return EFI_BUFFER_TOO_SMALL;
	}
	__builtin_memcpy(((struct efi_label_info *)buffer)->label, vi.label, n);
	*size = needed;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_set_info(struct cdk2_fat_file_protocol *p, EFI_GUID *type,
					    UINTN size, void *buffer)
{
	struct fat_handle *h;
	struct efi_file_info *i;
	struct cdk2_fat_change *changes;
	size_t count;
	UINT16 create_date, create_time, write_date, write_time;
	EFI_STATUS status;
	if (p == NULL || type == NULL || buffer == NULL)
		return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	drain_tasks(h);
	if (guid_equal(type, &cdk2_fat_fs_info_guid)) {
		struct efi_fs_info *fs = buffer;
		if (size < offsetof(struct efi_fs_info, label) + sizeof(CHAR16) ||
		    fs->size < offsetof(struct efi_fs_info, label) + sizeof(CHAR16) ||
		    fs->size > size ||
		    !bounded_string(fs->label,
				    fs->size - offsetof(struct efi_fs_info, label)) ||
		    (h->mode & 2U) == 0U)
			return EFI_INVALID_PARAMETER;
		return cdk2_fat_set_volume_label((struct cdk2_fat_volume *)h->file.volume,
						 fs->label);
	}
	if (guid_equal(type, &cdk2_fat_volume_label_info_guid)) {
		if (size < sizeof(CHAR16) ||
		    !bounded_string(((struct efi_label_info *)buffer)->label, size) ||
		    (h->mode & 2U) == 0U)
			return EFI_INVALID_PARAMETER;
		return cdk2_fat_set_volume_label((struct cdk2_fat_volume *)h->file.volume,
						 ((struct efi_label_info *)buffer)->label);
	}
	if (!guid_equal(type, &cdk2_fat_file_info_guid))
		return EFI_UNSUPPORTED;
	if (size < offsetof(struct efi_file_info, file_name) + sizeof(CHAR16))
		return EFI_BAD_BUFFER_SIZE;
	i = buffer;
	if (i->size < offsetof(struct efi_file_info, file_name) + sizeof(CHAR16) ||
	    i->size > size ||
	    !bounded_string(i->file_name,
			    i->size - offsetof(struct efi_file_info, file_name)) ||
	    i->file_size > UINT32_MAX || (i->attribute & ~0x37ULL) != 0U ||
	    ((i->attribute ^ h->file.entry.attributes) & 0x10U) != 0U ||
	    !cdk2_fat_time_is_valid(&i->create) || !cdk2_fat_time_is_valid(&i->modify))
		return EFI_INVALID_PARAMETER;
	create_date = i->create.year == 0U
			      ? h->file.entry.creation_date
			      : (UINT16)(((i->create.year - 1980U) << 9) |
					 (i->create.month << 5) | i->create.day);
	create_time = i->create.year == 0U
			      ? h->file.entry.creation_time
			      : (UINT16)((i->create.hour << 11) | (i->create.minute << 5) |
					 (i->create.second / 2U));
	write_date = i->modify.year == 0U
			     ? h->file.entry.write_date
			     : (UINT16)(((i->modify.year - 1980U) << 9) |
					(i->modify.month << 5) | i->modify.day);
	write_time = i->modify.year == 0U
			     ? h->file.entry.write_time
			     : (UINT16)((i->modify.hour << 11) | (i->modify.minute << 5) |
					(i->modify.second / 2U));
	count = h->file.volume->cluster_count;
	if ((h->mode & 2U) == 0U)
		return FAT_ACCESS_DENIED;
	status = h->owner->binding->ops->allocate(h->owner->binding->context,
						  count * sizeof(*changes), (void **)&changes);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_fat_file_set_info(&h->file, i->file_name, (UINT32)i->file_size,
					(UINT8)i->attribute, create_date, create_time,
					write_date, write_time, changes, &count);
	h->owner->binding->ops->release(h->owner->binding->context, changes);
	return status;
}
static EFI_STATUS complete(struct fat_handle *h, struct cdk2_fat_file_io_token *t, EFI_STATUS s)
{
	if (t == NULL)
		return EFI_INVALID_PARAMETER;
	t->status = s;
	return cdk2_fat_complete_io(h->owner->binding, (struct cdk2_fat_io_token *)t, s);
}
enum async_kind { ASYNC_OPEN, ASYNC_READ, ASYNC_WRITE, ASYNC_FLUSH };
#define ASYNC_CACHE_SLOTS 4096U
#define ASYNC_CACHE_BYTES 512U
struct async_cache_entry {
	UINT64 offset;
	UINTN size;
	UINT8 data[ASYNC_CACHE_BYTES];
};
#define ASYNC_WRITE_SLOTS 1024U
struct async_write_entry {
	UINT64 offset;
	UINTN size;
	UINT8 data[ASYNC_CACHE_BYTES];
	UINT8 original[ASYNC_CACHE_BYTES];
};
enum async_phase {
	ASYNC_PREPARE,
	ASYNC_COMMIT,
	ASYNC_COMMIT_FLUSH,
	ASYNC_ROLLBACK,
	ASYNC_ROLLBACK_FLUSH
};
struct async_task {
	struct fat_handle *handle;
	struct cdk2_fat_file_io_token *token;
	enum async_kind kind;
	struct cdk2_fat_file_protocol **result;
	CHAR16 *name;
	UINT64 mode, attributes;
	struct async_task *next;
	void *cookie;
	struct cdk2_disk_io2_token disk_token;
	UINT8 *buffer;
	UINTN remaining, transferred;
	UINTN submitted;
	UINT64 cluster_position, file_position;
	UINT32 cluster, steps;
	BOOLEAN disk_write, started;
	struct cdk2_fat_volume async_volume;
	struct cdk2_fat_file async_parent, async_result;
	struct async_cache_entry cache[ASYNC_CACHE_SLOTS];
	UINTN cache_count;
	struct async_write_entry writes[ASYNC_WRITE_SLOTS];
	UINTN write_count, write_index;
	struct cdk2_fat_change *changes;
	size_t change_count;
	UINT64 wanted_offset;
	UINTN wanted_size;
	enum async_phase phase;
	EFI_STATUS first_error;
	UINT32 old_first, old_size;
	UINT64 old_position;
};
static void drain_tasks(struct fat_handle *h)
{
	while (h->tasks != NULL) {
		if (h->tasks->disk_token.event != NULL &&
		    h->owner->binding->ops->wait_event != NULL)
			(void)h->owner->binding->ops->wait_event(h->owner->binding->context,
								 h->tasks->disk_token.event);
		else if (h->owner->binding->ops->drain != NULL)
			h->owner->binding->ops->drain(h->owner->binding->context,
						      h->tasks->cookie);
		else
			break;
	}
}
static void unlink_task(struct async_task *task)
{
	struct async_task **link;
	for (link = &task->handle->tasks; *link != NULL; link = &(*link)->next)
		if (*link == task) {
			*link = task->next;
			break;
		}
	task->handle->pending--;
}
static void append_task(struct fat_handle *handle, struct async_task *task)
{
	struct async_task **link;
	for (link = &handle->tasks; *link != NULL; link = &(*link)->next)
		;
	*link = task;
	handle->pending++;
}
static EFI_STATUS start_disk_task(struct async_task *task);
static void CDK2_MS_ABI disk_flush_complete(void *event, void *opaque);
static void finish_disk_rw(struct async_task *task, EFI_STATUS status);
static void start_next_task(struct fat_handle *handle);
static uint64_t async_cached_read(void *opaque, uint64_t offset, size_t size, void *buffer)
{
	struct async_task *task = opaque;
	UINT8 *output = buffer;
	UINT64 cursor = offset;
	UINTN remaining = size;
	if (size > UINT64_MAX - offset)
		return EFI_INVALID_PARAMETER;
	while (remaining != 0U) {
		const UINT8 *source = NULL;
		UINTN available = 0U, item;
		/* Newest staged data takes precedence over the original cache. */
		for (item = task->write_count; item != 0U; item--)
			if (cursor >= task->writes[item - 1U].offset &&
			    cursor - task->writes[item - 1U].offset <
				task->writes[item - 1U].size) {
				available = task->writes[item - 1U].size -
					    (UINTN)(cursor - task->writes[item - 1U].offset);
				source = task->writes[item - 1U].data +
					 (UINTN)(cursor - task->writes[item - 1U].offset);
				break;
			}
		if (source == NULL)
			for (item = 0U; item < task->cache_count; item++)
				if (cursor >= task->cache[item].offset &&
				    cursor - task->cache[item].offset <
					task->cache[item].size) {
					available = task->cache[item].size -
						    (UINTN)(cursor - task->cache[item].offset);
					source = task->cache[item].data +
						 (UINTN)(cursor - task->cache[item].offset);
					break;
				}
		if (source == NULL) {
			if (task->cache_count == ASYNC_CACHE_SLOTS)
				return EFI_OUT_OF_RESOURCES;
			task->wanted_offset = cursor;
			task->wanted_size = 1U;
			return EFI_NOT_READY;
		}
		if (available > remaining)
			available = remaining;
		__builtin_memcpy(output, source, available);
		output += available;
		cursor += available;
		remaining -= available;
	}
	return EFI_SUCCESS;
}
static uint64_t async_cached_write(void *opaque, uint64_t offset, size_t size,
				   const void *buffer)
{
	struct async_task *task = opaque;
	const UINT8 *input = buffer;
	while (size != 0U) {
		UINTN item, sector = task->async_volume.bytes_per_sector;
		UINTN part = size > ASYNC_CACHE_BYTES ? ASYNC_CACHE_BYTES : size;
		if (sector == 0U || sector > ASYNC_CACHE_BYTES)
			sector = ASYNC_CACHE_BYTES;
		if (part > sector - (UINTN)(offset % sector))
			part = sector - (UINTN)(offset % sector);
		for (item = 0U; item < task->write_count; item++)
			if (offset >= task->writes[item].offset &&
			    offset - task->writes[item].offset <= task->writes[item].size &&
			    part <= task->writes[item].size -
					(UINTN)(offset - task->writes[item].offset))
				break;
		if (item == task->write_count) {
			UINTN cached;
			if (item == ASYNC_WRITE_SLOTS)
				return EFI_OUT_OF_RESOURCES;
			for (cached = 0U; cached < task->cache_count; cached++)
				if (offset >= task->cache[cached].offset &&
				    part <= task->cache[cached].size &&
				    offset - task->cache[cached].offset <=
					task->cache[cached].size &&
				    part <= task->cache[cached].size -
						(UINTN)(offset - task->cache[cached].offset))
					break;
			if (cached == task->cache_count) {
				task->wanted_offset = offset;
				task->wanted_size = part;
				return EFI_NOT_READY;
			}
			task->writes[item].offset = task->cache[cached].offset;
			task->writes[item].size = task->cache[cached].size;
			__builtin_memcpy(task->writes[item].original, task->cache[cached].data,
					 task->cache[cached].size);
			__builtin_memcpy(task->writes[item].data, task->cache[cached].data,
					 task->cache[cached].size);
			task->write_count++;
		}
		__builtin_memcpy(task->writes[item].data +
				     (UINTN)(offset - task->writes[item].offset),
				 input, part);
		offset += part;
		input += part;
		size -= part;
	}
	return EFI_SUCCESS;
}
static uint64_t async_cached_flush(void *opaque)
{
	(void)opaque;
	return EFI_SUCCESS;
}
static void finish_disk_open(struct async_task *task, EFI_STATUS status)
{
	struct cdk2_fat_binding *binding = task->handle->owner->binding;
	struct fat_handle *handle = task->handle, *child = NULL;
	struct cdk2_fat_file_io_token *token = task->token;
	if (!EFI_ERROR(status)) {
		status = cdk2_fat_binding_open_handle(handle->owner->mount);
		if (!EFI_ERROR(status))
			status = binding->ops->allocate(binding->context, sizeof(*child),
							(void **)&child);
		if (!EFI_ERROR(status)) {
			__builtin_memset(child, 0, sizeof(*child));
			child->owner = handle->owner;
			child->protocol = handle->protocol;
			child->mode = task->mode;
			child->file = task->async_result;
			child->file.volume = &handle->owner->mount->volume;
			*task->result = &child->protocol;
		} else {
			if (child != NULL)
				binding->ops->release(binding->context, child);
			cdk2_fat_binding_close_handle(handle->owner->mount);
		}
	}
	unlink_task(task);
	(void)binding->ops->close_event(binding->context, task->disk_token.event);
	if (task->changes != NULL)
		binding->ops->release(binding->context, task->changes);
	binding->ops->release(binding->context, task);
	start_next_task(handle);
	token->status = status;
	(void)cdk2_fat_complete_io(binding, (struct cdk2_fat_io_token *)token, status);
}
static EFI_STATUS submit_prepare_read(struct async_task *task);
static EFI_STATUS submit_transaction_write(struct async_task *task, BOOLEAN original)
{
	struct cdk2_disk_io2 *disk2 = task->handle->owner->mount->disk2;
	struct async_write_entry *entry = &task->writes[task->write_index];
	task->disk_token.transaction_status = EFI_NOT_READY;
	return disk2->write_disk_ex(disk2, task->handle->owner->mount->media_id, entry->offset,
				    &task->disk_token, entry->size,
				    original ? entry->original : entry->data);
}
static EFI_STATUS submit_transaction_flush(struct async_task *task)
{
	task->disk_token.transaction_status = EFI_NOT_READY;
	return task->handle->owner->mount->disk2->flush_disk_ex(
	    task->handle->owner->mount->disk2, &task->disk_token);
}
static EFI_STATUS resume_prepare(struct async_task *task)
{
	EFI_STATUS status;
	/* Each cache miss restarts preparation from the committed snapshot. */
	task->write_count = 0U;
	if (task->kind == ASYNC_OPEN) {
		task->async_parent = task->handle->file;
		task->async_parent.volume = &task->async_volume;
		status = cdk2_fat_open(&task->async_parent, task->name, &task->async_result);
		if (status == EFI_NOT_FOUND && (task->mode & FAT_FILE_MODE_CREATE) != 0U) {
			task->change_count = task->async_volume.cluster_count;
			status = cdk2_fat_create(&task->async_parent, task->name,
						 (UINT8)task->attributes, &task->async_result,
						 task->changes, &task->change_count);
		}
		if (!EFI_ERROR(status) && (task->mode & 2U) != 0U &&
		    (task->async_volume.read_only || task->async_volume.write_protected))
			status = CDK2_FAT_WRITE_PROTECTED;
		if (!EFI_ERROR(status) && (task->mode & 2U) != 0U &&
		    !task->async_result.is_directory &&
		    (task->async_result.entry.attributes & 1U) != 0U)
			status = FAT_ACCESS_DENIED;
	} else {
		size_t size = task->token->buffer_size;
		UINT64 end = task->old_position + size;
		task->async_result = task->handle->file;
		task->async_result.volume = &task->async_volume;
		task->change_count = task->async_volume.cluster_count;
		status = end > task->old_size
			     ? cdk2_fat_file_resize(&task->async_result, (UINT32)end,
						    task->changes, &task->change_count)
			     : EFI_SUCCESS;
		if (!EFI_ERROR(status)) {
			size = task->token->buffer_size;
			status = cdk2_fat_write_file(
			    &task->async_volume, task->async_result.entry.first_cluster,
			    task->async_result.entry.size, task->old_position, &size,
			    task->token->buffer);
		}
	}
	if (status == EFI_NOT_READY)
		return submit_prepare_read(task);
	if (EFI_ERROR(status))
		return status;
	if (task->kind == ASYNC_OPEN && task->write_count == 0U) {
		finish_disk_open(task, EFI_SUCCESS);
		return EFI_SUCCESS;
	}
	task->phase = ASYNC_COMMIT;
	task->write_index = 0U;
	if (task->write_count != 0U)
		return submit_transaction_write(task, FALSE);
	task->phase = ASYNC_COMMIT_FLUSH;
	return submit_transaction_flush(task);
}
static void CDK2_MS_ABI disk_open_complete(void *event, void *opaque)
{
	struct async_task *task = opaque;
	EFI_STATUS status = task->disk_token.transaction_status;
	(void)event;
	if (task->phase == ASYNC_PREPARE) {
		if (!EFI_ERROR(status)) {
			task->cache[task->cache_count].offset = task->wanted_offset;
			task->cache[task->cache_count].size = task->wanted_size;
			task->cache_count++;
			status = resume_prepare(task);
		}
		if (!EFI_ERROR(status))
			return;
		task->first_error = status;
		if (task->kind == ASYNC_WRITE)
			finish_disk_rw(task, status);
		else
			finish_disk_open(task, status);
		return;
	}
	if (task->phase == ASYNC_COMMIT) {
		if (EFI_ERROR(status)) {
			task->first_error = status;
			task->write_index++;
			task->phase = ASYNC_ROLLBACK;
		} else if (++task->write_index < task->write_count) {
			status = submit_transaction_write(task, FALSE);
			if (!EFI_ERROR(status))
				return;
			task->first_error = status;
			task->phase = ASYNC_ROLLBACK;
		} else {
			task->phase = ASYNC_COMMIT_FLUSH;
			status = submit_transaction_flush(task);
			if (!EFI_ERROR(status))
				return;
			task->first_error = status;
			task->phase = ASYNC_ROLLBACK;
		}
	}
	if (task->phase == ASYNC_COMMIT_FLUSH) {
		if (!EFI_ERROR(status)) {
			if (task->kind == ASYNC_WRITE) {
				task->handle->file.entry = task->async_result.entry;
				task->handle->file.position =
				    task->old_position + task->token->buffer_size;
				task->transferred = task->token->buffer_size;
				finish_disk_rw(task, EFI_SUCCESS);
			} else
				finish_disk_open(task, EFI_SUCCESS);
			return;
		}
		task->first_error = status;
		task->write_index = task->write_count;
		task->phase = ASYNC_ROLLBACK;
	}
	while (task->phase == ASYNC_ROLLBACK) {
		if (task->write_index == 0U) {
			task->phase = ASYNC_ROLLBACK_FLUSH;
			status = submit_transaction_flush(task);
			if (!EFI_ERROR(status))
				return;
			break;
		}
		task->write_index--;
		status = submit_transaction_write(task, TRUE);
		if (!EFI_ERROR(status))
			return;
	}
	if (task->kind == ASYNC_WRITE)
		finish_disk_rw(task, task->first_error);
	else
		finish_disk_open(task, task->first_error);
}
static EFI_STATUS submit_prepare_read(struct async_task *task)
{
	struct cdk2_disk_io2 *disk2 = task->handle->owner->mount->disk2;
	UINTN sector = task->async_volume.bytes_per_sector;
	UINT64 base;
	if (sector == 0U || sector > ASYNC_CACHE_BYTES)
		sector = ASYNC_CACHE_BYTES;
	base = task->wanted_offset - task->wanted_offset % sector;
	if (base < task->async_volume.media_size) {
		task->wanted_offset = base;
		task->wanted_size = task->async_volume.media_size - base < sector
					? (UINTN)(task->async_volume.media_size - base)
					: sector;
	}
	if (task->cache_count >= ASYNC_CACHE_SLOTS || task->wanted_size > ASYNC_CACHE_BYTES)
		return EFI_OUT_OF_RESOURCES;
	task->disk_token.transaction_status = EFI_NOT_READY;
	return disk2->read_disk_ex(disk2, task->handle->owner->mount->media_id,
				   task->wanted_offset, &task->disk_token, task->wanted_size,
				   task->cache[task->cache_count].data);
}
static void start_next_task(struct fat_handle *handle)
{
	struct async_task *next = handle->tasks;
	EFI_STATUS status;
	if (next == NULL || next->started)
		return;
	status = start_disk_task(next);
	if (EFI_ERROR(status)) {
		if (next->kind == ASYNC_OPEN)
			finish_disk_open(next, status);
		else if (next->kind == ASYNC_FLUSH) {
			next->disk_token.transaction_status = status;
			disk_flush_complete(next->disk_token.event, next);
		} else
			finish_disk_rw(next, status);
	} else if (next->kind == ASYNC_READ && next->remaining == 0U)
		finish_disk_rw(next, EFI_SUCCESS);
}
static void CDK2_MS_ABI disk_flush_complete(void *event, void *opaque)
{
	struct async_task *task = opaque;
	struct fat_handle *handle = task->handle;
	struct cdk2_fat_binding *binding = task->handle->owner->binding;
	struct cdk2_fat_file_io_token *token = task->token;
	EFI_STATUS status = task->disk_token.transaction_status;
	unlink_task(task);
	(void)binding->ops->close_event(binding->context, event);
	binding->ops->release(binding->context, task);
	start_next_task(handle);
	token->status = status;
	(void)cdk2_fat_complete_io(binding, (struct cdk2_fat_io_token *)token, status);
}
static EFI_STATUS queue_disk_flush(struct fat_handle *h, struct async_task *task)
{
	struct cdk2_fat_binding *binding = h->owner->binding;
	EFI_STATUS status;
	if (binding->ops->create_event == NULL || binding->ops->close_event == NULL ||
	    h->owner->mount->disk2->flush_disk_ex == NULL) {
		binding->ops->release(binding->context, task);
		return EFI_UNSUPPORTED;
	}
	status = binding->ops->create_event(binding->context, disk_flush_complete, task,
					    &task->disk_token.event);
	if (EFI_ERROR(status)) {
		binding->ops->release(binding->context, task);
		return status;
	}
	task->token->status = EFI_NOT_READY;
	append_task(h, task);
	status = h->tasks == task ? start_disk_task(task) : EFI_SUCCESS;
	if (EFI_ERROR(status)) {
		unlink_task(task);
		(void)binding->ops->close_event(binding->context, task->disk_token.event);
		binding->ops->release(binding->context, task);
	}
	return status;
}
static EFI_STATUS submit_disk_rw(struct async_task *task);
static EFI_STATUS prepare_open_task(struct async_task *task)
{
	struct fat_handle *h = task->handle;
	struct cdk2_fat_binding *binding = h->owner->binding;
	task->async_volume = h->owner->mount->volume;
	task->async_volume.read = async_cached_read;
	task->async_volume.write = async_cached_write;
	task->async_volume.flush = async_cached_flush;
	task->async_volume.context = task;
	task->phase = ASYNC_PREPARE;
	if ((task->mode & FAT_FILE_MODE_CREATE) == 0U)
		return EFI_SUCCESS;
	return binding->ops->allocate(binding->context,
				      task->async_volume.cluster_count * sizeof(*task->changes),
				      (void **)&task->changes);
}
static EFI_STATUS prepare_rw_task(struct async_task *task)
{
	struct fat_handle *h = task->handle;
	struct cdk2_fat_volume *volume = (struct cdk2_fat_volume *)h->file.volume;
	struct cdk2_fat_binding *binding = h->owner->binding;
	UINT64 cluster_size, position = h->file.position;
	UINT32 next;
	int end;
	EFI_STATUS status;
	task->file_position = position;
	if (task->disk_write) {
		if ((h->mode & 2U) == 0U)
			return FAT_ACCESS_DENIED;
		if (h->file.is_directory || position > UINT32_MAX ||
		    task->token->buffer_size > UINT32_MAX - position)
			return EFI_UNSUPPORTED;
		task->async_volume = h->owner->mount->volume;
		task->async_volume.read = async_cached_read;
		task->async_volume.write = async_cached_write;
		task->async_volume.flush = async_cached_flush;
		task->async_volume.context = task;
		task->old_first = h->file.entry.first_cluster;
		task->old_size = h->file.entry.size;
		task->old_position = position;
		task->phase = ASYNC_PREPARE;
		return binding->ops->allocate(
		    binding->context, task->async_volume.cluster_count * sizeof(*task->changes),
		    (void **)&task->changes);
	}
	if (h->file.is_directory || position > h->file.entry.size ||
	    task->token->buffer_size > h->file.entry.size - position)
		return EFI_UNSUPPORTED;
	task->remaining = task->token->buffer_size;
	task->buffer = task->token->buffer;
	if (task->remaining == 0U)
		return EFI_SUCCESS;
	cluster_size = (UINT64)volume->bytes_per_sector * volume->sectors_per_cluster;
	if (cluster_size == 0U || h->file.entry.first_cluster < 2U)
		return EFI_UNSUPPORTED;
	task->cluster = h->file.entry.first_cluster;
	task->steps = 0U;
	while (position >= cluster_size) {
		status = cdk2_fat_next_cluster(volume, task->cluster, &next, &end);
		if (EFI_ERROR(status) || end || ++task->steps >= volume->cluster_count)
			return EFI_ERROR(status) ? status : FAT_VOLUME_CORRUPTED;
		task->cluster = next;
		position -= cluster_size;
	}
	task->cluster_position = position;
	return EFI_SUCCESS;
}
static void finish_disk_rw(struct async_task *task, EFI_STATUS status)
{
	struct cdk2_fat_binding *binding = task->handle->owner->binding;
	struct fat_handle *handle = task->handle;
	struct cdk2_fat_file_io_token *token = task->token;
	token->buffer_size = task->transferred;
	if (!EFI_ERROR(status))
		task->handle->file.position = task->file_position + task->transferred;
	unlink_task(task);
	(void)binding->ops->close_event(binding->context, task->disk_token.event);
	if (task->changes != NULL)
		binding->ops->release(binding->context, task->changes);
	binding->ops->release(binding->context, task);
	start_next_task(handle);
	token->status = status;
	(void)cdk2_fat_complete_io(binding, (struct cdk2_fat_io_token *)token, status);
}
static void CDK2_MS_ABI disk_rw_complete(void *event, void *opaque)
{
	struct async_task *task = opaque;
	struct cdk2_fat_volume *volume = (struct cdk2_fat_volume *)task->handle->file.volume;
	UINT32 next;
	int end;
	EFI_STATUS status = task->disk_token.transaction_status;
	(void)event;
	if (EFI_ERROR(status)) {
		finish_disk_rw(task, status);
		return;
	}
	task->remaining -= task->submitted;
	task->transferred += task->submitted;
	task->buffer += task->submitted;
	if (task->remaining == 0U) {
		finish_disk_rw(task, EFI_SUCCESS);
		return;
	}
	status = cdk2_fat_next_cluster(volume, task->cluster, &next, &end);
	if (EFI_ERROR(status) || end || ++task->steps >= volume->cluster_count) {
		finish_disk_rw(task, EFI_ERROR(status) ? status : FAT_VOLUME_CORRUPTED);
		return;
	}
	task->cluster = next;
	task->cluster_position = 0U;
	status = submit_disk_rw(task);
	if (EFI_ERROR(status))
		finish_disk_rw(task, status);
}
static EFI_STATUS submit_disk_rw(struct async_task *task)
{
	struct cdk2_fat_volume *volume = (struct cdk2_fat_volume *)task->handle->file.volume;
	struct cdk2_disk_io2 *disk2 = task->handle->owner->mount->disk2;
	UINT64 cluster_size = (UINT64)volume->bytes_per_sector * volume->sectors_per_cluster;
	uint64_t offset;
	UINTN part;
	EFI_STATUS status = cdk2_fat_cluster_offset(volume, task->cluster, &offset);
	if (EFI_ERROR(status))
		return status;
	part = (UINTN)(cluster_size - task->cluster_position);
	if (part > task->remaining)
		part = task->remaining;
	task->disk_token.transaction_status = EFI_NOT_READY;
	status = task->disk_write
		     ? disk2->write_disk_ex(disk2, task->handle->owner->mount->media_id,
					    offset + task->cluster_position, &task->disk_token,
					    part, task->buffer)
		     : disk2->read_disk_ex(disk2, task->handle->owner->mount->media_id,
					   offset + task->cluster_position, &task->disk_token,
					   part, task->buffer);
	if (!EFI_ERROR(status))
		task->submitted = part;
	return status;
}
static EFI_STATUS start_disk_task(struct async_task *task)
{
	EFI_STATUS status;
	task->started = TRUE;
	if (task->kind == ASYNC_OPEN) {
		status = prepare_open_task(task);
		return EFI_ERROR(status) ? status : resume_prepare(task);
	}
	if (task->kind == ASYNC_WRITE) {
		status = prepare_rw_task(task);
		if (EFI_ERROR(status))
			return status;
		return resume_prepare(task);
	}
	if (task->kind == ASYNC_FLUSH)
		return task->handle->owner->mount->disk2->flush_disk_ex(
		    task->handle->owner->mount->disk2, &task->disk_token);
	status = prepare_rw_task(task);
	return EFI_ERROR(status) || task->remaining == 0U ? status : submit_disk_rw(task);
}
static EFI_STATUS queue_disk_open(struct fat_handle *h, struct async_task *task)
{
	struct cdk2_fat_binding *binding = h->owner->binding;
	EFI_STATUS status;
	if (binding->ops->create_event == NULL || binding->ops->close_event == NULL ||
	    h->owner->mount->disk2 == NULL || h->owner->mount->disk2->read_disk_ex == NULL ||
	    ((task->mode & FAT_FILE_MODE_CREATE) != 0U &&
	     (h->owner->mount->disk2->write_disk_ex == NULL ||
	      h->owner->mount->disk2->flush_disk_ex == NULL))) {
		binding->ops->release(binding->context, task);
		return EFI_UNSUPPORTED;
	}
	status = binding->ops->create_event(binding->context, disk_open_complete, task,
					    &task->disk_token.event);
	if (EFI_ERROR(status)) {
		binding->ops->release(binding->context, task);
		return status;
	}
	task->token->status = EFI_NOT_READY;
	append_task(h, task);
	status = h->tasks == task ? start_disk_task(task) : EFI_SUCCESS;
	if (EFI_ERROR(status))
		finish_disk_open(task, status);
	return status;
}
static EFI_STATUS queue_disk_rw(struct fat_handle *h, struct async_task *task, BOOLEAN write)
{
	struct cdk2_fat_binding *binding = h->owner->binding;
	EFI_STATUS status;
	if (binding->ops->create_event == NULL || binding->ops->close_event == NULL ||
	    h->owner->mount->disk2 == NULL ||
	    (write ? (h->owner->mount->disk2->write_disk_ex == NULL ||
		      h->owner->mount->disk2->read_disk_ex == NULL ||
		      h->owner->mount->disk2->flush_disk_ex == NULL)
		   : h->owner->mount->disk2->read_disk_ex == NULL))
		goto unsupported;
	if (task->token->buffer_size != 0U && task->token->buffer == NULL) {
		binding->ops->release(binding->context, task);
		return EFI_INVALID_PARAMETER;
	}
	if (write) {
		status = binding->ops->create_event(binding->context, disk_open_complete, task,
						    &task->disk_token.event);
		if (EFI_ERROR(status)) {
			binding->ops->release(binding->context, task);
			return status;
		}
		task->disk_write = TRUE;
		task->token->status = EFI_NOT_READY;
		append_task(h, task);
		status = h->tasks == task ? start_disk_task(task) : EFI_SUCCESS;
		if (EFI_ERROR(status))
			finish_disk_rw(task, status);
		return status;
	}
	status = binding->ops->create_event(binding->context, disk_rw_complete, task,
					    &task->disk_token.event);
	if (EFI_ERROR(status)) {
		binding->ops->release(binding->context, task);
		return status;
	}
	task->token->status = EFI_NOT_READY;
	append_task(h, task);
	status = h->tasks == task ? start_disk_task(task) : EFI_SUCCESS;
	if (EFI_ERROR(status))
		finish_disk_rw(task, status);
	return status;
unsupported:
	binding->ops->release(binding->context, task);
	return EFI_UNSUPPORTED;
}
static EFI_STATUS CDK2_MS_ABI file_open_ex(struct cdk2_fat_file_protocol *p,
					   struct cdk2_fat_file_protocol **r, CHAR16 *n,
					   UINT64 m, UINT64 a, struct cdk2_fat_file_io_token *t)
{
	struct fat_handle *h;
	struct async_task *task;
	EFI_STATUS status;
	if (p == NULL || t == NULL)
		return EFI_INVALID_PARAMETER;
	if (p->revision < FAT_FILE_REVISION2)
		return EFI_UNSUPPORTED;
	if (t->event == NULL)
		return complete(handle_of(p), t, file_open(p, r, n, m, a));
	h = handle_of(p);
	status = h->owner->binding->ops->allocate(h->owner->binding->context, sizeof(*task),
						  (void **)&task);
	if (EFI_ERROR(status))
		return status;
	*task = (struct async_task){.handle = h,
				    .token = t,
				    .kind = ASYNC_OPEN,
				    .result = r,
				    .name = n,
				    .mode = m,
				    .attributes = a};
	if (r == NULL || n == NULL ||
	    (m != 1U && m != 3U && m != (3U | FAT_FILE_MODE_CREATE))) {
		h->owner->binding->ops->release(h->owner->binding->context, task);
		return EFI_INVALID_PARAMETER;
	}
	*r = NULL;
	return queue_disk_open(h, task);
}
static EFI_STATUS CDK2_MS_ABI file_read_ex(struct cdk2_fat_file_protocol *p,
					   struct cdk2_fat_file_io_token *t)
{
	struct fat_handle *h;
	struct async_task *task;
	EFI_STATUS s;
	if (p == NULL || t == NULL)
		return EFI_INVALID_PARAMETER;
	if (p->revision < FAT_FILE_REVISION2)
		return EFI_UNSUPPORTED;
	if (t->event == NULL) {
		s = file_read(p, &t->buffer_size, t->buffer);
		return complete(handle_of(p), t, s);
	}
	h = handle_of(p);
	s = h->owner->binding->ops->allocate(h->owner->binding->context, sizeof(*task),
					     (void **)&task);
	if (EFI_ERROR(s))
		return s;
	*task = (struct async_task){.handle = h, .token = t, .kind = ASYNC_READ};
	return queue_disk_rw(h, task, FALSE);
}
static EFI_STATUS CDK2_MS_ABI file_write_ex(struct cdk2_fat_file_protocol *p,
					    struct cdk2_fat_file_io_token *t)
{
	struct fat_handle *h;
	struct async_task *task;
	EFI_STATUS s;
	if (p == NULL || t == NULL)
		return EFI_INVALID_PARAMETER;
	if (p->revision < FAT_FILE_REVISION2)
		return EFI_UNSUPPORTED;
	if (t->event == NULL) {
		s = file_write(p, &t->buffer_size, t->buffer);
		return complete(handle_of(p), t, s);
	}
	h = handle_of(p);
	s = h->owner->binding->ops->allocate(h->owner->binding->context, sizeof(*task),
					     (void **)&task);
	if (EFI_ERROR(s))
		return s;
	*task = (struct async_task){.handle = h, .token = t, .kind = ASYNC_WRITE};
	return queue_disk_rw(h, task, TRUE);
}
static EFI_STATUS CDK2_MS_ABI file_flush_ex(struct cdk2_fat_file_protocol *p,
					    struct cdk2_fat_file_io_token *t)
{
	struct fat_handle *h;
	struct async_task *task;
	EFI_STATUS s;
	if (p == NULL || t == NULL)
		return EFI_INVALID_PARAMETER;
	if (p->revision < FAT_FILE_REVISION2)
		return EFI_UNSUPPORTED;
	if (t->event == NULL)
		return complete(handle_of(p), t, file_flush(p));
	h = handle_of(p);
	s = h->owner->binding->ops->allocate(h->owner->binding->context, sizeof(*task),
					     (void **)&task);
	if (EFI_ERROR(s))
		return s;
	*task = (struct async_task){.handle = h, .token = t, .kind = ASYNC_FLUSH};
	return queue_disk_flush(h, task);
}
static const struct cdk2_fat_file_protocol file_template = {
	FAT_FILE_REVISION2, file_open, file_close, file_delete, file_read,
	file_write, file_get_position, file_set_position, file_get_info, file_set_info,
	file_flush, file_open_ex, file_read_ex, file_write_ex, file_flush_ex};
static EFI_STATUS CDK2_MS_ABI open_volume(struct cdk2_fat_simple_fs_protocol *p,
					  struct cdk2_fat_file_protocol **result)
{
	struct cdk2_fat_protocol_volume *v;
	struct fat_handle *h = NULL;
	EFI_STATUS status;
	if (p == NULL || result == NULL)
		return EFI_INVALID_PARAMETER;
	*result = NULL;
	v = (struct cdk2_fat_protocol_volume *)((UINT8 *)p -
						offsetof(struct cdk2_fat_protocol_volume,
							 protocol));
	status = cdk2_fat_binding_open_handle(v->mount);
	if (EFI_ERROR(status))
		return status;
	status = v->binding->ops->allocate(v->binding->context, sizeof(*h), (void **)&h);
	if (!EFI_ERROR(status)) {
		__builtin_memset(h, 0, sizeof(*h));
		status = cdk2_fat_open_root(&v->mount->volume, &h->file);
	}
	if (EFI_ERROR(status)) {
		if (h != NULL)
			v->binding->ops->release(v->binding->context, h);
		cdk2_fat_binding_close_handle(v->mount);
		return status;
	}
	h->owner = v;
	h->protocol = file_template;
	h->mode = 3U;
	if (v->mount->disk2 == NULL)
		h->protocol.revision = 0x00010000ULL;
	*result = &h->protocol;
	return EFI_SUCCESS;
}
void cdk2_fat_protocol_init(struct cdk2_fat_protocol_volume *v,
			    struct cdk2_fat_binding *binding, struct cdk2_fat_mount *mount)
{
	*v = (struct cdk2_fat_protocol_volume){
	    {FAT_SIMPLE_FS_REVISION, open_volume}, binding, mount};
}
