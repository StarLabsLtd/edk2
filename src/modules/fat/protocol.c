/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/fat_binding.h>

#define FAT_FILE_REVISION2 0x00020000ULL
#define FAT_SIMPLE_FS_REVISION 0x00010000ULL
#define FAT_FILE_MODE_CREATE 0x8000000000000000ULL
#define FAT_WARN_DELETE_FAILURE 2U
#define FAT_ACCESS_DENIED EFIERR(15)

const EFI_GUID cdk2_fat_file_info_guid = { 0x09576e92U, 0x6d3fU, 0x11d2U,
	{ 0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };
const EFI_GUID cdk2_fat_fs_info_guid = { 0x09576e93U, 0x6d3fU, 0x11d2U,
	{ 0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };
const EFI_GUID cdk2_fat_volume_label_info_guid = { 0xdb47d7d3U, 0xfe81U, 0x11d3U,
	{ 0x9aU, 0x35U, 0x00U, 0x90U, 0x27U, 0x3fU, 0xc1U, 0x4dU } };

struct efi_time { UINT16 year; UINT8 month, day, hour, minute, second, pad1;
	UINT32 nanosecond; INT16 timezone; UINT8 daylight, pad2; };
struct efi_file_info { UINT64 size, file_size, physical_size; struct efi_time create,
	access, modify; UINT64 attribute; CHAR16 file_name[1]; };
struct efi_fs_info { UINT64 size; BOOLEAN read_only; UINT8 pad[7]; UINT64 volume_size,
	free_space; UINT32 block_size; CHAR16 label[1]; };
struct efi_label_info { CHAR16 label[1]; };
struct async_task;
struct fat_handle { struct cdk2_fat_file_protocol protocol;
	struct cdk2_fat_protocol_volume *owner; struct cdk2_fat_file file; UINT64 mode;
	UINTN pending; struct async_task *tasks; };
static void drain_tasks(struct fat_handle *h);

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{ return __builtin_memcmp(a, b, sizeof(*a)) == 0; }
static struct fat_handle *handle_of(struct cdk2_fat_file_protocol *p)
{ return (struct fat_handle *)((UINT8 *)p - offsetof(struct fat_handle, protocol)); }
static UINTN string_size(const CHAR16 *s)
{ UINTN n = 0; while (s[n] != 0U) n++; return (n + 1U) * sizeof(*s); }
static void fat_time(UINT16 date, UINT16 time, struct efi_time *out)
{
	*out = (struct efi_time) { .year = (UINT16)(1980U + (date >> 9)),
		.month = (UINT8)((date >> 5) & 15U), .day = (UINT8)(date & 31U),
		.hour = (UINT8)(time >> 11), .minute = (UINT8)((time >> 5) & 63U),
		.second = (UINT8)((time & 31U) * 2U), .timezone = 0x07ff };
}

static EFI_STATUS CDK2_MS_ABI file_close(struct cdk2_fat_file_protocol *protocol)
{
	struct fat_handle *h;
	if (protocol == NULL) return EFI_INVALID_PARAMETER;
	h = handle_of(protocol);
	drain_tasks(h);
	if (h->pending != 0U) return FAT_ACCESS_DENIED;
	cdk2_fat_binding_close_handle(h->owner->mount);
	h->owner->binding->ops->release(h->owner->binding->context, h);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_open(struct cdk2_fat_file_protocol *protocol,
	struct cdk2_fat_file_protocol **result, CHAR16 *name, UINT64 mode, UINT64 attr)
{
	struct fat_handle *parent, *child = NULL; EFI_STATUS status;
	if (protocol == NULL || result == NULL || name == NULL) return EFI_INVALID_PARAMETER;
	*result = NULL;
	if (mode != 1U && mode != 3U && mode != (3U | FAT_FILE_MODE_CREATE))
		return EFI_INVALID_PARAMETER;
	if ((mode & FAT_FILE_MODE_CREATE) != 0U && (attr & (1U | ~0x37ULL)) != 0U)
		return EFI_INVALID_PARAMETER;
	parent = handle_of(protocol);
	drain_tasks(parent);
	status = cdk2_fat_binding_open_handle(parent->owner->mount); if (EFI_ERROR(status)) return status;
	status = parent->owner->binding->ops->allocate(parent->owner->binding->context,
		sizeof(*child), (void **)&child);
	if (!EFI_ERROR(status)) status = cdk2_fat_open(&parent->file, name, &child->file);
	if (!EFI_ERROR(status) && (mode & 2U) != 0U &&
	    (parent->file.volume->read_only || parent->file.volume->write_protected))
		status = CDK2_FAT_WRITE_PROTECTED;
	if (!EFI_ERROR(status) && (mode & 2U) != 0U && !child->file.is_directory &&
	    (child->file.entry.attributes & 1U) != 0U)
		status = FAT_ACCESS_DENIED;
	if (status == EFI_NOT_FOUND && (mode & FAT_FILE_MODE_CREATE) != 0U) {
		struct cdk2_fat_change *changes = NULL; size_t count = parent->file.volume->cluster_count;
		status = parent->owner->binding->ops->allocate(parent->owner->binding->context,
			count * sizeof(*changes), (void **)&changes);
		if (!EFI_ERROR(status)) status = cdk2_fat_create(&parent->file, name, (UINT8)attr,
			&child->file, changes, &count);
		if (changes != NULL) parent->owner->binding->ops->release(
			parent->owner->binding->context, changes);
	}
	if (EFI_ERROR(status)) { if (child != NULL) parent->owner->binding->ops->release(
		parent->owner->binding->context, child); cdk2_fat_binding_close_handle(parent->owner->mount); return status; }
	child->owner = parent->owner; child->protocol = parent->protocol; child->mode = mode;
	*result = &child->protocol;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_read(struct cdk2_fat_file_protocol *p, UINTN *size, void *buf)
{
	struct fat_handle *h; struct cdk2_fat_file_info native;
	struct efi_file_info *wire; size_t native_size; UINTN needed, name_bytes;
	EFI_STATUS status;
	if (p == NULL || size == NULL) return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	drain_tasks(h);
	if (h->file.is_directory) {
		native_size = sizeof(native);
		status = cdk2_fat_file_read(&h->file, &native_size, &native);
		if (EFI_ERROR(status) || native_size == 0U) { *size = native_size; return status; }
		name_bytes = string_size(native.name);
		needed = offsetof(struct efi_file_info, file_name) + name_bytes;
		if (buf == NULL || *size < needed) { *size = needed; return EFI_BUFFER_TOO_SMALL; }
		wire = buf; __builtin_memset(wire, 0, needed); wire->size = needed;
		wire->file_size = native.size; wire->physical_size = native.physical_size;
		wire->attribute = native.attributes;
		__builtin_memcpy(wire->file_name, native.name, name_bytes);
		*size = needed; return EFI_SUCCESS;
	}
	native_size = (size_t)*size;
	status = cdk2_fat_file_read(&h->file, &native_size, buf);
	*size = native_size; return status;
}
static EFI_STATUS CDK2_MS_ABI file_write(struct cdk2_fat_file_protocol *p, UINTN *size, void *buf)
{
	struct fat_handle *h; UINT64 end, status, old_position; uint32_t old_size, old_first;
	struct cdk2_fat_change *changes = NULL;
	size_t count, native_size;
	if (p == NULL || size == NULL || (*size != 0U && buf == NULL)) return EFI_INVALID_PARAMETER;
	h = handle_of(p); if ((h->mode & 2U) == 0U) return FAT_ACCESS_DENIED;
	drain_tasks(h);
	if (h->file.is_directory || h->file.position > UINT32_MAX ||
		*size > UINT32_MAX - h->file.position) return EFI_UNSUPPORTED;
	old_size = h->file.entry.size; old_first = h->file.entry.first_cluster;
	old_position = h->file.position; end = h->file.position + *size;
	if (end > h->file.entry.size) {
		count = h->file.volume->cluster_count;
		status = h->owner->binding->ops->allocate(h->owner->binding->context,
			count * sizeof(*changes), (void **)&changes); if (EFI_ERROR(status)) return status;
		status = cdk2_fat_file_resize(&h->file, (UINT32)end, changes, &count);
		if (EFI_ERROR(status)) { h->owner->binding->ops->release(h->owner->binding->context, changes); return status; }
	}
	native_size = (size_t)*size;
	status = cdk2_fat_write_file((struct cdk2_fat_volume *)h->file.volume,
		h->file.entry.first_cluster, h->file.entry.size, h->file.position, &native_size, buf);
	*size = native_size; if (!EFI_ERROR(status)) h->file.position += native_size;
	else if (changes != NULL) cdk2_fat_file_rollback_resize(&h->file, old_first,
		old_size, old_position, changes, count);
	if (changes != NULL) h->owner->binding->ops->release(h->owner->binding->context, changes);
	return status;
}
static EFI_STATUS CDK2_MS_ABI file_get_position(struct cdk2_fat_file_protocol *p, UINT64 *v)
{
	uint64_t position; EFI_STATUS status;
	if (p == NULL || v == NULL) return EFI_INVALID_PARAMETER;
	drain_tasks(handle_of(p));
	status = cdk2_fat_file_get_position(&handle_of(p)->file, &position);
	*v = position; return status;
}
static EFI_STATUS CDK2_MS_ABI file_set_position(struct cdk2_fat_file_protocol *p, UINT64 v)
{ if (p == NULL) return EFI_INVALID_PARAMETER; drain_tasks(handle_of(p));
	return cdk2_fat_file_set_position(&handle_of(p)->file, v); }
static EFI_STATUS CDK2_MS_ABI file_flush(struct cdk2_fat_file_protocol *p)
{
	struct fat_handle *h; if (p == NULL) return EFI_INVALID_PARAMETER; h = handle_of(p);
	drain_tasks(h);
	return h->file.volume->flush == NULL ? EFI_SUCCESS : h->file.volume->flush(h->file.volume->context);
}
static EFI_STATUS CDK2_MS_ABI file_delete(struct cdk2_fat_file_protocol *p)
{
	struct fat_handle *h; struct cdk2_fat_change *changes = NULL; size_t count; EFI_STATUS status;
	if (p == NULL) return EFI_INVALID_PARAMETER;
	h = handle_of(p); count = h->file.volume->cluster_count;
	drain_tasks(h);
	if ((h->mode & 2U) == 0U || (h->file.entry.attributes & 1U) != 0U) {
		(void)file_close(p); return FAT_WARN_DELETE_FAILURE;
	}
	status = h->owner->binding->ops->allocate(h->owner->binding->context,
		count * sizeof(*changes), (void **)&changes);
	if (!EFI_ERROR(status)) status = cdk2_fat_file_delete(&h->file, changes, &count);
	if (changes != NULL) h->owner->binding->ops->release(h->owner->binding->context, changes);
	(void)file_close(p); return EFI_ERROR(status) ? FAT_WARN_DELETE_FAILURE : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_get_info(struct cdk2_fat_file_protocol *p,
	EFI_GUID *type, UINTN *size, void *buffer)
{
	struct fat_handle *h; struct cdk2_fat_volume_info vi; UINTN needed, n; EFI_STATUS status;
	if (p == NULL || type == NULL || size == NULL) return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	drain_tasks(h);
	if (guid_equal(type, &cdk2_fat_file_info_guid)) {
		struct efi_file_info *i; n = string_size(h->file.entry.name);
		needed = offsetof(struct efi_file_info, file_name) + n;
		if (buffer == NULL || *size < needed) { *size = needed; return EFI_BUFFER_TOO_SMALL; }
		i = buffer; __builtin_memset(i, 0, needed); i->size = needed;
		i->file_size = h->file.entry.size;
		{
			UINT64 cluster_size = (UINT64)h->file.volume->bytes_per_sector *
				h->file.volume->sectors_per_cluster;
			i->physical_size = h->file.entry.size == 0U ? 0U :
				((h->file.entry.size + cluster_size - 1U) / cluster_size) * cluster_size;
		}
		i->attribute = h->file.entry.attributes;
		fat_time(h->file.entry.creation_date, h->file.entry.creation_time, &i->create);
		fat_time(h->file.entry.write_date, h->file.entry.write_time, &i->modify);
		__builtin_memcpy(i->file_name, h->file.entry.name, n); *size = needed; return EFI_SUCCESS;
	}
	status = cdk2_fat_get_volume_info(h->file.volume, &vi); if (EFI_ERROR(status)) return status;
	n = string_size(vi.label);
	if (guid_equal(type, &cdk2_fat_fs_info_guid)) {
		struct efi_fs_info *i; needed = offsetof(struct efi_fs_info, label) + n;
		if (buffer == NULL || *size < needed) { *size = needed; return EFI_BUFFER_TOO_SMALL; }
		i = buffer; __builtin_memset(i, 0, needed); i->size = needed; i->read_only = vi.read_only;
		i->volume_size = vi.volume_size; i->free_space = vi.free_space; i->block_size = vi.block_size;
		__builtin_memcpy(i->label, vi.label, n); *size = needed; return EFI_SUCCESS;
	}
	if (!guid_equal(type, &cdk2_fat_volume_label_info_guid)) return EFI_UNSUPPORTED;
	needed = offsetof(struct efi_label_info, label) + n;
	if (buffer == NULL || *size < needed) { *size = needed; return EFI_BUFFER_TOO_SMALL; }
	__builtin_memcpy(((struct efi_label_info *)buffer)->label, vi.label, n); *size = needed; return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_set_info(struct cdk2_fat_file_protocol *p,
	EFI_GUID *type, UINTN size, void *buffer)
{
	struct fat_handle *h; struct efi_file_info *i; struct cdk2_fat_change *changes;
	size_t count; UINT16 create_date, create_time, write_date, write_time;
	EFI_STATUS status;
	if (p == NULL || type == NULL || buffer == NULL) return EFI_INVALID_PARAMETER;
	h = handle_of(p);
	drain_tasks(h);
	if (guid_equal(type, &cdk2_fat_fs_info_guid)) {
		struct efi_fs_info *fs = buffer;
		if (size < offsetof(struct efi_fs_info, label) + sizeof(CHAR16) ||
		    fs->size > size || (h->mode & 2U) == 0U) return EFI_INVALID_PARAMETER;
		return cdk2_fat_set_volume_label((struct cdk2_fat_volume *)h->file.volume,
			fs->label);
	}
	if (guid_equal(type, &cdk2_fat_volume_label_info_guid)) {
		if (size < sizeof(CHAR16) || (h->mode & 2U) == 0U) return EFI_INVALID_PARAMETER;
		return cdk2_fat_set_volume_label((struct cdk2_fat_volume *)h->file.volume,
			((struct efi_label_info *)buffer)->label);
	}
	if (!guid_equal(type, &cdk2_fat_file_info_guid)) return EFI_UNSUPPORTED;
	if (size < offsetof(struct efi_file_info, file_name) + sizeof(CHAR16))
		return EFI_BAD_BUFFER_SIZE;
	i = buffer;
	if (i->size > size || i->file_size > UINT32_MAX || i->create.year < 1980U ||
		i->create.year > 2107U || i->modify.year < 1980U || i->modify.year > 2107U)
		return EFI_INVALID_PARAMETER;
	create_date = (UINT16)(((i->create.year - 1980U) << 9) |
		(i->create.month << 5) | i->create.day);
	create_time = (UINT16)((i->create.hour << 11) | (i->create.minute << 5) |
		(i->create.second / 2U));
	write_date = (UINT16)(((i->modify.year - 1980U) << 9) |
		(i->modify.month << 5) | i->modify.day);
	write_time = (UINT16)((i->modify.hour << 11) | (i->modify.minute << 5) |
		(i->modify.second / 2U));
	count = h->file.volume->cluster_count;
	if ((h->mode & 2U) == 0U) return FAT_ACCESS_DENIED;
	status = h->owner->binding->ops->allocate(h->owner->binding->context,
		count * sizeof(*changes), (void **)&changes);
	if (EFI_ERROR(status)) return status;
	status = cdk2_fat_file_set_info(&h->file, i->file_name, (UINT32)i->file_size,
		(UINT8)i->attribute, create_date, create_time, write_date, write_time,
		changes, &count);
	h->owner->binding->ops->release(h->owner->binding->context, changes);
	return status;
}
static EFI_STATUS complete(struct fat_handle *h, struct cdk2_fat_file_io_token *t, EFI_STATUS s)
{ if (t == NULL) return EFI_INVALID_PARAMETER; t->status = s; return cdk2_fat_complete_io(h->owner->binding,
	(struct cdk2_fat_io_token *)t, s); }
enum async_kind { ASYNC_OPEN, ASYNC_READ, ASYNC_WRITE, ASYNC_FLUSH };
struct async_task { struct fat_handle *handle; struct cdk2_fat_file_io_token *token;
	enum async_kind kind; struct cdk2_fat_file_protocol **result; CHAR16 *name;
	UINT64 mode, attributes; struct async_task *next; void *cookie; };
static void drain_tasks(struct fat_handle *h)
{
	while (h->tasks != NULL && h->owner->binding->ops->drain != NULL)
		h->owner->binding->ops->drain(h->owner->binding->context, h->tasks->cookie);
}
static void async_dispatch(void *opaque)
{
	struct async_task *task = opaque; struct cdk2_fat_binding *binding;
	void *binding_context; EFI_STATUS status;
	binding = task->handle->owner->binding; binding_context = binding->context;
	{
		struct async_task **link;
		for (link = &task->handle->tasks; *link != NULL; link = &(*link)->next)
			if (*link == task) { *link = task->next; break; }
	}
	task->handle->pending--;
	if (task->kind == ASYNC_OPEN) status = file_open(&task->handle->protocol,
		task->result, task->name, task->mode, task->attributes);
	else if (task->kind == ASYNC_READ) status = file_read(&task->handle->protocol,
		&task->token->buffer_size, task->token->buffer);
	else if (task->kind == ASYNC_WRITE) status = file_write(&task->handle->protocol,
		&task->token->buffer_size, task->token->buffer);
	else status = file_flush(&task->handle->protocol);
	(void)complete(task->handle, task->token, status);
	binding->ops->release(binding_context, task);
}
static EFI_STATUS queue_async(struct fat_handle *h, struct async_task *task)
{
	EFI_STATUS status;
	if (h->owner->binding->ops->queue == NULL) {
		h->owner->binding->ops->release(h->owner->binding->context, task);
		return EFI_UNSUPPORTED;
	}
	drain_tasks(h);
	task->token->status = EFI_NOT_READY;
	h->pending++;
	status = h->owner->binding->ops->queue(h->owner->binding->context, async_dispatch,
		task, &task->cookie);
	if (!EFI_ERROR(status)) { task->next = h->tasks; h->tasks = task; }
	if (EFI_ERROR(status)) { h->pending--;
		h->owner->binding->ops->release(h->owner->binding->context, task); }
	return status;
}
static EFI_STATUS CDK2_MS_ABI file_open_ex(struct cdk2_fat_file_protocol *p,
	struct cdk2_fat_file_protocol **r, CHAR16 *n, UINT64 m, UINT64 a, struct cdk2_fat_file_io_token *t)
{
	struct fat_handle *h; struct async_task *task; EFI_STATUS status;
	if (p == NULL || t == NULL) return EFI_INVALID_PARAMETER;
	if (t->event == NULL) return complete(handle_of(p), t, file_open(p, r, n, m, a));
	h = handle_of(p); status = h->owner->binding->ops->allocate(h->owner->binding->context,
		sizeof(*task), (void **)&task); if (EFI_ERROR(status)) return status;
	*task = (struct async_task) { .handle = h, .token = t, .kind = ASYNC_OPEN,
		.result = r, .name = n, .mode = m, .attributes = a };
	return queue_async(h, task);
}
static EFI_STATUS CDK2_MS_ABI file_read_ex(struct cdk2_fat_file_protocol *p, struct cdk2_fat_file_io_token *t)
{ struct fat_handle *h; struct async_task *task; EFI_STATUS s; if (p == NULL || t == NULL) return EFI_INVALID_PARAMETER;
	if (t->event == NULL) { s = file_read(p, &t->buffer_size, t->buffer); return complete(handle_of(p), t, s); }
	h = handle_of(p); s = h->owner->binding->ops->allocate(h->owner->binding->context, sizeof(*task), (void **)&task);
	if (EFI_ERROR(s)) return s;
	*task = (struct async_task) { .handle = h, .token = t, .kind = ASYNC_READ };
	return queue_async(h, task); }
static EFI_STATUS CDK2_MS_ABI file_write_ex(struct cdk2_fat_file_protocol *p, struct cdk2_fat_file_io_token *t)
{ struct fat_handle *h; struct async_task *task; EFI_STATUS s; if (p == NULL || t == NULL) return EFI_INVALID_PARAMETER;
	if (t->event == NULL) { s = file_write(p, &t->buffer_size, t->buffer); return complete(handle_of(p), t, s); }
	h = handle_of(p); s = h->owner->binding->ops->allocate(h->owner->binding->context, sizeof(*task), (void **)&task);
	if (EFI_ERROR(s)) return s;
	*task = (struct async_task) { .handle = h, .token = t, .kind = ASYNC_WRITE };
	return queue_async(h, task); }
static EFI_STATUS CDK2_MS_ABI file_flush_ex(struct cdk2_fat_file_protocol *p, struct cdk2_fat_file_io_token *t)
{ struct fat_handle *h; struct async_task *task; EFI_STATUS s; if (p == NULL || t == NULL) return EFI_INVALID_PARAMETER;
	if (t->event == NULL) return complete(handle_of(p), t, file_flush(p));
	h = handle_of(p);
	s = h->owner->binding->ops->allocate(h->owner->binding->context, sizeof(*task), (void **)&task);
	if (EFI_ERROR(s)) return s;
	*task = (struct async_task) { .handle = h, .token = t, .kind = ASYNC_FLUSH };
	return queue_async(h, task); }
static const struct cdk2_fat_file_protocol file_template = { FAT_FILE_REVISION2,
	file_open, file_close, file_delete, file_read, file_write, file_get_position,
	file_set_position, file_get_info, file_set_info, file_flush, file_open_ex,
	file_read_ex, file_write_ex, file_flush_ex };
static EFI_STATUS CDK2_MS_ABI open_volume(struct cdk2_fat_simple_fs_protocol *p,
	struct cdk2_fat_file_protocol **result)
{
	struct cdk2_fat_protocol_volume *v; struct fat_handle *h = NULL; EFI_STATUS status;
	if (p == NULL || result == NULL) return EFI_INVALID_PARAMETER;
	*result = NULL;
	v = (struct cdk2_fat_protocol_volume *)((UINT8 *)p - offsetof(struct cdk2_fat_protocol_volume, protocol));
	status = cdk2_fat_binding_open_handle(v->mount); if (EFI_ERROR(status)) return status;
	status = v->binding->ops->allocate(v->binding->context, sizeof(*h), (void **)&h);
	if (!EFI_ERROR(status)) status = cdk2_fat_open_root(&v->mount->volume, &h->file);
	if (EFI_ERROR(status)) { if (h != NULL) v->binding->ops->release(v->binding->context, h);
		cdk2_fat_binding_close_handle(v->mount); return status; }
	h->owner = v; h->protocol = file_template; h->mode = 3U;
	*result = &h->protocol; return EFI_SUCCESS;
}
void cdk2_fat_protocol_init(struct cdk2_fat_protocol_volume *v,
	struct cdk2_fat_binding *binding, struct cdk2_fat_mount *mount)
{ *v = (struct cdk2_fat_protocol_volume) { { FAT_SIMPLE_FS_REVISION, open_volume }, binding, mount }; }
