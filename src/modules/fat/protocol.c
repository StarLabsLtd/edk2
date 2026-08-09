/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/fat_binding.h>

#define FAT_FILE_REVISION2 0x00020000ULL
#define FAT_SIMPLE_FS_REVISION 0x00010000ULL
#define FAT_FILE_MODE_CREATE 0x8000000000000000ULL
#define FAT_WARN_DELETE_FAILURE 2U

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
struct fat_handle { struct cdk2_fat_file_protocol protocol;
	struct cdk2_fat_protocol_volume *owner; struct cdk2_fat_file file; };

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
	h = handle_of(protocol); cdk2_fat_binding_close_handle(h->owner->mount);
	h->owner->binding->ops->release(h->owner->binding->context, h);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_open(struct cdk2_fat_file_protocol *protocol,
	struct cdk2_fat_file_protocol **result, CHAR16 *name, UINT64 mode, UINT64 attr)
{
	struct fat_handle *parent, *child = NULL; EFI_STATUS status;
	(void)attr;
	if (protocol == NULL || result == NULL || name == NULL) return EFI_INVALID_PARAMETER;
	*result = NULL; if ((mode & FAT_FILE_MODE_CREATE) != 0U) return EFI_UNSUPPORTED;
	parent = handle_of(protocol);
	status = cdk2_fat_binding_open_handle(parent->owner->mount); if (EFI_ERROR(status)) return status;
	status = parent->owner->binding->ops->allocate(parent->owner->binding->context,
		sizeof(*child), (void **)&child);
	if (!EFI_ERROR(status)) status = cdk2_fat_open(&parent->file, name, &child->file);
	if (EFI_ERROR(status)) { if (child != NULL) parent->owner->binding->ops->release(
		parent->owner->binding->context, child); cdk2_fat_binding_close_handle(parent->owner->mount); return status; }
	child->owner = parent->owner; child->protocol = parent->protocol; *result = &child->protocol;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI file_read(struct cdk2_fat_file_protocol *p, UINTN *size, void *buf)
{
	struct fat_handle *h; struct cdk2_fat_file_info native;
	struct efi_file_info *wire; size_t native_size; UINTN needed, name_bytes;
	EFI_STATUS status;
	if (p == NULL || size == NULL) return EFI_INVALID_PARAMETER;
	h = handle_of(p);
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
	struct fat_handle *h; UINT64 end, status; struct cdk2_fat_change *changes = NULL;
	size_t count, native_size;
	if (p == NULL || size == NULL || (*size != 0U && buf == NULL)) return EFI_INVALID_PARAMETER;
	h = handle_of(p); if (h->file.is_directory || h->file.position > UINT32_MAX ||
		*size > UINT32_MAX - h->file.position) return EFI_UNSUPPORTED;
	end = h->file.position + *size;
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
	if (changes != NULL) h->owner->binding->ops->release(h->owner->binding->context, changes);
	return status;
}
static EFI_STATUS CDK2_MS_ABI file_get_position(struct cdk2_fat_file_protocol *p, UINT64 *v)
{
	uint64_t position; EFI_STATUS status;
	if (p == NULL || v == NULL) return EFI_INVALID_PARAMETER;
	status = cdk2_fat_file_get_position(&handle_of(p)->file, &position);
	*v = position; return status;
}
static EFI_STATUS CDK2_MS_ABI file_set_position(struct cdk2_fat_file_protocol *p, UINT64 v)
{ return p == NULL ? EFI_INVALID_PARAMETER : cdk2_fat_file_set_position(&handle_of(p)->file, v); }
static EFI_STATUS CDK2_MS_ABI file_flush(struct cdk2_fat_file_protocol *p)
{
	struct fat_handle *h; if (p == NULL) return EFI_INVALID_PARAMETER; h = handle_of(p);
	return h->file.volume->flush == NULL ? EFI_SUCCESS : h->file.volume->flush(h->file.volume->context);
}
static EFI_STATUS CDK2_MS_ABI file_delete(struct cdk2_fat_file_protocol *p)
{
	struct fat_handle *h; struct cdk2_fat_change *changes = NULL; size_t count; EFI_STATUS status;
	if (p == NULL) return EFI_INVALID_PARAMETER;
	h = handle_of(p); count = h->file.volume->cluster_count;
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
	if (guid_equal(type, &cdk2_fat_file_info_guid)) {
		struct efi_file_info *i; n = string_size(h->file.entry.name);
		needed = offsetof(struct efi_file_info, file_name) + n;
		if (buffer == NULL || *size < needed) { *size = needed; return EFI_BUFFER_TOO_SMALL; }
		i = buffer; __builtin_memset(i, 0, needed); i->size = needed; i->file_size = h->file.entry.size;
		i->physical_size = h->file.entry.size; i->attribute = h->file.entry.attributes;
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
	h = handle_of(p); count = h->file.volume->cluster_count;
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
static EFI_STATUS CDK2_MS_ABI file_open_ex(struct cdk2_fat_file_protocol *p,
	struct cdk2_fat_file_protocol **r, CHAR16 *n, UINT64 m, UINT64 a, struct cdk2_fat_file_io_token *t)
{ return complete(handle_of(p), t, file_open(p, r, n, m, a)); }
static EFI_STATUS CDK2_MS_ABI file_read_ex(struct cdk2_fat_file_protocol *p, struct cdk2_fat_file_io_token *t)
{ EFI_STATUS s; if (p == NULL || t == NULL) return EFI_INVALID_PARAMETER; s = file_read(p, &t->buffer_size, t->buffer); return complete(handle_of(p), t, s); }
static EFI_STATUS CDK2_MS_ABI file_write_ex(struct cdk2_fat_file_protocol *p, struct cdk2_fat_file_io_token *t)
{ EFI_STATUS s; if (p == NULL || t == NULL) return EFI_INVALID_PARAMETER; s = file_write(p, &t->buffer_size, t->buffer); return complete(handle_of(p), t, s); }
static EFI_STATUS CDK2_MS_ABI file_flush_ex(struct cdk2_fat_file_protocol *p, struct cdk2_fat_file_io_token *t)
{ if (p == NULL || t == NULL) return EFI_INVALID_PARAMETER; return complete(handle_of(p), t, file_flush(p)); }
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
	h->owner = v; h->protocol = file_template; *result = &h->protocol; return EFI_SUCCESS;
}
void cdk2_fat_protocol_init(struct cdk2_fat_protocol_volume *v,
	struct cdk2_fat_binding *binding, struct cdk2_fat_mount *mount)
{ *v = (struct cdk2_fat_protocol_volume) { { FAT_SIMPLE_FS_REVISION, open_volume }, binding, mount }; }
