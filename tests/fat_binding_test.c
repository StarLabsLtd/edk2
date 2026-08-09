/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/fat_binding.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAT_ACCESS_DENIED EFIERR(15)
#define FAT_ALREADY_STARTED EFIERR(20)

struct fixture {
	struct cdk2_block_media media[2];
	struct cdk2_block_io block[2];
	struct cdk2_disk_io disk[2];
	struct cdk2_disk_io2 disk2[2];
	uint8_t image[2][4096U * 512U];
	unsigned opens, closes, publishes, unpublishes, allocations, releases;
	unsigned fail_open, fail_publish, fail_unpublish, fail_close;
	unsigned signals;
	unsigned have_disk2;
};
static struct fixture *active;
static void (*queued_function)(void *); static void *queued_context;
static void (CDK2_MS_ABI *disk_notify)(void *, void *); static void *disk_context;
static void (CDK2_MS_ABI *event_notify[32])(void *, void *); static void *event_context[32];
static unsigned event_count;
static struct cdk2_disk_io2_token *disk_token;
static UINT64 disk2_offset; static UINTN disk2_size; static void *disk2_buffer;
static unsigned disk2_calls;
static INTN CDK2_MS_ABI collate(struct cdk2_unicode_collation *self,
	CHAR16 *left, CHAR16 *right)
{ (void)self; while (*left == *right && *left != 0U) { left++; right++; } return *left - *right; }
static VOID CDK2_MS_ABI upper(struct cdk2_unicode_collation *self, CHAR16 *text)
{ (void)self; (void)text; }
static BOOLEAN CDK2_MS_ABI to_fat(struct cdk2_unicode_collation *self,
	CHAR16 *text, UINTN size, CHAR8 *fat)
{ (void)self; (void)text; (void)size; (void)fat; return FALSE; }

static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = (uint8_t)(v >> 8); }
static void format(struct fixture *f, unsigned id)
{
	uint8_t *b = f->image[id];
	memset(b, 0, sizeof(f->image[id])); put16(b + 11U, 512U); b[13U] = 1U;
	put16(b + 14U, 1U); b[16U] = 2U; put16(b + 17U, 224U);
	put16(b + 19U, 4096U); put16(b + 22U, 9U);
	b[510U] = 0x55U; b[511U] = 0xaaU;
	b[512U + 3U] = 3U; b[512U + 4U] = 0xf0U; b[512U + 5U] = 0xffU;
	memcpy(b + 9728U, "ASYNC   TXT", 11U); b[9728U + 11U] = 0x20U;
	put16(b + 9728U + 26U, 2U); b[9728U + 28U] = 0x58U; b[9728U + 29U] = 2U;
	memset(b + 16896U, 'A', 512U); memset(b + 17408U, 'B', 88U);
}
static uint64_t CDK2_MS_ABI disk_read(struct cdk2_disk_io *disk, uint32_t media,
	uint64_t offset, size_t size, void *buffer)
{
	struct fixture *f = active;
	unsigned id = disk == &f->disk[1];
	if (media != f->media[id].media_id || offset > sizeof(f->image[id]) ||
	    size > sizeof(f->image[id]) - offset)
		return EFI_INVALID_PARAMETER;
	memcpy(buffer, f->image[id] + offset, size); return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI disk_flush(struct cdk2_disk_io2 *disk,
	struct cdk2_disk_io2_token *token)
{ unsigned id = (unsigned)(UINTN)token->event - 4U; (void)disk; disk_token = token;
	disk_notify = event_notify[id]; disk_context = event_context[id]; return EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI disk_read_ex(struct cdk2_disk_io2 *disk, uint32_t media,
	uint64_t offset, struct cdk2_disk_io2_token *token, size_t size, void *buffer)
{ unsigned id = (unsigned)(UINTN)token->event - 4U;
	(void)disk; (void)media; disk_token = token; disk2_offset = offset;
	disk_notify = event_notify[id]; disk_context = event_context[id];
	disk2_size = size; disk2_buffer = buffer; disk2_calls++; return EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI disk_write_ex(struct cdk2_disk_io2 *disk, uint32_t media,
	uint64_t offset, struct cdk2_disk_io2_token *token, size_t size, void *buffer)
{ return disk_read_ex(disk, media, offset, token, size, buffer); }
static EFI_STATUS open_protocol(void *context, void *controller,
	const EFI_GUID *guid, void **interface)
{
	struct fixture *f = context; unsigned id = controller == (void *)2;
	f->opens++; if (f->opens == f->fail_open) return EFI_DEVICE_ERROR;
	if (guid->data1 == cdk2_fat_disk_io2_guid.data1 && !f->have_disk2)
		return EFI_UNSUPPORTED;
	*interface = guid->data1 == cdk2_fat_block_io_guid.data1 ?
		(void *)&f->block[id] : (guid->data1 == cdk2_fat_disk_io2_guid.data1 ?
		(void *)&f->disk2[id] : (void *)&f->disk[id]);
	return EFI_SUCCESS;
}
static EFI_STATUS close_protocol(void *context, void *controller,
	const EFI_GUID *guid)
{ struct fixture *f = context; (void)controller; (void)guid; f->closes++; return f->closes == f->fail_close ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS publish(void *context, void *controller, const EFI_GUID *guid,
	void *interface)
{ struct fixture *f = context; (void)controller; (void)guid; (void)interface; f->publishes++; return f->publishes == f->fail_publish ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS unpublish(void *context, void *controller, const EFI_GUID *guid,
	void *interface)
{ struct fixture *f = context; (void)controller; (void)guid; (void)interface; f->unpublishes++; return f->unpublishes == f->fail_unpublish ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ struct fixture *f = context; f->allocations++; *buffer = calloc(1U, size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ struct fixture *f = context; f->releases++; free(buffer); }
static EFI_STATUS signal(void *context, void *event)
{ struct fixture *f = context; if (event == NULL) return EFI_INVALID_PARAMETER; f->signals++; return EFI_SUCCESS; }
static EFI_STATUS queue(void *context, void (*function)(void *), void *opaque, void **cookie)
{ (void)context; queued_function = function; queued_context = opaque; *cookie = opaque; return EFI_SUCCESS; }
static void drain(void *context, void *cookie)
{ (void)context; (void)cookie; queued_function(queued_context); queued_function = NULL; }
static EFI_STATUS create_event(void *context,
	void (CDK2_MS_ABI *notify)(void *, void *), void *opaque, void **event)
{ unsigned id = event_count++; (void)context; event_notify[id] = notify;
	event_context[id] = opaque; *event = (void *)(UINTN)(id + 4U); return EFI_SUCCESS; }
static EFI_STATUS close_event(void *context, void *event)
{ (void)context; (void)event; return EFI_SUCCESS; }
static EFI_STATUS wait_event(void *context, void *event)
{ (void)context; (void)event; return EFI_SUCCESS; }
static int expect(int ok, const char *message)
{ if (!ok) fprintf(stderr, "FAT binding test: %s\n", message); return !ok; }

int main(void)
{
	static const struct cdk2_fat_binding_ops ops = {
		open_protocol, close_protocol, publish, unpublish, allocate, release, signal, queue,
		drain, create_event, close_event, wait_event
	};
	struct fixture f = { 0 };
	struct cdk2_unicode_collation collation = { .stri_coll = collate,
		.str_upr = upper, .str_to_fat = to_fat };
	struct cdk2_fat_binding binding = { &ops, &f, NULL, &collation };
	struct cdk2_fat_mount *first;
	int failures = 0; unsigned id;
	struct cdk2_fat_io_token token = { (void *)3, EFI_SUCCESS };
	active = &f;
	f.have_disk2 = 1U;
	failures += expect(cdk2_fat_complete_io(&binding, &token, EFI_DEVICE_ERROR) ==
		EFI_SUCCESS && token.transaction_status == EFI_DEVICE_ERROR &&
		f.signals == 1U, "revision-2 completion did not publish status before signal");
	for (id = 0U; id < 2U; id++) {
		format(&f, id); f.media[id] = (struct cdk2_block_media) {
			.media_id = id + 1U, .media_present = 1U, .block_size = 512U,
			.last_block = 4095U };
		f.block[id].media = &f.media[id];
		f.disk[id].read_disk = disk_read;
		f.disk2[id].flush_disk_ex = disk_flush;
		f.disk2[id].read_disk_ex = disk_read_ex;
		f.disk2[id].write_disk_ex = disk_write_ex;
	}
	failures += expect(cdk2_fat_binding_start(&binding, (void *)1) == EFI_SUCCESS &&
		cdk2_fat_binding_start(&binding, (void *)2) == EFI_SUCCESS &&
		binding.mounts != NULL && binding.mounts->next != NULL,
		"independent controllers did not publish independent volumes");
	{
		struct cdk2_fat_file_protocol *root;
		struct cdk2_fat_file_io_token async = { (void *)9, EFI_NOT_READY, 0U, NULL };
		failures += expect(binding.mounts->simple_fs->protocol.open_volume(
			&binding.mounts->simple_fs->protocol, &root) == EFI_SUCCESS &&
			root->flush_ex(root, &async) == EFI_SUCCESS && disk_token != NULL &&
			async.status == EFI_NOT_READY && f.signals == 1U,
			"revision-2 request did not reach DiskIo2 with handle residency");
		disk_token->transaction_status = EFI_SUCCESS;
		disk_notify(disk_token->event, disk_context);
		failures += expect(root->close(root) == EFI_SUCCESS && async.status == EFI_SUCCESS &&
			f.signals == 2U, "DiskIo2 completion did not release handle residency");
	}
	{
		struct cdk2_fat_file_protocol *root, *file;
		UINT8 output[600];
		struct cdk2_fat_file_io_token token = { (void *)9, EFI_NOT_READY,
			sizeof(output), output };
		failures += expect(binding.mounts->simple_fs->protocol.open_volume(
			&binding.mounts->simple_fs->protocol, &root) == EFI_SUCCESS &&
			root->open(root, &file, L"ASYNC.TXT", 1U, 0U) == EFI_SUCCESS &&
			file->read_ex(file, &token) == EFI_SUCCESS && disk2_offset == 16896U &&
			disk2_size == 512U && token.status == EFI_NOT_READY,
			"fragmented ReadEx did not submit its first DiskIo2 extent");
		memcpy(disk2_buffer, f.image[1] + disk2_offset, disk2_size);
		disk_token->transaction_status = EFI_SUCCESS;
		disk_notify(disk_token->event, disk_context);
		failures += expect(disk2_offset == 17408U && disk2_size == 88U &&
			token.status == EFI_NOT_READY,
			"fragmented ReadEx did not chain its second DiskIo2 extent");
		memcpy(disk2_buffer, f.image[1] + disk2_offset, disk2_size);
		disk_token->transaction_status = EFI_SUCCESS;
		disk_notify(disk_token->event, disk_context);
		failures += expect(token.status == EFI_SUCCESS && token.buffer_size == 600U &&
			output[0] == 'A' && output[511] == 'A' && output[512] == 'B',
			"fragmented DiskIo2 completion did not publish exact data/status");
		(void)file->close(file); (void)root->close(root);
	}
	{
		struct cdk2_fat_file_protocol *root, *file;
		UINT8 first[300], second[300];
		struct cdk2_fat_file_io_token one = { (void *)9, EFI_NOT_READY,
			sizeof(first), first };
		struct cdk2_fat_file_io_token two = { (void *)8, EFI_NOT_READY,
			sizeof(second), second };
		unsigned calls = disk2_calls;
		(void)binding.mounts->simple_fs->protocol.open_volume(
			&binding.mounts->simple_fs->protocol, &root);
		(void)root->open(root, &file, L"ASYNC.TXT", 1U, 0U);
		failures += expect(file->read_ex(file, &one) == EFI_SUCCESS &&
			file->read_ex(file, &two) == EFI_SUCCESS && disk2_calls == calls + 1U,
			"same-handle async requests were submitted out of order");
		memcpy(disk2_buffer, f.image[1] + disk2_offset, disk2_size);
		disk_token->transaction_status = EFI_SUCCESS;
		disk_notify(disk_token->event, disk_context);
		failures += expect(one.status == EFI_SUCCESS && two.status == EFI_NOT_READY &&
			disk2_calls == calls + 2U && disk2_offset == 17196U,
			"second same-handle request did not start after first completion");
		memcpy(disk2_buffer, f.image[1] + disk2_offset, disk2_size);
		disk_token->transaction_status = EFI_SUCCESS;
		disk_notify(disk_token->event, disk_context);
		failures += expect(two.status == EFI_NOT_READY && disk2_offset == 17408U &&
			disk2_size == 88U, "serialized request did not cross its FAT extent");
		memcpy(disk2_buffer, f.image[1] + disk2_offset, disk2_size);
		disk_token->transaction_status = EFI_SUCCESS;
		disk_notify(disk_token->event, disk_context);
		failures += expect(two.status == EFI_SUCCESS && second[0] == 'A' &&
			second[211] == 'A' && second[212] == 'B',
			"serialized second request returned wrong fragmented data");
		(void)file->close(file); (void)root->close(root);
	}
	{
		struct cdk2_fat_file_protocol *root, *file;
		UINT8 input[600];
		struct cdk2_fat_file_io_token token = { (void *)9, EFI_NOT_READY,
			sizeof(input), input };
		memset(input, 'W', sizeof(input));
		failures += expect(binding.mounts->simple_fs->protocol.open_volume(
			&binding.mounts->simple_fs->protocol, &root) == EFI_SUCCESS &&
			root->open(root, &file, L"ASYNC.TXT", 3U, 0U) == EFI_SUCCESS &&
			file->write_ex(file, &token) == EFI_SUCCESS && disk2_offset == 16896U,
			"fragmented WriteEx did not submit through DiskIo2");
		disk_token->transaction_status = EFI_DEVICE_ERROR;
		disk_notify(disk_token->event, disk_context);
		failures += expect(token.status == EFI_DEVICE_ERROR && token.buffer_size == 0U,
			"failed first DiskIo2 extent reported bytes or lost its status");
		(void)file->close(file); (void)root->close(root);
	}
	failures += expect(cdk2_fat_binding_start(&binding, (void *)1) ==
		FAT_ALREADY_STARTED, "repeated Start was not idempotently rejected");
	first = binding.mounts;
	failures += expect(cdk2_fat_binding_open_handle(first) == EFI_SUCCESS &&
		cdk2_fat_binding_stop(&binding, first->controller) == FAT_ACCESS_DENIED,
		"Stop released a volume with an open file handle");
	cdk2_fat_binding_close_handle(first);
	f.media[1].media_id++;
	failures += expect(cdk2_fat_binding_open_handle(first) == EFI_SUCCESS &&
		first->media_id == f.media[1].media_id,
		"closed volume did not remount after media change");
	cdk2_fat_binding_close_handle(first);
	f.fail_unpublish = f.unpublishes + 1U;
	failures += expect(cdk2_fat_binding_stop(&binding, first->controller) ==
		EFI_DEVICE_ERROR && binding.mounts == first,
		"unpublish failure destroyed live volume ownership");
	f.fail_unpublish = 0U;
	failures += expect(cdk2_fat_binding_stop(&binding, first->controller) ==
		EFI_SUCCESS && cdk2_fat_binding_stop(&binding, (void *)1) == EFI_SUCCESS &&
		binding.mounts == NULL && f.allocations == f.releases,
		"successful Stop leaked a mount or protocol ownership");

	memset(&binding, 0, sizeof(binding)); binding.ops = &ops; binding.context = &f;
	binding.collation = &collation;
	f.fail_publish = f.publishes + 1U;
	failures += expect(cdk2_fat_binding_start(&binding, (void *)1) ==
		EFI_DEVICE_ERROR && binding.mounts == NULL && f.allocations == f.releases,
		"Start publication failure did not unwind allocation and opens");
	f.fail_publish = 0U;
	failures += expect(cdk2_fat_binding_start(&binding, (void *)1) == EFI_SUCCESS,
		"rollback fixture could not start volume");
	first = binding.mounts; f.fail_close = f.closes + 2U;
	failures += expect(cdk2_fat_binding_stop(&binding, (void *)1) == EFI_DEVICE_ERROR &&
		first->published && first->disk_open && first->block_open,
		"Stop close failure did not restore a retryable published volume");
	f.fail_close = 0U;
	failures += expect(cdk2_fat_binding_stop(&binding, (void *)1) == EFI_SUCCESS &&
		binding.mounts == NULL, "Stop rollback state was not retryable");
	f.have_disk2 = 0U;
	failures += expect(cdk2_fat_binding_start(&binding, (void *)1) == EFI_SUCCESS,
		"DiskIo-only parent was rejected");
	{
		struct cdk2_fat_file_protocol *root;
		struct cdk2_fat_file_io_token token = { (void *)1, EFI_NOT_READY, 0U, NULL };
		failures += expect(binding.mounts->simple_fs->protocol.open_volume(
			&binding.mounts->simple_fs->protocol, &root) == EFI_SUCCESS &&
			root->revision == 0x00010000ULL && root->flush_ex(root, &token) ==
			EFI_UNSUPPORTED, "DiskIo-only parent incorrectly advertised revision 2");
		(void)root->close(root);
	}
	failures += expect(cdk2_fat_binding_stop(&binding, (void *)1) == EFI_SUCCESS,
		"DiskIo-only parent did not stop cleanly");
	return failures == 0 ? 0 : 1;
}
