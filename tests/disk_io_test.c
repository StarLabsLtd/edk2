/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CDK2_DISK_IO_TEST
#include "../src/modules/disk_io/disk_io.c"

static uint8_t medium[4 * 16];
static unsigned int reads, writes, signals;

static uint64_t CDK2_MS_ABI block_read(struct cdk2_block_io *io, uint32_t id,
	uint64_t lba, size_t size, void *buffer)
{
	if (id != io->media->media_id)
		return EFI_DEVICE_ERROR;
	if (size != 16 || lba > 3)
		return EFI_INVALID_PARAMETER;
	memcpy(buffer, medium + lba * 16, 16); reads++; return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI block_write(struct cdk2_block_io *io, uint32_t id,
	uint64_t lba, size_t size, void *buffer)
{
	if (id != io->media->media_id)
		return EFI_DEVICE_ERROR;
	if (size != 16 || lba > 3)
		return EFI_INVALID_PARAMETER;
	memcpy(medium + lba * 16, buffer, 16); writes++; return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI block_flush(struct cdk2_block_io *io)
{ (void)io; return EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI signal(void *event)
{ if (event == (void *)1) signals++; return EFI_SUCCESS; }
static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "disk-io: %s\n", message);
		return 1;
	}
	return 0;
}
int main(void)
{
	struct cdk2_block_media media = { .media_id = 7, .block_size = 16,
		.io_align = 16, .last_block = 3 };
	struct cdk2_block_io block = { .media = &media, .read_blocks = block_read,
		.write_blocks = block_write, .flush_blocks = block_flush };
	uint8_t scratch[16] __aligned(16), output_storage[41], input[20];
	uint8_t *output = output_storage + 1;
	struct disk_context ctx = { .block = &block, .scratch = scratch };
	struct boot_services services = { .signal_event = signal };
	struct cdk2_disk_io2_token token = { .event = (void *)1 };
	int failures = 0; unsigned int i;

	ctx.disk = (struct cdk2_disk_io){ CDK2_DISK_IO_REVISION, read_disk, write_disk };
	ctx.disk2 = (struct cdk2_disk_io2){ CDK2_DISK_IO2_REVISION, cancel,
		read_disk_ex, write_disk_ex, flush_disk_ex };
	for (i = 0; i < sizeof(medium); i++)
		medium[i] = (uint8_t)i;
	reads = writes = 0;
	failures += expect(read_disk(&ctx.disk, 7, 5, 40, output) == EFI_SUCCESS,
		"unaligned multi-block read succeeds");
	failures += expect(memcmp(output, medium + 5, 40) == 0 && reads == 3,
		"read preserves byte-range semantics");
	memset(input, 0xa5, sizeof(input)); reads = writes = 0;
	failures += expect(write_disk(&ctx.disk, 7, 7, sizeof(input), input) == EFI_SUCCESS,
		"unaligned write succeeds");
	failures += expect(memcmp(medium + 7, input, sizeof(input)) == 0 && reads == 2 &&
		writes == 2, "partial blocks use read-modify-write");
	failures += expect(read_disk(&ctx.disk, 7, 0, 0, NULL) == EFI_SUCCESS,
		"zero length accepts null buffer");
	failures += expect(read_disk(&ctx.disk, 7, 63, 2, output) == EFI_INVALID_PARAMETER,
		"range beyond media rejected");
	failures += expect(read_disk(&ctx.disk, 7, UINT64_MAX, 2, output) == EFI_INVALID_PARAMETER,
		"offset overflow rejected");
	failures += expect(read_disk(&ctx.disk, 8, 0, 16, output) == EFI_DEVICE_ERROR,
		"media identifier reaches block driver");
	bs = &services; signals = 0;
	failures += expect(read_disk_ex(&ctx.disk2, 7, 0, &token, 16, output) == EFI_SUCCESS &&
		token.transaction_status == EFI_SUCCESS && signals == 1,
		"v2 completion status and event are delivered");
	token.event = NULL;
	failures += expect(read_disk_ex(&ctx.disk2, 8, 0, &token, 16, output) ==
		EFI_DEVICE_ERROR && token.transaction_status == EFI_DEVICE_ERROR,
		"v2 blocking downgrade returns operation status");
	failures += expect(read_disk_ex(&ctx.disk2, 7, 0, NULL, 16, output) ==
		EFI_SUCCESS, "v2 null token selects blocking I/O");
	failures += expect(flush_disk_ex(&ctx.disk2, &token) == EFI_SUCCESS,
		"v2 flush delegates to block protocol");
	failures += expect(flush_disk_ex(&ctx.disk2, NULL) == EFI_SUCCESS,
		"v2 blocking flush accepts null token");
	return failures != 0;
}
