/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_disk.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	void (*complete)(void *context, EFI_STATUS status, UINT8 host, UINT8 target);
	void *context;
	UINT32 submits, signals, executes, cancels;
};

static EFI_STATUS execute(void *opaque, struct cdk2_scsi_disk_command *command,
	void *buffer, UINT32 bytes, BOOLEAN write, UINT8 *host, UINT8 *target)
{
	struct fixture *fixture = opaque;

	(void)command; (void)buffer; (void)bytes; (void)write;
	fixture->executes++; *host = 0U; *target = 0U; return EFI_SUCCESS;
}

static EFI_STATUS submit(void *opaque, struct cdk2_scsi_disk_command *command,
	void *buffer, UINT32 bytes, BOOLEAN write,
	void (*complete)(void *, EFI_STATUS, UINT8, UINT8), void *context)
{
	struct fixture *fixture = opaque;

	(void)command; (void)buffer; (void)bytes; (void)write;
	fixture->submits++; fixture->complete = complete; fixture->context = context;
	return EFI_SUCCESS;
}

static EFI_STATUS cancel(void *opaque)
{
	struct fixture *fixture = opaque;

	fixture->cancels++; return EFI_SUCCESS;
}

static EFI_STATUS wait(void *opaque)
{
	struct fixture *fixture = opaque;

	if (fixture->complete != NULL) {
		void (*complete)(void *, EFI_STATUS, UINT8, UINT8) = fixture->complete;
		void *context = fixture->context;

		fixture->complete = NULL;
		complete(context, EFI_SUCCESS, 0, 0);
	}
	return EFI_SUCCESS;
}

static EFI_STATUS signal(void *opaque, void *event)
{
	struct fixture *fixture = opaque;

	CHECK(event != NULL); fixture->signals++; return EFI_SUCCESS;
}

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_scsi_disk disk = { .media = { 9, 1, 1, 0, 512, 8, 99 },
		.transport = { &fixture, execute, submit, cancel, wait } };
	struct cdk2_scsi_disk_async async;
	struct cdk2_scsi_disk_block block;
	struct cdk2_block_io2_token token = { (void *)1, EFI_SUCCESS };
	struct cdk2_block_io2_token flush = { (void *)2, EFI_SUCCESS };
	UINT8 buffer[512] __aligned(8);

	CHECK(sizeof(struct cdk2_block_media) == 48U &&
		offsetof(struct cdk2_block_media, last_block) == 24U &&
		sizeof(struct cdk2_block_io) == 48U &&
		sizeof(struct cdk2_block_io2) == 40U);
	CHECK(cdk2_scsi_disk_async_init(&async, &disk, &fixture, signal) ==
		EFI_SUCCESS && cdk2_scsi_disk_block_init(&block, &disk, &async) ==
		EFI_SUCCESS);
	CHECK(block.block.media == block.block2.media && block.media.media_id == 9U &&
		block.media.removable_media && block.media.media_present &&
		block.media.block_size == 512U && block.media.io_align == 8U &&
		block.media.last_block == 99U);
	CHECK(block.block.read_blocks(&block.block, 9, 0, sizeof(buffer), buffer) ==
		EFI_SUCCESS && fixture.executes == 1U);
	CHECK(block.block2.write_blocks(&block.block2, 9, 1, &token, sizeof(buffer),
		buffer) == EFI_SUCCESS && token.transaction_status == EFI_NOT_READY &&
		fixture.submits == 1U && fixture.signals == 0U);
	CHECK(block.block2.flush_blocks(&block.block2, &flush) == EFI_SUCCESS &&
		flush.transaction_status == EFI_NOT_READY && fixture.signals == 0U);
	CHECK(block.block.read_blocks(&block.block, 9, 2, sizeof(buffer), buffer) ==
		EFI_SUCCESS && fixture.executes == 2U);
	CHECK(token.transaction_status == EFI_SUCCESS &&
		flush.transaction_status == EFI_SUCCESS && fixture.signals == 2U);
	CHECK(block.block2.reset(&block.block2, FALSE) == EFI_SUCCESS);
	puts("scsi disk block tests: PASS");
	return 0;
}
