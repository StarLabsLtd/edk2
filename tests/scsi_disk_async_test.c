/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_disk.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	void (*complete)(void *context, EFI_STATUS status, UINT8 host, UINT8 target);
	void *complete_context;
	UINT32 calls, signals, blocks[4];
	UINT8 opcodes[4];
	EFI_STATUS submit_status;
};

static EFI_STATUS submit(void *opaque, struct cdk2_scsi_disk_command *command,
	void *buffer, UINT32 bytes, BOOLEAN write,
	void (*complete)(void *, EFI_STATUS, UINT8, UINT8), void *context)
{
	struct fixture *fixture = opaque;
	UINT32 index = fixture->calls++;

	(void)write;
	CHECK(index < 4U && buffer != NULL && bytes == command->blocks * 512U);
	fixture->blocks[index] = command->blocks;
	fixture->opcodes[index] = command->cdb[0];
	if (EFI_ERROR(fixture->submit_status))
		return fixture->submit_status;
	fixture->complete = complete;
	fixture->complete_context = context;
	return EFI_SUCCESS;
}

static EFI_STATUS signal(void *opaque, void *event)
{
	struct fixture *fixture = opaque;

	CHECK(event != NULL);
	fixture->signals++;
	return EFI_SUCCESS;
}

static void complete(struct fixture *fixture, EFI_STATUS status, UINT8 host,
	UINT8 target)
{
	void (*notify)(void *, EFI_STATUS, UINT8, UINT8) = fixture->complete;
	void *context = fixture->complete_context;

	CHECK(notify != NULL);
	fixture->complete = NULL;
	fixture->complete_context = NULL;
	notify(context, status, host, target);
}

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_scsi_disk disk = { .media = { 7, 0, 1, 0, 512, 1,
		0x40000U }, .transport = { .context = &fixture, .submit = submit } };
	struct cdk2_scsi_disk_async async;
	struct cdk2_scsi_disk_token first = { (void *)1, EFI_SUCCESS };
	struct cdk2_scsi_disk_token second = { (void *)2, EFI_SUCCESS };
	UINT8 *buffer = malloc(0x10001ULL * 512U);

	CHECK(buffer != NULL && cdk2_scsi_disk_async_init(&async, &disk, &fixture,
		signal) == EFI_SUCCESS);
	CHECK(cdk2_scsi_disk_async_submit(&async, 7, 0, 0x10000ULL * 512U,
		buffer, FALSE, &first) == EFI_SUCCESS && fixture.calls == 1U &&
		fixture.signals == 0U && first.status == EFI_NOT_READY &&
		fixture.blocks[0] == UINT16_MAX);
	CHECK(cdk2_scsi_disk_async_submit(&async, 7, 0x10000U, 512U,
		buffer, TRUE, &second) == EFI_SUCCESS && fixture.calls == 1U);
	CHECK(cdk2_scsi_disk_async_submit(&async, 7, 0, 512U, buffer, FALSE,
		&second) == EFI_ALREADY_STARTED);
	complete(&fixture, EFI_SUCCESS, 0, 0);
	CHECK(fixture.calls == 2U && fixture.signals == 0U &&
		fixture.blocks[1] == 1U);
	complete(&fixture, EFI_SUCCESS, 0, 0);
	CHECK(first.status == EFI_SUCCESS && fixture.signals == 1U &&
		fixture.calls == 3U && fixture.opcodes[2] == 0x2aU);
	complete(&fixture, EFI_SUCCESS, 0, 2);
	CHECK(second.status == EFI_DEVICE_ERROR && fixture.signals == 2U &&
		async.count == 0U);
	fixture.submit_status = EFI_TIMEOUT;
	first.status = EFI_SUCCESS;
	CHECK(cdk2_scsi_disk_async_submit(&async, 7, 0, 512U, buffer, FALSE,
		&first) == EFI_TIMEOUT && first.status == EFI_SUCCESS &&
		fixture.signals == 2U && async.count == 0U);
	fixture.submit_status = EFI_SUCCESS;
	second.status = EFI_NOT_READY;
	CHECK(cdk2_scsi_disk_async_submit(&async, 7, 0, 0, NULL, FALSE, &second) ==
		EFI_SUCCESS && second.status == EFI_SUCCESS && fixture.signals == 3U);
	free(buffer);
	puts("scsi disk async tests: PASS");
	return 0;
}
