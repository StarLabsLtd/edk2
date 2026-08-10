/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_disk.h>

#include <stdio.h>
#include <stdlib.h>

#define CHECK(condition) do { if (!(condition)) { \
	fprintf(stderr, "failed: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
	exit(EXIT_FAILURE); \
} } while (0)

struct fixture {
	UINT32 calls;
	UINT32 blocks[3];
	UINT8 opcodes[3];
	BOOLEAN writes[3];
	EFI_STATUS failure;
	UINT8 host_status;
	UINT8 target_status;
};

static EFI_STATUS execute(void *context, struct cdk2_scsi_disk_command *command,
	void *buffer, UINT32 bytes, BOOLEAN write, UINT8 *host_status,
	UINT8 *target_status)
{
	struct fixture *fixture = context;
	UINT32 index = fixture->calls++;

	CHECK(buffer != NULL && bytes == command->blocks * 512U && index < 3U);
	fixture->blocks[index] = command->blocks;
	fixture->opcodes[index] = command->cdb[0];
	fixture->writes[index] = write;
	*host_status = fixture->host_status;
	*target_status = fixture->target_status;
	return fixture->failure;
}

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_scsi_disk disk = {
		.media = { 4, 0, 1, 0, 512, 1, 0x20000U },
		.transport = { &fixture, execute },
	};
	UINT8 *buffer = malloc(0x10000ULL * 512U);

	CHECK(buffer != NULL);
	CHECK(cdk2_scsi_disk_read(&disk, 4, 0, 0x10000ULL * 512U, buffer) ==
		EFI_SUCCESS && fixture.calls == 2U && fixture.blocks[0] == UINT16_MAX &&
		fixture.blocks[1] == 1U && fixture.opcodes[0] == 0x28U);
	fixture = (struct fixture) { 0 };
	disk.cdb16 = 1;
	CHECK(cdk2_scsi_disk_write(&disk, 4, 4, 1024U, buffer) == EFI_SUCCESS &&
		fixture.calls == 1U && fixture.blocks[0] == 2U && fixture.opcodes[0] == 0x8aU &&
		fixture.writes[0]);
	fixture = (struct fixture) { .target_status = 2 };
	CHECK(cdk2_scsi_disk_read(&disk, 4, 0, 512U, buffer) == EFI_DEVICE_ERROR &&
		fixture.calls == 1U);
	fixture = (struct fixture) { .failure = EFI_TIMEOUT };
	CHECK(cdk2_scsi_disk_read(&disk, 4, 0, 512U, buffer) == EFI_TIMEOUT);
	fixture = (struct fixture) { 0 };
	CHECK(cdk2_scsi_disk_read(&disk, 4, 0, 0, NULL) == EFI_SUCCESS &&
		fixture.calls == 0U);
	free(buffer);
	puts("scsi disk I/O tests: PASS");
	return 0;
}
