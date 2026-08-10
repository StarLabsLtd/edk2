/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_disk.h>

#include <stdio.h>

#define CHECK(condition) do { if (!(condition)) { \
	fprintf(stderr, "failed: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
	return 1; \
} } while (0)

int main(void)
{
	UINT8 capacity10[8] = { 0xff, 0xff, 0xff, 0xff, 0, 0, 2, 0 };
	UINT8 capacity16[32] = { 0 };
	struct cdk2_scsi_disk_command command;
	struct cdk2_scsi_disk_media media = { 7, 0, 1, 0, 512, 8, 1023 };
	UINT64 last;
	UINT32 size;
	BOOLEAN needs16;
	UINT64 aligned[64];

	CHECK(cdk2_scsi_disk_parse_capacity10(capacity10, &last, &size, &needs16) ==
		EFI_SUCCESS && last == UINT32_MAX && size == 512U && needs16);
	capacity16[7] = 0xffU; capacity16[10] = 2U;
	CHECK(cdk2_scsi_disk_parse_capacity16(capacity16, &last, &size) == EFI_SUCCESS &&
		last == 0xffU && size == 512U);
	capacity10[7] = 3U;
	CHECK(cdk2_scsi_disk_parse_capacity10(capacity10, &last, &size, &needs16) ==
		EFI_DEVICE_ERROR);
	CHECK(cdk2_scsi_disk_build_rw(0, 0x12345678U, 0x100U, 0, &command) ==
		EFI_SUCCESS && command.cdb_length == 10U && command.cdb[0] == 0x28U &&
		command.cdb[2] == 0x12U && command.cdb[7] == 1U);
	CHECK(cdk2_scsi_disk_build_rw(1, 1ULL << 40, 0x10000U, 1, &command) ==
		EFI_SUCCESS && command.cdb_length == 16U && command.cdb[0] == 0x8aU &&
		command.cdb[4] == 1U && command.cdb[11] == 1U);
	CHECK(cdk2_scsi_disk_build_rw(0, 1ULL << 40, 1, 0, &command) ==
		EFI_BAD_BUFFER_SIZE);
	CHECK(cdk2_scsi_disk_validate(&media, 6, 0, 512, aligned, 0) ==
		EFI_MEDIA_CHANGED);
	CHECK(cdk2_scsi_disk_validate(&media, 7, 1023, 1024, aligned, 0) ==
		EFI_INVALID_PARAMETER);
	CHECK(cdk2_scsi_disk_validate(&media, 7, 0, 513, aligned, 0) ==
		EFI_BAD_BUFFER_SIZE);
	media.read_only = 1;
	CHECK(cdk2_scsi_disk_validate(&media, 7, 0, 512, aligned, 1) ==
		EFI_WRITE_PROTECTED);
	media.present = 0;
	CHECK(cdk2_scsi_disk_validate(&media, 7, 0, 0, NULL, 0) == EFI_NO_MEDIA);
	puts("scsi disk model tests: PASS");
	return 0;
}
