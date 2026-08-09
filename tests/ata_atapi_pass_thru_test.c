/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

static void topology_and_paths(enum cdk2_ata_mode mode)
{
	struct cdk2_ata_topology topology;
	UINT8 path[16]; size_t size; UINT16 port, device;
	CHECK(cdk2_ata_topology_init(&topology, mode) == EFI_SUCCESS);
	CHECK(cdk2_ata_add_device(&topology, 4, 2, CDK2_ATA_DISK) == EFI_SUCCESS);
	CHECK(cdk2_ata_add_device(&topology, 1, 0xffff, CDK2_ATA_DISK) == EFI_SUCCESS);
	CHECK(cdk2_ata_add_device(&topology, 4, 1, CDK2_ATAPI_DEVICE) == EFI_SUCCESS);
	CHECK(cdk2_ata_add_device(&topology, 4, 2, CDK2_ATA_DISK) == EFI_ALREADY_STARTED);
	port = 0xffff; CHECK(cdk2_ata_get_next_port(&topology, &port) == EFI_SUCCESS);
	CHECK(port == 1); CHECK(cdk2_ata_get_next_port(&topology, &port) == EFI_SUCCESS);
	CHECK(port == 4); CHECK(cdk2_ata_get_next_port(&topology, &port) == EFI_NOT_FOUND);
	port = 3; CHECK(cdk2_ata_get_next_port(&topology, &port) == EFI_INVALID_PARAMETER);
	device = 0xffff;
	CHECK(cdk2_ata_get_next_device(&topology, 4, &device) == EFI_SUCCESS);
	CHECK(device == 2);
	CHECK(cdk2_ata_get_next_device(&topology, 4, &device) == EFI_NOT_FOUND);
	size = 1;
	CHECK(cdk2_ata_build_device_path(&topology, 4, 2, path, &size) ==
		EFI_BUFFER_TOO_SMALL);
	CHECK(size == (mode == CDK2_ATA_IDE ? sizeof(struct cdk2_atapi_device_path) :
		sizeof(struct cdk2_sata_device_path)));
	CHECK(cdk2_ata_build_device_path(&topology, 4, 2, path, &size) == EFI_SUCCESS);
	CHECK(cdk2_ata_get_device(&topology, path, size, &port, &device) == EFI_SUCCESS);
	CHECK(port == 4 && device == 2);
	path[1] = 0xff;
	CHECK(cdk2_ata_get_device(&topology, path, size, &port, &device) == EFI_UNSUPPORTED);
}

int main(void)
{
	UINT8 aligned[16];
	CHECK(sizeof(struct cdk2_atapi_device_path) == 8);
	CHECK(sizeof(struct cdk2_sata_device_path) == 10);
	CHECK(sizeof(struct cdk2_ata_command_block) == 20);
	CHECK(sizeof(struct cdk2_ata_status_block) == 20);
	CHECK(offsetof(struct cdk2_ata_command_packet, timeout) == 2 * sizeof(void *));
	CHECK(offsetof(struct cdk2_ata_command_packet, protocol) ==
		2 * sizeof(void *) + sizeof(UINT64) + 2 * sizeof(void *) + 2 * sizeof(UINT32));
	CHECK(offsetof(struct cdk2_ata_pass_thru_protocol, pass_thru) == sizeof(void *));
	CHECK(sizeof(struct cdk2_ata_pass_thru_protocol) == 8 * sizeof(void *));
	topology_and_paths(CDK2_ATA_IDE);
	topology_and_paths(CDK2_ATA_AHCI);
	CHECK(cdk2_ata_validate_transfer(4, 0x20, aligned, sizeof(aligned), NULL, 0,
		8) == EFI_SUCCESS);
	CHECK(cdk2_ata_validate_transfer(4, 0x20, aligned, sizeof(aligned), aligned,
		1, 8) == EFI_INVALID_PARAMETER);
	CHECK(cdk2_ata_validate_transfer(2, 0, aligned, 1, NULL, 0, 1) ==
		EFI_INVALID_PARAMETER);
	CHECK(cdk2_ata_validate_transfer(3, 0, NULL, 0, NULL, 0, 1) ==
		EFI_INVALID_PARAMETER);
	puts("ata atapi pass thru model tests: PASS");
	return 0;
}
