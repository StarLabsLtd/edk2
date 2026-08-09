/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 512U
#define DISK_BLOCKS 100U

struct fixture {
	UINT8 disk[DISK_BLOCKS][BLOCK_SIZE];
	BOOLEAN fail_read;
};

static void write32(UINT8 *bytes, UINT32 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
	bytes[2] = (UINT8)(value >> 16);
	bytes[3] = (UINT8)(value >> 24);
}

static void write64(UINT8 *bytes, UINT64 value)
{
	write32(bytes, (UINT32)value);
	write32(bytes + 4, (UINT32)(value >> 32));
}

static EFI_STATUS read_blocks(void *context, UINT64 lba, UINTN blocks,
	void *buffer)
{
	struct fixture *fixture = context;

	if (fixture->fail_read)
		return EFI_DEVICE_ERROR;
	if (lba + blocks > DISK_BLOCKS)
		return EFI_INVALID_PARAMETER;
	memcpy(buffer, &fixture->disk[lba], blocks * BLOCK_SIZE);
	return EFI_SUCCESS;
}

static void make_backup(struct fixture *fixture)
{
	UINT8 *header = fixture->disk[DISK_BLOCKS - 1U];

	memcpy(fixture->disk[DISK_BLOCKS - 2U], fixture->disk[2], BLOCK_SIZE);
	memcpy(header, fixture->disk[1], BLOCK_SIZE);
	write64(header + 24, DISK_BLOCKS - 1U);
	write64(header + 32, 1U);
	write64(header + 48, DISK_BLOCKS - 3U);
	write64(header + 72, DISK_BLOCKS - 2U);
	write32(header + 88, cdk2_partition_crc32(
		fixture->disk[DISK_BLOCKS - 2U], BLOCK_SIZE));
	write32(header + 16, 0);
	write32(header + 16, cdk2_partition_crc32(header, 92U));
}

static void update_crcs(struct fixture *fixture)
{
	UINT8 *header = fixture->disk[1];

	write32(header + 88, cdk2_partition_crc32(fixture->disk[2], BLOCK_SIZE));
	write32(header + 16, 0);
	write32(header + 16, cdk2_partition_crc32(header, 92U));
}

static void make_fixture(struct fixture *fixture)
{
	UINT8 *header;
	UINT8 *entry;
	UINTN index;

	memset(fixture, 0, sizeof(*fixture));
	header = fixture->disk[1];
	entry = fixture->disk[2];
	memcpy(header, "EFI PART", 8);
	write32(header + 8, 0x00010000U);
	write32(header + 12, 92U);
	write64(header + 24, 1U);
	write64(header + 32, DISK_BLOCKS - 1U);
	write64(header + 40, 34U);
	write64(header + 48, 98U);
	header[56] = 0xa5;
	write64(header + 72, 2U);
	write32(header + 80, 4U);
	write32(header + 84, 128U);
	for (index = 0; index < 16; index++) {
		entry[index] = (UINT8)(index + 1U);
		entry[16U + index] = (UINT8)(0x80U + index);
	}
	write64(entry + 32, 40U);
	write64(entry + 40, 49U);
	write64(entry + 48, 0x1122334455667788ULL);
	entry[56] = 'O';
	entry[58] = 'S';
	update_crcs(fixture);
}

static EFI_STATUS parse(struct fixture *fixture, UINTN entry_capacity,
	struct cdk2_partition *partitions, UINTN capacity, UINTN *count)
{
	struct cdk2_partition_media media = {
		.context = fixture,
		.read = read_blocks,
		.block_size = BLOCK_SIZE,
		.last_block = DISK_BLOCKS - 1U,
	};
	UINT8 header[BLOCK_SIZE];
	UINT8 entries[BLOCK_SIZE];

	return cdk2_partition_parse_gpt(&media, header, sizeof(header), entries,
		entry_capacity, partitions, capacity, count);
}

static int expect(BOOLEAN condition, const char *expression, int line)
{
	if (condition)
		return 0;
	fprintf(stderr, "%s:%d: %s\n", __FILE__, line, expression);
	return 1;
}

#define EXPECT(condition) (failures += expect((condition), #condition, __LINE__))

int main(void)
{
	struct fixture fixture;
	struct cdk2_partition partitions[2];
	UINTN count;
	EFI_STATUS status;
	int failures = 0;

	make_fixture(&fixture);
	status = parse(&fixture, BLOCK_SIZE, partitions, 2U, &count);
	EXPECT(status == EFI_SUCCESS && count == 1U);
	EXPECT(partitions[0].scheme == CDK2_PARTITION_GPT);
	EXPECT(partitions[0].start_lba == 40U && partitions[0].end_lba == 49U);
	EXPECT(partitions[0].attributes == 0x1122334455667788ULL);
	EXPECT(partitions[0].index == 1U && partitions[0].name[0] == 'O' &&
		partitions[0].name[1] == 'S');

	make_fixture(&fixture);
	make_backup(&fixture);
	fixture.disk[1][40] ^= 1U;
	status = parse(&fixture, BLOCK_SIZE, partitions, 2U, &count);
	EXPECT(status == EFI_SUCCESS &&
		count == 1U && partitions[0].start_lba == 40U);
	make_fixture(&fixture);
	make_backup(&fixture);
	fixture.disk[2][60] ^= 1U;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) == EFI_SUCCESS &&
		count == 1U);
	make_fixture(&fixture);
	make_backup(&fixture);
	fixture.disk[1][0] = 0;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) == EFI_SUCCESS &&
		count == 1U);
	make_fixture(&fixture);
	write64(fixture.disk[1] + 72, 40U);
	update_crcs(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) ==
		EFI_COMPROMISED_DATA);
	make_fixture(&fixture);
	write64(fixture.disk[1] + 72, DISK_BLOCKS - 1U);
	update_crcs(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) ==
		EFI_COMPROMISED_DATA);
	make_fixture(&fixture);
	write64(fixture.disk[1] + 32, 50U);
	update_crcs(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) ==
		EFI_COMPROMISED_DATA);

	make_fixture(&fixture);
	fixture.disk[1][0] = 0;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) == EFI_NOT_FOUND);
	make_fixture(&fixture);
	fixture.disk[1][40] ^= 1U;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) == EFI_CRC_ERROR);
	make_fixture(&fixture);
	fixture.disk[2][60] ^= 1U;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) == EFI_CRC_ERROR);
	make_fixture(&fixture);
	write64(fixture.disk[2] + 32, 50U);
	write64(fixture.disk[2] + 40, 40U);
	update_crcs(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) ==
		EFI_COMPROMISED_DATA);
	make_fixture(&fixture);
	memcpy(fixture.disk[2] + 128, fixture.disk[2], 128);
	write64(fixture.disk[2] + 128 + 32, 45U);
	write64(fixture.disk[2] + 128 + 40, 55U);
	update_crcs(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) ==
		EFI_COMPROMISED_DATA);
	make_fixture(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE - 1U, partitions, 2U, &count) ==
		EFI_BAD_BUFFER_SIZE);
	make_fixture(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 0U, &count) ==
		EFI_BUFFER_TOO_SMALL);
	make_fixture(&fixture);
	fixture.fail_read = TRUE;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) == EFI_DEVICE_ERROR);
	if (failures == 0)
		puts("partition GPT tests: PASS");
	return failures != 0;
}
