/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 512U
#define DISK_BLOCKS 300U
#define TABLE 446U

struct fixture {
	UINT8 disk[DISK_BLOCKS][BLOCK_SIZE];
};

static void write32(UINT8 *bytes, UINT32 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
	bytes[2] = (UINT8)(value >> 16);
	bytes[3] = (UINT8)(value >> 24);
}

static void entry(UINT8 *block, UINTN index, UINT8 type, UINT32 start,
	UINT32 blocks)
{
	UINT8 *record = block + TABLE + index * 16U;

	record[4] = type;
	write32(record + 8, start);
	write32(record + 12, blocks);
}

static void seal(UINT8 *block)
{
	block[510] = 0x55U;
	block[511] = 0xaaU;
}

static EFI_STATUS read_blocks(void *context, UINT64 lba, UINTN blocks,
	void *buffer)
{
	struct fixture *fixture = context;

	if (lba >= DISK_BLOCKS || blocks > DISK_BLOCKS - lba)
		return EFI_DEVICE_ERROR;
	memcpy(buffer, &fixture->disk[lba], blocks * BLOCK_SIZE);
	return EFI_SUCCESS;
}

static EFI_STATUS parse(struct fixture *fixture, UINTN block_capacity,
	struct cdk2_partition *partitions, UINTN capacity, UINTN *count)
{
	struct cdk2_partition_media media = {
		.context = fixture,
		.read = read_blocks,
		.block_size = BLOCK_SIZE,
		.last_block = DISK_BLOCKS - 1U,
	};
	UINT8 block[BLOCK_SIZE];

	return cdk2_partition_parse_mbr(&media, block, block_capacity, partitions,
		capacity, count);
}

static int expect(BOOLEAN condition, const char *expression, int line)
{
	if (condition)
		return 0;
	fprintf(stderr, "%s:%d: %s\n", __FILE__, line, expression);
	return 1;
}

#define EXPECT(condition) (failures += expect((condition), #condition, __LINE__))

static void make_extended(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	write32(fixture->disk[0] + 440, 0xa1b2c3d4U);
	entry(fixture->disk[0], 0, 0x83U, 10U, 20U);
	entry(fixture->disk[0], 1, 0x0fU, 100U, 150U);
	seal(fixture->disk[0]);
	entry(fixture->disk[100], 0, 0x07U, 1U, 20U);
	entry(fixture->disk[100], 1, 0x0fU, 30U, 120U);
	seal(fixture->disk[100]);
	entry(fixture->disk[130], 0, 0x83U, 1U, 10U);
	seal(fixture->disk[130]);
}

int main(void)
{
	struct fixture fixture;
	struct cdk2_partition partitions[4];
	UINTN count;
	int failures = 0;

	make_extended(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) == EFI_SUCCESS);
	EXPECT(count == 3U);
	EXPECT(partitions[0].start_lba == 10U && partitions[0].end_lba == 29U);
	EXPECT(partitions[1].start_lba == 101U && partitions[1].index == 5U);
	EXPECT(partitions[2].start_lba == 131U && partitions[2].index == 6U);
	EXPECT(partitions[2].disk_signature == 0xa1b2c3d4U);

	make_extended(&fixture);
	entry(fixture.disk[0], 0, 0xeeU, 1U, DISK_BLOCKS - 1U);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) == EFI_NOT_FOUND);
	make_extended(&fixture);
	fixture.disk[0][510] = 0;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) == EFI_NOT_FOUND);
	make_extended(&fixture);
	fixture.disk[0][TABLE] = 1U;
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) ==
		EFI_COMPROMISED_DATA);
	make_extended(&fixture);
	entry(fixture.disk[0], 2, 0x83U, 20U, 20U);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) ==
		EFI_COMPROMISED_DATA);
	make_extended(&fixture);
	entry(fixture.disk[100], 1, 0x0fU, 1U, 120U);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) ==
		EFI_COMPROMISED_DATA);
	make_extended(&fixture);
	entry(fixture.disk[100], 0, 0x07U, 1U, 200U);
	entry(fixture.disk[100], 1, 0x0fU, 50U, 100U);
	seal(fixture.disk[100]);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) ==
		EFI_COMPROMISED_DATA);
	make_extended(&fixture);
	entry(fixture.disk[130], 0, 0x83U, 1U, 200U);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 4U, &count) ==
		EFI_COMPROMISED_DATA);
	make_extended(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE - 1U, partitions, 4U, &count) ==
		EFI_INVALID_PARAMETER);
	make_extended(&fixture);
	EXPECT(parse(&fixture, BLOCK_SIZE, partitions, 2U, &count) ==
		EFI_BUFFER_TOO_SMALL);
	if (failures == 0)
		puts("partition MBR tests: PASS");
	return failures != 0;
}
