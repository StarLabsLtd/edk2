/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 2048U
#define DISK_BLOCKS 600U

struct fixture {
	UINT8 disk[DISK_BLOCKS][BLOCK_SIZE];
};

static struct fixture fixture;

static void write16(UINT8 *bytes, UINT16 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
}

static void write32(UINT8 *bytes, UINT32 value)
{
	write16(bytes, (UINT16)value);
	write16(bytes + 2, (UINT16)(value >> 16));
}

static UINT16 crc16(const UINT8 *bytes, UINTN size)
{
	UINT16 crc = 0;
	UINTN index;
	UINTN bit;

	for (index = 0; index < size; index++) {
		crc ^= (UINT16)bytes[index] << 8;
		for (bit = 0; bit < 8; bit++)
			crc = crc & 0x8000U ? (UINT16)((crc << 1) ^ 0x1021U) :
				(UINT16)(crc << 1);
	}
	return crc;
}

static void seal(UINT8 *block, UINT16 tag, UINT32 location, UINT16 crc_length)
{
	UINT8 sum = 0;
	UINTN index;

	write16(block, tag);
	write16(block + 2, 2U);
	write32(block + 12, location);
	write16(block + 10, crc_length);
	write16(block + 8, crc16(block + 16, crc_length));
	block[4] = 0;
	for (index = 0; index < 16U; index++)
		if (index != 4U)
			sum = (UINT8)(sum + block[index]);
	block[4] = sum;
}

static void make_fixture(void)
{
	UINT8 *block;
	UINT32 base;

	memset(&fixture, 0, sizeof(fixture));
	block = fixture.disk[256];
	write32(block + 16, 4U * BLOCK_SIZE);
	write32(block + 20, 300U);
	seal(block, 2U, 256U, 16U);
	for (base = 300U; base <= 320U; base += 20U) {
		seal(fixture.disk[base], 1U, base, 16U);
		block = fixture.disk[base + 1U];
		write16(block + 22, 5U);
		write32(block + 184, 1U);
		write32(block + 188, 400U);
		write32(block + 192, 100U);
		seal(block, 5U, base + 1U, 180U);
		block = fixture.disk[base + 2U];
		write32(block + 212, BLOCK_SIZE);
		write32(block + 248, BLOCK_SIZE);
		write32(block + 252, 5U);
		write16(block + 256, 0U);
		write32(block + 264, 6U);
		write32(block + 268, 1U);
		block[440] = 1U;
		block[441] = 6U;
		write16(block + 444, 5U);
		seal(block, 6U, base + 2U, 424U);
		seal(fixture.disk[base + 3U], 8U, base + 3U, 16U);
	}
	seal(fixture.disk[405], 256U, 5U, 496U);
}

static EFI_STATUS read_blocks(void *context, UINT64 lba, UINTN blocks,
	void *buffer)
{
	struct fixture *disk = context;

	if (lba >= DISK_BLOCKS || blocks > DISK_BLOCKS - lba)
		return EFI_DEVICE_ERROR;
	memcpy(buffer, &disk->disk[lba], blocks * BLOCK_SIZE);
	return EFI_SUCCESS;
}

static EFI_STATUS parse(struct cdk2_partition *partitions, UINTN capacity,
	UINTN *count)
{
	struct cdk2_partition_media media = {
		.context = &fixture,
		.read = read_blocks,
		.block_size = BLOCK_SIZE,
		.last_block = DISK_BLOCKS - 1U,
	};
	UINT8 block[BLOCK_SIZE];

	return cdk2_partition_parse_udf(&media, block, sizeof(block), partitions,
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

int main(void)
{
	struct cdk2_partition partitions[2];
	UINTN count;
	int failures = 0;

	make_fixture();
	EXPECT(parse(partitions, 2U, &count) == EFI_SUCCESS && count == 1U);
	EXPECT(partitions[0].scheme == CDK2_PARTITION_UDF);
	EXPECT(partitions[0].start_lba == 400U && partitions[0].end_lba == 499U);
	EXPECT(partitions[0].index == 6U && partitions[0].attributes == 1U);
	make_fixture();
	write32(fixture.disk[302] + 264, 64U);
	fixture.disk[302][440] = 2U;
	fixture.disk[302][441] = 64U;
	write16(fixture.disk[302] + 478, 5U);
	seal(fixture.disk[302], 6U, 302U, 424U);
	EXPECT(parse(partitions, 2U, &count) == EFI_UNSUPPORTED);

	make_fixture();
	write32(fixture.disk[256] + 24, 4U * BLOCK_SIZE);
	write32(fixture.disk[256] + 28, 320U);
	seal(fixture.disk[256], 2U, 256U, 16U);
	fixture.disk[301][4] ^= 1U;
	EXPECT(parse(partitions, 2U, &count) == EFI_SUCCESS && count == 1U);

	make_fixture();
	memcpy(fixture.disk[599], fixture.disk[256], BLOCK_SIZE);
	seal(fixture.disk[599], 2U, 599U, 16U);
	fixture.disk[256][4] ^= 1U;
	EXPECT(parse(partitions, 2U, &count) == EFI_SUCCESS);
	make_fixture();
	memcpy(fixture.disk[599], fixture.disk[256], BLOCK_SIZE);
	write32(fixture.disk[599] + 20, 320U);
	seal(fixture.disk[599], 2U, 599U, 16U);
	fixture.disk[301][4] ^= 1U;
	EXPECT(parse(partitions, 2U, &count) == EFI_SUCCESS && count == 1U);
	make_fixture();
	fixture.disk[256][4] ^= 1U;
	EXPECT(parse(partitions, 2U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	fixture.disk[301][188] ^= 1U;
	EXPECT(parse(partitions, 2U, &count) == EFI_CRC_ERROR);
	make_fixture();
	write32(fixture.disk[256] + 16, 257U * BLOCK_SIZE);
	seal(fixture.disk[256], 2U, 256U, 16U);
	EXPECT(parse(partitions, 2U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	write32(fixture.disk[301] + 188, 590U);
	seal(fixture.disk[301], 5U, 301U, 180U);
	EXPECT(parse(partitions, 2U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	write32(fixture.disk[302] + 212, 512U);
	seal(fixture.disk[302], 6U, 302U, 424U);
	EXPECT(parse(partitions, 2U, &count) == EFI_UNSUPPORTED);
	make_fixture();
	fixture.disk[405][12] ^= 1U;
	EXPECT(parse(partitions, 2U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	fixture.disk[303][0] = 0;
	EXPECT(parse(partitions, 2U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	EXPECT(parse(partitions, 0, &count) == EFI_BUFFER_TOO_SMALL);
	if (failures == 0)
		puts("partition UDF tests: PASS");
	return failures != 0;
}
