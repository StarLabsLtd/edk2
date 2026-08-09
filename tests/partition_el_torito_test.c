/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/partition.h>

#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 512U
#define DISK_BLOCKS 4000U
#define ISO_BLOCKS 4U

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

static UINT8 *iso_sector(UINT32 sector)
{
	return fixture.disk[sector * ISO_BLOCKS];
}

static void seal_catalog(UINT8 *catalog)
{
	UINT32 sum = 0;
	UINTN index;

	write16(catalog + 28, 0);
	for (index = 0; index < 32U; index += 2U)
		sum += (UINT16)catalog[index] | (UINT16)catalog[index + 1U] << 8;
	write16(catalog + 28, (UINT16)(0U - sum));
}

static void make_fixture(void)
{
	UINT8 *descriptor;
	UINT8 *catalog;

	memset(&fixture, 0, sizeof(fixture));
	descriptor = iso_sector(16U);
	descriptor[0] = 0;
	memcpy(descriptor + 1, "CD001", 5);
	descriptor[6] = 1U;
	memcpy(descriptor + 7, "EL TORITO SPECIFICATION", 23);
	write32(descriptor + 71, 20U);
	catalog = iso_sector(20U);
	catalog[0] = 1U;
	catalog[1] = 0U;
	catalog[30] = 0x55U;
	catalog[31] = 0xaaU;
	catalog[32] = 0x88U;
	write16(catalog + 32 + 6, 4U);
	write32(catalog + 32 + 8, 30U);
	catalog[64] = 0x91U;
	catalog[65] = 0xefU;
	catalog[66] = 1U;
	catalog[96] = 0x88U;
	catalog[97] = 1U;
	write16(catalog + 96 + 6, 1U);
	write32(catalog + 96 + 8, 40U);
	seal_catalog(catalog);
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
	UINT8 sector[2048];

	return cdk2_partition_parse_el_torito(&media, sector, sizeof(sector),
		partitions, capacity, count);
}

static EFI_STATUS read_optical(void *context, UINT64 lba, UINTN blocks,
	void *buffer)
{
	struct fixture *disk = context;

	if (lba >= DISK_BLOCKS / ISO_BLOCKS || blocks > DISK_BLOCKS / ISO_BLOCKS - lba)
		return EFI_DEVICE_ERROR;
	memcpy(buffer, &disk->disk[lba * ISO_BLOCKS], blocks * 2048U);
	return EFI_SUCCESS;
}

static EFI_STATUS parse_optical(struct cdk2_partition *partitions, UINTN *count)
{
	struct cdk2_partition_media media = {
		.context = &fixture, .read = read_optical, .block_size = 2048U,
		.last_block = DISK_BLOCKS / ISO_BLOCKS - 1U,
	};
	UINT8 sector[2048];

	return cdk2_partition_parse_el_torito(&media, sector, sizeof(sector),
		partitions, 3U, count);
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
	struct cdk2_partition partitions[3];
	UINT8 *catalog;
	UINTN count;
	int failures = 0;

	make_fixture();
	EXPECT(parse(partitions, 3U, &count) == EFI_SUCCESS && count == 2U);
	EXPECT(partitions[0].start_lba == 120U && partitions[0].end_lba == 123U);
	EXPECT(partitions[0].boot_entry == 0 && partitions[0].attributes == 0);
	EXPECT(partitions[1].start_lba == 160U && partitions[1].end_lba == 2559U);
	EXPECT(partitions[1].boot_entry == 1 && partitions[1].attributes == 1U);
	EXPECT(parse_optical(partitions, &count) == EFI_SUCCESS && count == 2U &&
		partitions[0].start_lba == 30U && partitions[0].end_lba == 33U);
	make_fixture();
	write16(iso_sector(20U) + 32 + 6, 0U);
	EXPECT(parse(partitions, 3U, &count) == EFI_SUCCESS &&
		partitions[0].start_lba == 120U && partitions[0].end_lba == DISK_BLOCKS - 1U);

	make_fixture();
	catalog = iso_sector(20U);
	catalog[64] = 0x90U;
	catalog[128] = 0x44U;
	catalog[160] = 0x91U;
	catalog[161] = 0xefU;
	write16(catalog + 160 + 2, 1U);
	catalog[192] = 0x88U;
	write16(catalog + 192 + 6, 1U);
	write32(catalog + 192 + 8, 50U);
	EXPECT(parse(partitions, 3U, &count) == EFI_SUCCESS && count == 3U &&
		partitions[2].start_lba == 200U);

	make_fixture();
	catalog = iso_sector(20U);
	write16(catalog + 64 + 2, 0x0101U);
	catalog[97] = 0U;
	catalog[128] = 0x88U;
	write16(catalog + 128 + 6, 1U);
	write32(catalog + 128 + 8, 50U);
	catalog[160] = 0x88U;
	write16(catalog + 160 + 6, 1U);
	write32(catalog + 160 + 8, 60U);
	EXPECT(parse(partitions, 3U, &count) == EFI_BUFFER_TOO_SMALL);
	make_fixture();
	catalog = iso_sector(20U);
	write16(catalog + 64 + 2, 65U);
	memset(catalog + 96, 0, 32U);
	catalog = iso_sector(21U);
	catalog[32] = 0x88U;
	write16(catalog + 32 + 6, 1U);
	write32(catalog + 32 + 8, 50U);
	EXPECT(parse(partitions, 3U, &count) == EFI_SUCCESS && count == 2U &&
		partitions[1].start_lba == 200U);

	make_fixture();
	iso_sector(16U)[1] = 'X';
	EXPECT(parse(partitions, 3U, &count) == EFI_NOT_FOUND);
	make_fixture();
	catalog = iso_sector(20U);
	catalog[12] ^= 1U;
	EXPECT(parse(partitions, 3U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	catalog = iso_sector(20U);
	catalog[1] = 3U;
	seal_catalog(catalog);
	EXPECT(parse(partitions, 3U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	catalog = iso_sector(20U);
	write32(catalog + 96 + 8, 30U);
	EXPECT(parse(partitions, 3U, &count) == EFI_SUCCESS && count == 2U &&
		partitions[0].start_lba == partitions[1].start_lba);
	make_fixture();
	catalog = iso_sector(20U);
	write32(catalog + 32 + 8, 2000U);
	EXPECT(parse(partitions, 3U, &count) == EFI_COMPROMISED_DATA);
	make_fixture();
	EXPECT(parse(partitions, 1U, &count) == EFI_BUFFER_TOO_SMALL);
	if (failures == 0)
		puts("partition El Torito tests: PASS");
	return failures != 0;
}
