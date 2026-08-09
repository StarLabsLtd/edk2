/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/fat.h>
#include <uefi.h>
#include <stdio.h>
#include <string.h>

#define FAT_VOLUME_CORRUPTED EFIERR(10)

struct medium { uint8_t boot[512]; uint64_t size; uint64_t status; };

static void write16(uint8_t *data, uint16_t value)
{ data[0] = value; data[1] = value >> 8; }
static void write32(uint8_t *data, uint32_t value)
{ write16(data, value); write16(data + 2U, value >> 16); }
static uint64_t read_media(void *opaque, uint64_t offset, size_t size, void *buffer)
{
	struct medium *medium = opaque;
	if (medium->status != EFI_SUCCESS)
		return medium->status;
	if (offset != 0U || size != sizeof(medium->boot))
		return EFI_INVALID_PARAMETER;
	memcpy(buffer, medium->boot, size);
	return EFI_SUCCESS;
}
static void make_bpb(struct medium *medium, uint32_t sectors, uint16_t roots,
	uint16_t fat16, uint32_t fat32, uint8_t cluster)
{
	memset(medium, 0, sizeof(*medium));
	write16(medium->boot + 11U, 512U); medium->boot[13U] = cluster;
	write16(medium->boot + 14U, fat32 == 0U ? 1U : 32U);
	medium->boot[16U] = 2U; write16(medium->boot + 17U, roots);
	write32(medium->boot + 32U, sectors); write16(medium->boot + 22U, fat16);
	write32(medium->boot + 36U, fat32); write32(medium->boot + 44U, 2U);
	medium->boot[510U] = 0x55U; medium->boot[511U] = 0xaaU;
	medium->size = (uint64_t)sectors * 512U;
}
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "FAT test: %s\n", message); return !condition; }

int main(void)
{
	struct cdk2_fat_volume volume;
	struct medium medium;
	uint64_t offset;
	int failures = 0;

	make_bpb(&medium, 4096U, 224U, 9U, 0U, 1U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_SUCCESS && volume.fat_type == CDK2_FAT12,
		"valid FAT12 BPB was rejected");
	make_bpb(&medium, 65500U, 512U, 250U, 0U, 1U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_SUCCESS && volume.fat_type == CDK2_FAT16,
		"valid FAT16 BPB was rejected");
	make_bpb(&medium, 200000U, 0U, 0U, 1000U, 1U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_SUCCESS && volume.fat_type == CDK2_FAT32 &&
		cdk2_fat_cluster_offset(&volume, 2U, &offset) == EFI_SUCCESS &&
		offset == volume.data_offset, "valid FAT32 geometry was not mapped");
	medium.boot[510U] = 0U;
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_UNSUPPORTED, "missing boot signature was admitted");
	make_bpb(&medium, 200000U, 0U, 0U, 1000U, 3U);
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		EFI_UNSUPPORTED, "non-power-of-two cluster geometry was admitted");
	make_bpb(&medium, 200000U, 0U, 0U, 1000U, 1U); medium.size--;
	failures += expect(cdk2_fat_probe(&volume, read_media, &medium, medium.size) ==
		FAT_VOLUME_CORRUPTED, "truncated medium was admitted");
	return failures == 0 ? 0 : 1;
}
