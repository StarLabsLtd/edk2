/* SPDX-License-Identifier: GPL-2.0-only */

/* Build one deterministic DXE-driver FFS from an X64 PE/COFF image. */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FFS_HEADER_SIZE 24U
#define FFS_TYPE_DXE_DRIVER 0x07U
#define FFS_FIXED_CHECKSUM 0xaaU
#define FFS_STATE_VALID 0xf8U
#define SECTION_DXE_DEPEX 0x13U
#define SECTION_VERSION 0x14U
#define SECTION_USER_INTERFACE 0x15U
#define SECTION_PE32 0x10U

static void fail(const char *message)
{
	fprintf(stderr, "cdk2-ffsbuild: %s\n", message);
	exit(EXIT_FAILURE);
}

static uint8_t checksum8(const uint8_t *data, size_t size)
{
	uint8_t sum = 0;
	size_t index;

	for (index = 0; index < size; index++)
		sum = (uint8_t)(sum + data[index]);
	return (uint8_t)(0U - sum);
}

static void put24(uint8_t *data, size_t value)
{
	if (value > 0xffffffU)
		fail("24-bit size overflow");
	data[0] = (uint8_t)value;
	data[1] = (uint8_t)(value >> 8);
	data[2] = (uint8_t)(value >> 16);
}

static size_t align4(size_t value)
{
	return (value + 3U) & ~3U;
}

static uint8_t hex_digit(char character)
{
	if (character >= '0' && character <= '9')
		return (uint8_t)(character - '0');
	if (character >= 'a' && character <= 'f')
		return (uint8_t)(character - 'a' + 10);
	if (character >= 'A' && character <= 'F')
		return (uint8_t)(character - 'A' + 10);
	fail("invalid GUID");
	return 0;
}

static uint8_t hex_byte(const char *text)
{
	return (uint8_t)((hex_digit(text[0]) << 4) | hex_digit(text[1]));
}

static void parse_guid(const char *text, uint8_t guid[16])
{
	static const uint8_t order[16] = { 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 };
	char compact[33];
	size_t source = 0;
	size_t target = 0;
	size_t index;

	while (text[source] != '\0') {
		if (text[source] != '-') {
			if (target >= 32)
				fail("invalid GUID length");
			compact[target++] = text[source];
		}
		source++;
	}
	if (target != 32)
		fail("invalid GUID length");
	compact[32] = '\0';
	for (index = 0; index < 16; index++)
		guid[order[index]] = hex_byte(compact + index * 2);
}

static uint8_t *read_file(const char *path, size_t *size)
{
	FILE *file = fopen(path, "rb");
	long length;
	uint8_t *data;

	if (file == NULL) {
		fprintf(stderr, "cdk2-ffsbuild: cannot open %s: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
	    fseek(file, 0, SEEK_SET) != 0)
		fail("cannot size input PE");
	data = malloc((size_t)length == 0 ? 1 : (size_t)length);
	if (data == NULL || fread(data, 1, (size_t)length, file) != (size_t)length)
		fail("cannot read input PE");
	if (fclose(file) != 0)
		fail("cannot close input PE");
	*size = (size_t)length;
	return data;
}

static size_t add_utf16_section(uint8_t *output, size_t offset, uint8_t type, const char *text)
{
	size_t length = strlen(text);
	size_t section_size = 4U + (length + 1U) * 2U;
	size_t index;

	put24(output + offset, section_size);
	output[offset + 3] = type;
	for (index = 0; index < length; index++)
		output[offset + 4 + index * 2] = (uint8_t)text[index];
	return align4(offset + section_size);
}

int main(int argc, char **argv)
{
	uint8_t guid[16];
	uint8_t *pe;
	uint8_t *output;
	size_t pe_size;
	size_t output_size;
	size_t pe_section_size;
	size_t offset;
	FILE *file;

	if (argc != 7) {
		fprintf(stderr, "usage: %s GUID UI VERSION SIZE PE OUTPUT\n", argv[0]);
		return EXIT_FAILURE;
	}
	parse_guid(argv[1], guid);
	output_size = (size_t)strtoull(argv[4], NULL, 0);
	if (output_size < FFS_HEADER_SIZE + 32U || output_size > 0xffffffU)
		fail("invalid output size");
	pe = read_file(argv[5], &pe_size);
	if (pe_size < 2 || pe[0] != 'M' || pe[1] != 'Z')
		fail("input is not a PE/COFF image");
	output = calloc(1, output_size);
	if (output == NULL)
		fail("out of memory");
	memcpy(output, guid, sizeof(guid));
	output[16] = 0;
	output[17] = 0;
	output[18] = FFS_TYPE_DXE_DRIVER;
	put24(output + 20, output_size);
	output[23] = 0;

	offset = FFS_HEADER_SIZE;
	put24(output + offset, 6);
	output[offset + 3] = SECTION_DXE_DEPEX;
	output[offset + 4] = 0x06; /* TRUE */
	output[offset + 5] = 0x08; /* END */
	offset = align4(offset + 6);
	pe_section_size = output_size - offset;
	/* Reserve the fixed UI and version sections at the tail. */
	pe_section_size -= align4(4U + (strlen(argv[2]) + 1U) * 2U);
	pe_section_size -= 4U + (strlen(argv[3]) + 1U) * 2U;
	if (pe_size > pe_section_size - 4U)
		fail("PE does not fit requested FFS size");
	put24(output + offset, pe_section_size);
	output[offset + 3] = SECTION_PE32;
	memcpy(output + offset + 4, pe, pe_size);
	offset = align4(offset + pe_section_size);
	offset = add_utf16_section(output, offset, SECTION_USER_INTERFACE, argv[2]);
	offset = add_utf16_section(output, offset, SECTION_VERSION, argv[3]);
	if (offset != align4(output_size))
		fail("section layout does not match requested FFS size");
	output[16] = checksum8(output, FFS_HEADER_SIZE);
	output[17] = FFS_FIXED_CHECKSUM;
	output[23] = FFS_STATE_VALID;

	file = fopen(argv[6], "wb");
	if (file == NULL || fwrite(output, 1, output_size, file) != output_size || fclose(file) != 0)
		fail("cannot write output FFS");
	free(output);
	free(pe);
	return EXIT_SUCCESS;
}
