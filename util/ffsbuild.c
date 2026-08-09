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
#define SECTION_MM_DEPEX 0x1cU
#define SECTION_VERSION 0x14U
#define SECTION_USER_INTERFACE 0x15U
#define SECTION_PE32 0x10U
#define SECTION_RAW 0x19U

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

static uint32_t get24(const uint8_t *data)
{
	return data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16;
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

static uint8_t *read_file(const char *path, size_t *size, const char *kind)
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
		fail(kind);
	data = malloc((size_t)length == 0 ? 1 : (size_t)length);
	if (data == NULL || fread(data, 1, (size_t)length, file) != (size_t)length)
		fail(kind);
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

static size_t add_version_section(uint8_t *output, size_t offset, const char *text)
{
	size_t length = strlen(text);
	size_t section_size = 6U + (length + 1U) * 2U;
	size_t index;

	put24(output + offset, section_size);
	output[offset + 3] = SECTION_VERSION;
	/* Build number zero, followed by the UTF-16 version string. */
	for (index = 0; index < length; index++)
		output[offset + 6 + index * 2] = (uint8_t)text[index];
	return align4(offset + section_size);
}

int main(int argc, char **argv)
{
	uint8_t guid[16];
	uint8_t *pe;
	uint8_t *depex = NULL;
	uint8_t *raw = NULL;
	uint8_t *output;
	size_t pe_size;
	size_t depex_size = 6;
	size_t raw_size = 0;
	size_t output_size;
	size_t pe_section_size;
	size_t offset;
	FILE *file;
	uint8_t file_type = FFS_TYPE_DXE_DRIVER;
	uint8_t depex_type = SECTION_DXE_DEPEX;
	int argument;

	if (argc < 7) {
		fprintf(stderr, "usage: %s GUID UI VERSION SIZE PE OUTPUT [DEPEX|-] "
			"[--file-type TYPE] [--depex-type TYPE] [--raw FILE]\n", argv[0]);
		return EXIT_FAILURE;
	}
	argument = 7;
	if (argument < argc && strncmp(argv[argument], "--", 2) != 0)
		argument++;
	while (argument < argc) {
		char *end;
		unsigned long value;

		if (argument + 1 >= argc)
			fail("missing option value");
		if (strcmp(argv[argument], "--raw") == 0) {
			raw = read_file(argv[argument + 1], &raw_size,
				"cannot read RAW section input");
			argument += 2;
			continue;
		}
		value = strtoul(argv[argument + 1], &end, 0);
		if (*end != '\0' || value > 0xffU)
			fail("invalid option value");
		if (strcmp(argv[argument], "--file-type") == 0)
			file_type = (uint8_t)value;
		else if (strcmp(argv[argument], "--depex-type") == 0)
			depex_type = (uint8_t)value;
		else
			fail("unknown option");
		argument += 2;
	}
	if (file_type != FFS_TYPE_DXE_DRIVER && file_type != 0x0aU)
		fail("unsupported FFS file type");
	if (depex_type != SECTION_DXE_DEPEX && depex_type != SECTION_MM_DEPEX)
		fail("unsupported DEPEX section type");
	if ((file_type == 0x0aU) != (depex_type == SECTION_MM_DEPEX))
		fail("FFS file type and DEPEX section type do not match");
	parse_guid(argv[1], guid);
	output_size = (size_t)strtoull(argv[4], NULL, 0);
	if (output_size < FFS_HEADER_SIZE + 32U || output_size > 0xffffffU)
		fail("invalid output size");
	pe = read_file(argv[5], &pe_size, "cannot read input PE");
	if (pe_size < 2 || pe[0] != 'M' || pe[1] != 'Z')
		fail("input is not a PE/COFF image");
	if (argc >= 8 && strncmp(argv[7], "--", 2) != 0 && strcmp(argv[7], "-") == 0) {
		depex_size = 0;
	} else if (argc >= 8 && strncmp(argv[7], "--", 2) != 0) {
		depex = read_file(argv[7], &depex_size, "cannot read DEPEX section");
		if (depex_size < 4 || get24(depex) != depex_size ||
		    depex[3] != depex_type)
			fail("input is not a complete expected DEPEX section");
	}
	output = calloc(1, output_size);
	if (output == NULL)
		fail("out of memory");
	memcpy(output, guid, sizeof(guid));
	output[16] = 0;
	output[17] = 0;
	output[18] = file_type;
	put24(output + 20, output_size);
	output[23] = 0;

	offset = FFS_HEADER_SIZE;
	if (raw != NULL) {
		size_t next, required;
		size_t ui_size = align4(4U + (strlen(argv[2]) + 1U) * 2U);
		size_t version_size = align4(6U + (strlen(argv[3]) + 1U) * 2U);

		if (raw_size > 0xffffffU - 4U)
			fail("RAW section is too large");
		if (raw_size + 4U > output_size - offset)
			fail("RAW section does not fit requested FFS size");
		next = align4(offset + raw_size + 4U);
		required = align4(next + depex_size);
		if (required > output_size || pe_size > output_size - required ||
		    output_size - required - pe_size < 4U)
			fail("RAW section leaves no room for following sections");
		required = align4(required + 4U + pe_size);
		if (ui_size > output_size - required ||
		    version_size > output_size - required - ui_size)
			fail("RAW section leaves no room for following sections");
		put24(output + offset, raw_size + 4U);
		output[offset + 3] = SECTION_RAW;
		memcpy(output + offset + 4U, raw, raw_size);
		offset = align4(offset + raw_size + 4U);
	}
	if (depex_size == 0) {
		/* Some UEFI drivers are deliberately admitted without a DEPEX. */
	} else if (depex != NULL) {
		memcpy(output + offset, depex, depex_size);
	} else {
		put24(output + offset, 6);
		output[offset + 3] = depex_type;
		output[offset + 4] = 0x06; /* TRUE */
		output[offset + 5] = 0x08; /* END */
	}
	offset = align4(offset + depex_size);
	pe_section_size = output_size - offset;
	/* Reserve the fixed UI and version sections at the tail. */
	pe_section_size -= align4(4U + (strlen(argv[2]) + 1U) * 2U);
	pe_section_size -= 6U + (strlen(argv[3]) + 1U) * 2U;
	if (pe_size > pe_section_size - 4U)
		fail("PE does not fit requested FFS size");
	put24(output + offset, pe_section_size);
	output[offset + 3] = SECTION_PE32;
	memcpy(output + offset + 4, pe, pe_size);
	offset = align4(offset + pe_section_size);
	offset = add_utf16_section(output, offset, SECTION_USER_INTERFACE, argv[2]);
	offset = add_version_section(output, offset, argv[3]);
	if (offset != align4(output_size))
		fail("section layout does not match requested FFS size");
	output[16] = checksum8(output, FFS_HEADER_SIZE);
	output[17] = FFS_FIXED_CHECKSUM;
	output[23] = FFS_STATE_VALID;

	file = fopen(argv[6], "wb");
	if (file == NULL || fwrite(output, 1, output_size, file) != output_size || fclose(file) != 0)
		fail("cannot write output FFS");
	free(output);
	free(raw);
	free(depex);
	free(pe);
	return EXIT_SUCCESS;
}
