/* SPDX-License-Identifier: GPL-2.0-only */

/* Deterministic, fail-closed firmware-volume inventory tool. */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FV_MIN_HEADER_SIZE 0x38U
#define FV_SIGNATURE_OFFSET 0x28U
#define FV_LENGTH_OFFSET 0x20U
#define FV_HEADER_LENGTH_OFFSET 0x30U
#define FFS_HEADER_SIZE 0x18U
#define FFS_LARGE_HEADER_SIZE 0x20U
#define FFS_ATTRIB_LARGE_FILE 0x01U
#define SECTION_HEADER_SIZE 4U
#define SECTION_LARGE_HEADER_SIZE 8U
#define SECTION_USER_INTERFACE 0x15U
#define SECTION_PE32 0x10U

static void fail(const char *message)
{
	fprintf(stderr, "cdk2-fvinfo: %s\n", message);
	exit(EXIT_FAILURE);
}

static uint16_t get16(const uint8_t *data)
{
	return (uint16_t)(data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t get24(const uint8_t *data)
{
	return (uint32_t)(data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16));
}

static uint32_t get32(const uint8_t *data)
{
	return (uint32_t)(data[0] | ((uint32_t)data[1] << 8) |
			  ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24));
}

static uint64_t get64(const uint8_t *data)
{
	return (uint64_t)get32(data) | ((uint64_t)get32(data + 4) << 32);
}

static size_t align_up(size_t value, size_t alignment)
{
	if (value > SIZE_MAX - (alignment - 1))
		fail("offset overflow");
	return (value + alignment - 1) & ~(alignment - 1);
}

static bool all_byte(const uint8_t *data, size_t size, uint8_t value)
{
	size_t index;

	for (index = 0; index < size; index++) {
		if (data[index] != value)
			return false;
	}
	return true;
}

static void format_guid(char output[37], const uint8_t *guid)
{
	snprintf(output, 37,
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
		 "%02x%02x%02x%02x%02x%02x",
		 guid[3], guid[2], guid[1], guid[0], guid[5], guid[4],
		 guid[7], guid[6], guid[8], guid[9], guid[10], guid[11],
		 guid[12], guid[13], guid[14], guid[15]);
}

static char *read_file(const char *path, size_t *size_out)
{
	FILE *file;
	long length;
	char *data;

	file = fopen(path, "rb");
	if (file == NULL)
		fail(strerror(errno));
	if ((fseek(file, 0, SEEK_END) != 0) || ((length = ftell(file)) < 0) ||
	    (fseek(file, 0, SEEK_SET) != 0))
		fail("cannot determine input size");
	if ((uintmax_t)length > SIZE_MAX)
		fail("input is too large");
	data = malloc(length == 0 ? 1 : (size_t)length);
	if (data == NULL)
		fail("out of memory");
	if (fread(data, 1, (size_t)length, file) != (size_t)length)
		fail("cannot read input");
	if (fclose(file) != 0)
		fail("cannot close input");
	*size_out = (size_t)length;
	return data;
}

static void print_utf16_name(const uint8_t *data, size_t size)
{
	size_t offset;
	uint16_t codepoint;

	for (offset = 0; offset + 1 < size; offset += 2) {
		codepoint = get16(data + offset);
		if (codepoint == 0)
			return;
		if ((codepoint >= 0x20) && (codepoint <= 0x7e) &&
		    (codepoint != '\\') && (codepoint != '\t'))
			putchar((int)codepoint);
		else
			printf("\\u%04x", codepoint);
	}
	if ((size & 1) != 0)
		fail("UI section has an odd byte count");
}

static void find_ui_name(const uint8_t *data, size_t size)
{
	size_t offset = 0;
	size_t header_size;
	uint32_t section_size;

	while (offset < size) {
		if (size - offset < SECTION_HEADER_SIZE)
			fail("truncated section header");
		section_size = get24(data + offset);
		header_size = SECTION_HEADER_SIZE;
		if (section_size == 0xffffffU) {
			if (size - offset < SECTION_LARGE_HEADER_SIZE)
				fail("truncated extended section header");
			section_size = get32(data + offset + 4);
			header_size = SECTION_LARGE_HEADER_SIZE;
		}
		if ((section_size < header_size) || (section_size > size - offset))
			fail("section extends outside firmware file");
		if (data[offset + 3] == SECTION_USER_INTERFACE) {
			print_utf16_name(data + offset + header_size,
					 section_size - header_size);
			return;
		}
		offset = align_up(offset + section_size, 4);
		if (offset > size)
			fail("section alignment extends outside firmware file");
	}
}

static void inventory(const uint8_t *image, size_t image_size)
{
	uint64_t fv_length64;
	size_t fv_length;
	size_t header_length;
	size_t offset;
	size_t file_size;
	size_t file_header_size;
	uint32_t size24;
	char guid[37];

	if (image_size < FV_MIN_HEADER_SIZE)
		fail("truncated firmware-volume header");
	if (memcmp(image + FV_SIGNATURE_OFFSET, "_FVH", 4) != 0)
		fail("invalid firmware-volume signature");
	fv_length64 = get64(image + FV_LENGTH_OFFSET);
	if ((fv_length64 < FV_MIN_HEADER_SIZE) || (fv_length64 > image_size) ||
	    (fv_length64 > SIZE_MAX))
		fail("invalid firmware-volume length");
	fv_length = (size_t)fv_length64;
	header_length = get16(image + FV_HEADER_LENGTH_OFFSET);
	if ((header_length < FV_MIN_HEADER_SIZE) || (header_length > fv_length))
		fail("invalid firmware-volume header length");
	offset = align_up(header_length, 8);
	puts("guid\toffset\tsize\ttype\tui_name");
	while (offset < fv_length) {
		if (all_byte(image + offset, fv_length - offset, 0xff))
			break;
		if (fv_length - offset < FFS_HEADER_SIZE)
			fail("truncated firmware-file header");
		size24 = get24(image + offset + 20);
		file_header_size = FFS_HEADER_SIZE;
		if ((image[offset + 19] & FFS_ATTRIB_LARGE_FILE) != 0) {
			if ((size24 != 0) || (fv_length - offset < FFS_LARGE_HEADER_SIZE))
				fail("invalid large firmware-file header");
			if (get64(image + offset + 24) > SIZE_MAX)
				fail("firmware file is too large");
			file_size = (size_t)get64(image + offset + 24);
			file_header_size = FFS_LARGE_HEADER_SIZE;
		} else {
			file_size = size24;
		}
		if ((file_size < file_header_size) || (file_size > fv_length - offset))
			fail("firmware file extends outside firmware volume");
		format_guid(guid, image + offset);
		printf("%s\t0x%08zx\t0x%08zx\t0x%02x\t", guid, offset,
		       file_size, image[offset + 18]);
		if (image[offset + 18] != 0xf0)
			find_ui_name(image + offset + file_header_size,
				     file_size - file_header_size);
		putchar('\n');
		offset = align_up(offset + file_size, 8);
		if (offset > fv_length)
			fail("firmware-file alignment extends outside volume");
	}
}

int main(int argc, char **argv)
{
	char *image;
	size_t image_size;

	if (argc != 2) {
		fprintf(stderr, "usage: cdk2-fvinfo FIRMWARE_VOLUME\n");
		return EXIT_FAILURE;
	}
	image = read_file(argv[1], &image_size);
	inventory((const uint8_t *)image, image_size);
	free(image);
	return EXIT_SUCCESS;
}
