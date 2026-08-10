/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t size24(const uint8_t *bytes)
{
	return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 |
		(uint32_t)bytes[2] << 16;
}

int main(int argc, char **argv)
{
	static const uint8_t guid[16] = { 0xc4, 0xcc, 0x67, 0x01, 0xf7, 0xd0,
		0x21, 0x4f, 0xa3, 0xef, 0x9e, 0x64, 0xb7, 0xcd, 0xce, 0x8b };
	static const uint8_t types[] = { 0x10, 0x15, 0x14 };
	uint8_t *data;
	FILE *file;
	long length;
	size_t offset = 24;
	unsigned int sum = 0;
	unsigned int index;

	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL)
		return 1;
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) != 0x703e ||
	    fseek(file, 0, SEEK_SET) != 0 ||
	    (data = malloc((size_t)length)) == NULL ||
	    fread(data, 1, (size_t)length, file) != (size_t)length) {
		fclose(file);
		return 1;
	}
	fclose(file);
	for (index = 0; index < 24; index++)
		sum += data[index];
	sum -= data[17] + data[23];
	if (memcmp(data, guid, sizeof(guid)) != 0 || (sum & 0xffU) != 0U ||
	    data[17] != 0xaa || data[18] != 7 || size24(data + 20) != 0x703e ||
	    data[23] != 0xf8) {
		free(data);
		return 1;
	}
	for (index = 0; index < sizeof(types); index++) {
		uint32_t section_size;
		size_t end;

		if (offset + 4 > (size_t)length ||
		    (section_size = size24(data + offset)) < 4 ||
		    data[offset + 3] != types[index] ||
		    section_size > (size_t)length - offset) {
			free(data);
			return 1;
		}
		end = offset + section_size;
		if (index == 0 && (section_size != 0x7004 || data[offset + 4] != 'M' ||
		    data[offset + 5] != 'Z')) {
			free(data);
			return 1;
		}
		offset = (end + 3U) & ~(size_t)3U;
		if (offset > (size_t)length)
			offset = end;
	}
	free(data);
	return offset == (size_t)length ? 0 : 1;
}
