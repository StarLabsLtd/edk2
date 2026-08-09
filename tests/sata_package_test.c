/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t size24(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16;
}

int main(int argc, char **argv)
{
	static const uint8_t guid[16] = { 0xbb, 0x59, 0x0c, 0x82, 0x4c, 0x27,
		0xb2, 0x43, 0x83, 0xea, 0xda, 0xc6, 0x73, 0x03, 0x5a, 0x59 };
	static const uint8_t types[] = { 0x10, 0x15, 0x14 };
	uint8_t *data;
	FILE *file;
	long length;
	size_t offset = 24;
	unsigned int sum = 0;
	unsigned int index;

	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL)
		return 1;
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) != 0x604e ||
	    fseek(file, 0, SEEK_SET) != 0 ||
	    (data = malloc((size_t)length)) == NULL ||
	    fread(data, 1, (size_t)length, file) != (size_t)length) {
		fclose(file);
		return 1;
	}
	fclose(file);
	for (index = 0; index < 24; index++)
		sum += data[index];
	/* PI FFS header checksum excludes State and the fixed file checksum. */
	sum -= data[17] + data[23];
	if (memcmp(data, guid, sizeof(guid)) != 0 || (sum & 0xffU) != 0U ||
	    data[17] != 0xaa || data[18] != 7 || size24(data + 20) != 0x604e ||
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
		if (index == 0 && (section_size != 0x6004 || data[offset + 4] != 'M' ||
		    data[offset + 5] != 'Z')) {
			free(data);
			return 1;
		}
		offset = (end + 3U) & ~(size_t)3U;
		if (offset > (size_t)length)
			offset = end;
	}
	/* Exactly PE32, UI and VERSION: in particular, no DEPEX section. */
	free(data);
	return offset == (size_t)length ? 0 : 1;
}
