/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t size24(const uint8_t *p)
{ return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16; }

int main(int argc, char **argv)
{
	static const uint8_t guid[16] = { 0xb4, 0x3c, 0x52, 0x5e, 0x97, 0xd3,
		0x86, 0x49, 0x87, 0xbd, 0xa6, 0xdd, 0x8b, 0x22, 0xf4, 0x55 };
	static const uint8_t types[] = { 0x10, 0x15, 0x14 };
	uint8_t *data;
	FILE *file;
	long length;
	size_t offset = 24;
	unsigned int sum = 0;

	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL)
		return 1;
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) != 0xe056 ||
	    fseek(file, 0, SEEK_SET) != 0 ||
	    (data = malloc((size_t)length)) == NULL ||
	    fread(data, 1, (size_t)length, file) != (size_t)length) {
		fclose(file); return 1;
	}
	fclose(file);
	for (unsigned int index = 0; index < 24; index++)
		sum += data[index];
	sum -= data[17] + data[23];
	if (memcmp(data, guid, sizeof(guid)) != 0 || (sum & 0xffU) != 0U ||
	    data[17] != 0xaa || data[18] != 7 || size24(data + 20) != 0xe056 ||
	    data[23] != 0xf8) {
		free(data); return 1;
	}
	for (unsigned int index = 0; index < sizeof(types); index++) {
		uint32_t section_size; size_t end;
		if (offset + 4 > (size_t)length ||
		    (section_size = size24(data + offset)) < 4U ||
		    data[offset + 3] != types[index] ||
		    section_size > (size_t)length - offset) {
			free(data); return 1;
		}
		end = offset + section_size;
		if (index == 0U && (section_size != 0xe004U ||
		    data[offset + 4] != 'M' || data[offset + 5] != 'Z')) {
			free(data); return 1;
		}
		if (index == 1U && (section_size != 0x2cU ||
		    memcmp(data + offset + 4, "A\0t\0a\0A\0t\0a\0p\0i\0P\0a\0s\0s\0T\0h\0r\0u\0D\0x\0e\0\0\0",
			40U) != 0)) {
			free(data); return 1;
		}
		if (index == 2U && (section_size != 0x0eU ||
		    memcmp(data + offset + 4, "\0\x00\x31\0.\0\x30\0\0\0", 10U) != 0)) {
			free(data); return 1;
		}
		offset = (end + 3U) & ~(size_t)3U;
		if (offset > (size_t)length)
			offset = end;
	}
	free(data);
	return offset == (size_t)length ? 0 : 1;
}
