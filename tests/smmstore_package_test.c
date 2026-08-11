/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t size24(const uint8_t *bytes)
{
	return bytes[0] | (uint32_t)bytes[1] << 8 |
		(uint32_t)bytes[2] << 16;
}

int main(int argc, char **argv)
{
	static const uint8_t guid[16] = { 0xca, 0x2f, 0x40, 0xa0, 0x25, 0x6b,
		0xea, 0x4c, 0xb7, 0xdd, 0xc0, 0x8f, 0x99, 0x71, 0x4b, 0x29 };
	static const uint8_t types[] = { 0x13, 0x10, 0x15, 0x14 };
	static const uint32_t sizes[] = { 0x16, 0x8004, 0x30, 0x0e };
	static const uint8_t depex[] = { 0x02, 0xf6, 0xf0, 0xa3, 0x13, 0x4a,
		0x26, 0xf0, 0x3e, 0xf2, 0xe0, 0xde, 0xc5, 0x12, 0x34, 0x2f,
		0x34, 0x08 };
	uint8_t *data;
	FILE *file;
	long length;
	size_t offset = 24U;
	unsigned int sum = 0U;

	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL)
		return 1;
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) != 0x8072L ||
	    fseek(file, 0, SEEK_SET) != 0 || (data = malloc(length)) == NULL ||
	    fread(data, 1, length, file) != (size_t)length) {
		fclose(file);
		return 1;
	}
	fclose(file);
	for (unsigned int index = 0; index < 24U; index++)
		sum += data[index];
	sum -= data[17] + data[23];
	if (memcmp(data, guid, sizeof(guid)) != 0 || (sum & 0xffU) != 0U ||
	    data[17] != 0xaaU || data[18] != 7U || size24(data + 20) != 0x8072U ||
	    data[23] != 0xf8U) {
		free(data);
		return 1;
	}
	for (unsigned int index = 0; index < sizeof(types); index++) {
		uint32_t size = size24(data + offset);
		if (size != sizes[index] || data[offset + 3U] != types[index] ||
		    size > (size_t)length - offset ||
		    (index == 0U && memcmp(data + offset + 4U, depex,
				     sizeof(depex)) != 0) ||
		    (index == 1U && (data[offset + 4U] != 'M' ||
				     data[offset + 5U] != 'Z'))) {
			free(data);
			return 1;
		}
		offset = (offset + size + 3U) & ~(size_t)3U;
		if (offset > (size_t)length)
			offset = length;
	}
	free(data);
	return offset == (size_t)length ? 0 : 1;
}
