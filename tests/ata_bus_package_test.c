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
	static const uint8_t guid[16] = { 0x5a, 0x14, 0xdf, 0x19, 0xd4, 0xb1,
		0x3f, 0x45, 0x85, 0x07, 0x38, 0x81, 0x66, 0x76, 0xd7, 0xf6 };
	static const uint8_t types[] = { 0x10, 0x15, 0x14 };
	uint8_t *data, *pe;
	FILE *file;
	long length, pe_length;
	size_t offset = 24;
	unsigned int sum = 0;

	if (argc != 3 || (file = fopen(argv[1], "rb")) == NULL)
		return 1;
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) != 0x9042 ||
	    fseek(file, 0, SEEK_SET) != 0 || (data = malloc((size_t)length)) == NULL ||
	    fread(data, 1, (size_t)length, file) != (size_t)length) {
		fclose(file);
		return 1;
	}
	fclose(file);
	if ((file = fopen(argv[2], "rb")) == NULL || fseek(file, 0, SEEK_END) != 0 ||
	    (pe_length = ftell(file)) <= 0 || pe_length > 0x9000 ||
	    fseek(file, 0, SEEK_SET) != 0 || (pe = malloc((size_t)pe_length)) == NULL ||
	    fread(pe, 1, (size_t)pe_length, file) != (size_t)pe_length) {
		free(data);
		if (file != NULL)
			fclose(file);
		return 1;
	}
	fclose(file);
	for (unsigned int index = 0; index < 24; index++)
		sum += data[index];
	sum -= data[17] + data[23];
	if (memcmp(data, guid, 16) != 0 || (sum & 0xffU) != 0U || data[17] != 0xaa ||
	    data[18] != 7 || size24(data + 20) != 0x9042 || data[23] != 0xf8)
		goto bad;
	for (unsigned int index = 0; index < sizeof(types); index++) {
		uint32_t section_size;
		size_t end;
		if (offset + 4 > (size_t)length || (section_size = size24(data + offset)) < 4 ||
		    data[offset + 3] != types[index] || section_size > (size_t)length - offset)
			goto bad;
		end = offset + section_size;
		if (index == 0 && (section_size != 0x9004 || data[offset + 4] != 'M' ||
		    data[offset + 5] != 'Z' || memcmp(data + offset + 4, pe,
		    (size_t)pe_length) != 0))
			goto bad;
		if (index == 0)
			for (size_t pad = (size_t)pe_length; pad < 0x9000; pad++)
				if (data[offset + 4 + pad] != 0x00)
					goto bad;
		if (index == 1 && (section_size != 0x18 || memcmp(data + offset + 4,
		    "A\0t\0a\0B\0u\0s\0D\0x\0e\0\0\0", 20) != 0))
			goto bad;
		if (index == 2 && (section_size != 0x0e || memcmp(data + offset + 4,
		    "\0\x00\x31\0.\0\x30\0\0\0", 10) != 0))
			goto bad;
		offset = (end + 3U) & ~(size_t)3U;
		if (offset > (size_t)length)
			offset = end;
	}
	free(pe);
	free(data);
	return offset == (size_t)length ? 0 : 1;
bad:
	free(pe);
	free(data);
	return 1;
}
