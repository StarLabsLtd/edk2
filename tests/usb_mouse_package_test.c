/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t size24(const uint8_t *bytes)
{ return bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16; }

int main(int argc, char **argv)
{
	static const uint8_t guid[16] = { 0xaa, 0x62, 0x2e, 0x2d, 0xcf, 0x9e,
		0xb7, 0x43, 0x82, 0x19, 0x94, 0xe7, 0xfc, 0x71, 0x3d, 0xfe };
	static const uint8_t types[] = { 0x10, 0x15, 0x14 };
	static const uint8_t ui[] = { 'U', 0, 's', 0, 'b', 0, 'M', 0, 'o', 0,
		'u', 0, 's', 0, 'e', 0, 'D', 0, 'x', 0, 'e', 0, 0, 0 };
	static const uint8_t version[] = { '1', 0, '.', 0, '0', 0, 0, 0 };
	uint8_t *data;
	FILE *file;
	long length;
	size_t offset = 24U;
	unsigned int sum = 0U;

	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL)
		return 1;
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) != 0x7046L ||
	    fseek(file, 0, SEEK_SET) != 0 || (data = malloc(length)) == NULL ||
	    fread(data, 1, length, file) != (size_t)length) {
		fclose(file);
		return 1;
	}
	fclose(file);
	for (unsigned int index = 0U; index < 24U; index++)
		sum += data[index];
	sum -= data[17] + data[23];
	if (memcmp(data, guid, sizeof(guid)) != 0 || (sum & 0xffU) != 0U ||
	    data[17] != 0xaaU || data[18] != 7U || size24(data + 20) != 0x7046U ||
	    data[23] != 0xf8U) {
		free(data);
		return 1;
	}
	for (unsigned int index = 0U; index < sizeof(types); index++) {
		uint32_t section_size = size24(data + offset);
		size_t end;

		if (offset + 4U > (size_t)length || section_size < 4U ||
		    data[offset + 3U] != types[index] ||
		    section_size > (size_t)length - offset) {
			free(data);
			return 1;
		}
		end = offset + section_size;
		if ((index == 0U && (section_size != 0x7004U ||
		    data[offset + 4U] != 'M' || data[offset + 5U] != 'Z')) ||
		    (index == 1U && (section_size != 0x1cU ||
		    memcmp(data + offset + 4U, ui, sizeof(ui)) != 0)) ||
		    (index == 2U && (section_size != 0x0eU ||
		    memcmp(data + offset + 6U, version, sizeof(version)) != 0))) {
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
