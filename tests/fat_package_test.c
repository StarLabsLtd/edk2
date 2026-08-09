/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint32_t size24(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16); }

int main(int argc, char **argv)
{
	static const uint8_t guid[16] = { 0xfe,0x78,0x15,0x96,0xb7,0xb6,0xc3,0x44,
		0xaf,0x35,0x6b,0xc7,0x05,0xcd,0x2b,0x1f };
	static const uint8_t order[3] = { 0x10, 0x15, 0x14 };
	FILE *file; uint8_t *data; long length; uint32_t offset, section_size;
	unsigned section = 0; int ui_ok = 0, version_ok = 0;
	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL) return 1;
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) != 0xe036L ||
	    fseek(file, 0, SEEK_SET) != 0) return 1;
	data = malloc((size_t)length); if (data == NULL) return 1;
	if (fread(data, 1U, (size_t)length, file) != (size_t)length || fclose(file) != 0 ||
	    __builtin_memcmp(data, guid, sizeof(guid)) != 0 || data[18] != 0x07U ||
	    size24(data + 20) != (uint32_t)length) return 1;
	for (offset = 24U; offset + 4U <= (uint32_t)length && section < 3U; ) {
		section_size = size24(data + offset);
		if (section_size < 4U || section_size > (uint32_t)length - offset ||
		    data[offset + 3U] != order[section]) return 1;
		if (section == 1U && section_size >= 12U && data[offset + 4U] == 'F' &&
		    data[offset + 6U] == 'a' && data[offset + 8U] == 't' && data[offset + 10U] == 0U)
			ui_ok = 1;
		if (section == 2U && section_size >= 14U && data[offset + 6U] == '1' &&
		    data[offset + 8U] == '.' && data[offset + 10U] == '0' && data[offset + 12U] == 0U)
			version_ok = 1;
		section++;
		offset = (offset + section_size + 3U) & ~3U;
	}
	while (offset < (uint32_t)length && data[offset] == 0xffU) offset++;
	free(data); return section == 3U && ui_ok && version_ok &&
		offset >= (uint32_t)length ? 0 : 1;
}
