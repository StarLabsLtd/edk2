/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
	static const uint8_t guid[16] = { 0xbb, 0x59, 0x0c, 0x82, 0x4c, 0x27,
		0xb2, 0x43, 0x83, 0xea, 0xda, 0xc6, 0x73, 0x03, 0x5a, 0x59 };
	uint8_t header[28]; FILE *file; long size;
	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL) return 1;
	if (fread(header, 1, sizeof(header), file) != sizeof(header) ||
	    fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0) {
		fclose(file); return 1;
	}
	fclose(file);
	return size != 0x604e || memcmp(header, guid, sizeof(guid)) != 0 ||
		header[18] != 7 || header[20] != 0x4e || header[21] != 0x60 ||
		header[24] != 4 || header[25] != 0x60 || header[27] != 0x10;
}
