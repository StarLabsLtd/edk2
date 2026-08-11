/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	FILE *file;
	uint8_t header[28];
	long size;
	static const uint8_t guid[16] = { 0xa8, 0x1c, 0x4e, 0x86, 0xeb, 0x85,
		0x63, 0x4d, 0x9d, 0xcc, 0x6e, 0x0f, 0xc9, 0x0f, 0xfd, 0x55 };

	if (argc != 2 || (file = fopen(argv[1], "rb")) == NULL)
		return 1;
	if (fread(header, 1, sizeof(header), file) != sizeof(header) ||
	    fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0) {
		fclose(file);
		return 1;
	}
	fclose(file);
	if (size != 0x6042 || __builtin_memcmp(header, guid, sizeof(guid)) != 0 ||
	    header[18] != 0x07 || header[20] != 0x42 || header[21] != 0x60 ||
	    header[22] != 0 || header[24] != 0x04 || header[25] != 0x60 ||
	    header[26] != 0 || header[27] != 0x10) {
		fprintf(stderr, "sio package: admitted envelope mismatch\n");
		return 1;
	}
	return 0;
}
