/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>

int main(int argc, char **argv)
{
	static const unsigned char depex[] = {
		0x16, 0x00, 0x00, 0x13,
		0x02, 0xf6, 0xf0, 0xa3, 0x13, 0x4a, 0x26, 0xf0, 0x3e, 0xf2, 0xe0,
		0xde, 0xc5, 0x12, 0x34, 0x2f, 0x34,
		0x08,
	};
	FILE *file;
	if (argc != 2)
		return 2;
	file = fopen(argv[1], "wb");
	if (file == NULL)
		return 1;
	if (fwrite(depex, 1, sizeof(depex), file) != sizeof(depex))
		return 1;
	return fclose(file) == 0 ? 0 : 1;
}
