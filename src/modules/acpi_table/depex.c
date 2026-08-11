/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>

int main(int argc, char **argv)
{
	static const unsigned char section[] = {
		0x16, 0x00, 0x00, 0x13, 0x02, 0xf6, 0xf0, 0xa3,
		0x13, 0x4a, 0x26, 0xf0, 0x3e, 0xf2, 0xe0, 0xde,
		0xc5, 0x12, 0x34, 0x2f, 0x34, 0x08
	};
	FILE *file;

	if (argc != 2 || (file = fopen(argv[1], "wb")) == NULL)
		return 1;
	if (fwrite(section, 1, sizeof(section), file) != sizeof(section) ||
	    fclose(file) != 0)
		return 1;
	return 0;
}
