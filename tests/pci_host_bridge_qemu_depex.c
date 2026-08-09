/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>

int main(int argc, char **argv)
{
	static const unsigned char depex[] = {
		0x16, 0, 0, 0x13, 0x02,
		0xbb, 0x7e, 0x70, 0x2f, 0x1a, 0x4a, 0xd4, 0x11,
		0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d, 0x08
	};
	FILE *output;

	if (argc != 2)
		return 2;
	output = fopen(argv[1], "wb");
	if (output == NULL || fwrite(depex, 1, sizeof(depex), output) != sizeof(depex) ||
	    fclose(output) != 0)
		return 1;
	return 0;
}
