/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>

int main(int argc, char **argv)
{
	static const unsigned char depex[] = {
		0x16, 0, 0, 0x13, 0x02,
		0xbe, 0x34, 0x80, 0xcf, 0x68, 0x67, 0x8b, 0x4d,
		0xb7, 0x39, 0x7c, 0xce, 0x68, 0x3a, 0x9f, 0xbe, 0x08
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
