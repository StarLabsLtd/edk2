/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>

int main(int argc, char **argv)
{
	static const unsigned char depex[] = { 6, 0, 0, 0x13, 0x06, 0x08 };
	FILE *output;

	if (argc != 2)
		return 2;
	output = fopen(argv[1], "wb");
	if (output == NULL || fwrite(depex, 1, sizeof(depex), output) != sizeof(depex) ||
	    fclose(output) != 0)
		return 1;
	return 0;
}
