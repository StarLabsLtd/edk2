/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>

int main(int argc, char **argv)
{
	static const unsigned char depex[] = { 6, 0, 0, 0x13, 0x06, 0x08 };
	FILE *file;

	if (argc != 2 || (file = fopen(argv[1], "wb")) == NULL)
		return 1;
	return fwrite(depex, 1, sizeof(depex), file) != sizeof(depex) || fclose(file) != 0;
}
