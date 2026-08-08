/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdint.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	static const uint8_t depex[] = {
		0x16, 0x00, 0x00, 0x13,
		0x02, 0x18, 0xf8, 0x41, 0x64, 0x62, 0x63, 0x44, 0x4e,
		0xb5, 0x70, 0x7d, 0xba, 0x31, 0xdd, 0x24, 0x53,
		0x08
	};
	FILE *output;

	if (argc != 2)
		return 1;
	output = fopen(argv[1], "wb");
	if (output == NULL || fwrite(depex, 1, sizeof(depex), output) != sizeof(depex) ||
	    fclose(output) != 0)
		return 1;
	return 0;
}
