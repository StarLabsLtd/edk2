/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Emit the original BEFORE gEfiDxeSmmReadyToLockProtocolGuid DXE DEPEX. */

#include <stdint.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	static const uint8_t depex[] = {
		0x16, 0x00, 0x00, 0x13, /* section size and DXE_DEPEX type */
		0x02,                   /* BEFORE */
		0xf6, 0xf0, 0xa3, 0x13, 0x4a, 0x26, 0xf0, 0x3e,
		0xf2, 0xe0, 0xde, 0xc5, 0x12, 0x34, 0x2f, 0x34,
		0x08                    /* END */
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
