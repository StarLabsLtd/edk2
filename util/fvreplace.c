/* SPDX-License-Identifier: GPL-2.0-only */

/* Replace an equal-sized FFS file without changing the surrounding FV layout. */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message)
{
	fprintf(stderr, "cdk2-fvreplace: %s\n", message);
	exit(EXIT_FAILURE);
}

static uint32_t get24(const uint8_t *data)
{
	return data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16;
}

static uint8_t *read_file(const char *path, size_t *size)
{
	FILE *file = fopen(path, "rb");
	long length;
	uint8_t *data;

	if (file == NULL) {
		fprintf(stderr, "cdk2-fvreplace: cannot open %s: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
	    fseek(file, 0, SEEK_SET) != 0)
		fail("cannot size input");
	data = malloc((size_t)length == 0 ? 1 : (size_t)length);
	if (data == NULL || fread(data, 1, (size_t)length, file) != (size_t)length)
		fail("cannot read input");
	if (fclose(file) != 0)
		fail("cannot close input");
	*size = (size_t)length;
	return data;
}

int main(int argc, char **argv)
{
	uint8_t *volume;
	uint8_t *replacement;
	size_t volume_size;
	size_t replacement_size;
	size_t offset;
	FILE *file;

	if (argc != 5) {
		fprintf(stderr, "usage: %s FV OFFSET REPLACEMENT OUTPUT\n", argv[0]);
		return EXIT_FAILURE;
	}
	volume = read_file(argv[1], &volume_size);
	replacement = read_file(argv[3], &replacement_size);
	offset = (size_t)strtoull(argv[2], NULL, 0);
	if (replacement_size < 24 || get24(replacement + 20) != replacement_size)
		fail("replacement is not a valid normal-size FFS file");
	if (offset > volume_size || replacement_size > volume_size - offset)
		fail("replacement lies outside FV");
	if (memcmp(volume + offset, replacement, 16) != 0)
		fail("replacement GUID does not match target FFS");
	if (get24(volume + offset + 20) != replacement_size)
		fail("replacement size does not match target FFS");
	memcpy(volume + offset, replacement, replacement_size);
	file = fopen(argv[4], "wb");
	if (file == NULL || fwrite(volume, 1, volume_size, file) != volume_size || fclose(file) != 0)
		fail("cannot write output FV");
	free(replacement);
	free(volume);
	return EXIT_SUCCESS;
}
