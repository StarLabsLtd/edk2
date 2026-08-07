/* SPDX-License-Identifier: GPL-2.0-only */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define IMAGE_SIZE 0x100U
#define FFS_OFFSET 0x48U
#define FFS_SIZE 0x24U
#define PATH_SIZE 4096U

static void put16(uint8_t *data, uint16_t value)
{
	data[0] = (uint8_t)value;
	data[1] = (uint8_t)(value >> 8);
}

static void put24(uint8_t *data, uint32_t value)
{
	data[0] = (uint8_t)value;
	data[1] = (uint8_t)(value >> 8);
	data[2] = (uint8_t)(value >> 16);
}

static void put64(uint8_t *data, uint64_t value)
{
	unsigned int index;

	for (index = 0; index < 8; index++)
		data[index] = (uint8_t)(value >> (index * 8));
}

static void build_image(uint8_t image[IMAGE_SIZE])
{
	static const uint8_t guid[16] = {
		0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde,
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
	};

	memset(image, 0xff, IMAGE_SIZE);
	memset(image, 0, FFS_OFFSET);
	put64(image + 0x20, IMAGE_SIZE);
	memcpy(image + 0x28, "_FVH", 4);
	put16(image + 0x30, FFS_OFFSET);
	memset(image + FFS_OFFSET, 0, FFS_SIZE);
	memcpy(image + FFS_OFFSET, guid, sizeof(guid));
	image[FFS_OFFSET + 18] = 0x07;
	put24(image + FFS_OFFSET + 20, FFS_SIZE);
	image[FFS_OFFSET + 23] = 0xf8;
	put24(image + FFS_OFFSET + 24, 12);
	image[FFS_OFFSET + 27] = 0x15;
	image[FFS_OFFSET + 28] = 'D';
	image[FFS_OFFSET + 30] = 'x';
	image[FFS_OFFSET + 32] = 'e';
}

static int write_image(const char *path, const uint8_t *image)
{
	FILE *file = fopen(path, "wb");

	if (file == NULL)
		return 1;
	if (fwrite(image, 1, IMAGE_SIZE, file) != IMAGE_SIZE)
		return 1;
	return fclose(file) != 0;
}

static int run_tool(const char *tool, const char *input, const char *output)
{
	pid_t child;
	int status;
	FILE *stream;

	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		stream = freopen(output, "w", stdout);
		if (stream == NULL)
			_exit(126);
		stream = freopen("/dev/null", "w", stderr);
		if (stream == NULL)
			_exit(126);
		execl(tool, tool, input, (char *)NULL);
		_exit(127);
	}
	if (waitpid(child, &status, 0) != child)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int output_matches(const char *path, const char *expected)
{
	char buffer[512];
	FILE *file = fopen(path, "r");
	size_t size;

	if (file == NULL)
		return 0;
	size = fread(buffer, 1, sizeof(buffer) - 1, file);
	buffer[size] = '\0';
	fclose(file);
	return strcmp(buffer, expected) == 0;
}

static int expect(int condition, const char *message)
{
	if (condition)
		return 0;
	fprintf(stderr, "cdk2 fvinfo test: %s\n", message);
	return 1;
}

int main(int argc, char **argv)
{
	uint8_t image[IMAGE_SIZE];
	char input[PATH_SIZE];
	char output[PATH_SIZE];
	int failed = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: cdk2-fvinfo-test TOOL BUILD_DIR\n");
		return EXIT_FAILURE;
	}
	if ((snprintf(input, sizeof(input), "%s/fvinfo-test.fv", argv[2]) < 0) ||
	    (snprintf(output, sizeof(output), "%s/fvinfo-test.out", argv[2]) < 0))
		return EXIT_FAILURE;

	build_image(image);
	failed |= expect(write_image(input, image) == 0, "cannot write valid fixture");
	failed |= expect(run_tool(argv[1], input, output) == 0, "valid FV was rejected");
	failed |= expect(output_matches(output,
		"guid\toffset\tsize\ttype\tui_name\n"
		"12345678-9abc-def0-1234-56789abcdef0\t0x00000048\t"
		"0x00000024\t0x07\tDxe\n"), "inventory output is not deterministic");

	build_image(image);
	memcpy(image + 0x28, "BAD!", 4);
	failed |= expect(write_image(input, image) == 0, "cannot write signature fixture");
	failed |= expect(run_tool(argv[1], input, output) != 0, "bad signature was accepted");

	build_image(image);
	put64(image + 0x20, IMAGE_SIZE + 1);
	failed |= expect(write_image(input, image) == 0, "cannot write length fixture");
	failed |= expect(run_tool(argv[1], input, output) != 0, "oversized FV was accepted");

	build_image(image);
	put24(image + FFS_OFFSET + 20, 0);
	failed |= expect(write_image(input, image) == 0, "cannot write FFS fixture");
	failed |= expect(run_tool(argv[1], input, output) != 0, "zero-sized FFS was accepted");

	build_image(image);
	put24(image + FFS_OFFSET + 24, FFS_SIZE);
	failed |= expect(write_image(input, image) == 0, "cannot write section fixture");
	failed |= expect(run_tool(argv[1], input, output) != 0,
			 "out-of-bounds section was accepted");

	unlink(input);
	unlink(output);
	if (failed == 0)
		puts("cdk2 fvinfo tests: PASS");
	return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
