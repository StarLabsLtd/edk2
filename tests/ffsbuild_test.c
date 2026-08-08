/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_file(const char *path, const uint8_t *data, size_t size)
{
	FILE *file = fopen(path, "wb");
	int failed = file == NULL || fwrite(data, 1, size, file) != size;

	if (file != NULL && fclose(file) != 0)
		failed = 1;
	return failed;
}

static int run(const char *tool, const char *pe, const char *output,
	       const char *depex)
{
	pid_t child = fork();
	int status;

	if (child == 0) {
		execl(tool, tool, "f80697e9-7fd6-4665-8646-88e33ef71dfc",
		      "Test", "1.0", "130", pe, output, depex, NULL);
		_exit(127);
	}
	if (child < 0 || waitpid(child, &status, 0) != child)
		return 1;
	return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

static int run_without_depex(const char *tool, const char *pe, const char *output)
{
	pid_t child = fork();
	int status;

	if (child == 0) {
		execl(tool, tool, "cd3bafb6-50fb-4fe8-8e4e-ab74d2c1a600",
		      "EnglishDxe", "1.0", "130", pe, output, "-", NULL);
		_exit(127);
	}
	if (child < 0 || waitpid(child, &status, 0) != child)
		return 1;
	return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

static int run_raw(const char *tool, const char *pe, const char *output,
	const char *raw)
{
	pid_t child = fork();
	int status;

	if (child == 0) {
		execl(tool, tool, "80cf7257-87ab-47f9-a3fe-d50b76d89541",
		      "PcdDxe", "1.0", "130", pe, output, "--raw", raw, NULL);
		_exit(127);
	}
	if (child < 0 || waitpid(child, &status, 0) != child)
		return 1;
	return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

static int run_mm(const char *tool, const char *pe, const char *output,
	const char *depex, const char *depex_type)
{
	pid_t child = fork();
	int status;

	if (child == 0) {
		execl(tool, tool, "a47ee2d8-f60e-42fd-8e58-7bd65ee4c29b",
		      "CpuIo2Smm", "1.0", "130", pe, output, depex,
		      "--file-type", "0x0a", "--depex-type", depex_type, NULL);
		_exit(127);
	}
	if (child < 0 || waitpid(child, &status, 0) != child)
		return 1;
	return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

static int run_mm_partial(const char *tool, const char *pe, const char *output,
	const char *depex, int file_type_only)
{
	pid_t child = fork();
	int status;

	if (child == 0) {
		execl(tool, tool, "a47ee2d8-f60e-42fd-8e58-7bd65ee4c29b",
		      "CpuIo2Smm", "1.0", "130", pe, output, depex,
		      file_type_only ? "--file-type" : "--depex-type",
		      file_type_only ? "0x0a" : "0x1c", NULL);
		_exit(127);
	}
	if (child < 0 || waitpid(child, &status, 0) != child)
		return 1;
	return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

int main(int argc, char **argv)
{
	static const uint8_t pe[16] = { 'M', 'Z' };
	static const uint8_t depex[] = {
		0x16, 0, 0, 0x13, 0x02,
		0xf6, 0xf0, 0xa3, 0x13, 0x4a, 0x26, 0xf0, 0x3e,
		0xf2, 0xe0, 0xde, 0xc5, 0x12, 0x34, 0x2f, 0x34, 0x08
	};
	static const uint8_t raw[] = { 0x3c, 0x19, 0x7d, 0x3c, 7, 0, 0, 0 };
	uint8_t mm_depex[sizeof(depex)];
	uint8_t output[130];
	char pe_path[512], depex_path[512], raw_path[512], output_path[512];
	FILE *file;

	if (argc != 3)
		return 1;
	snprintf(pe_path, sizeof(pe_path), "%s/ffsbuild-test.efi", argv[2]);
	snprintf(depex_path, sizeof(depex_path), "%s/ffsbuild-test.depex", argv[2]);
	snprintf(raw_path, sizeof(raw_path), "%s/ffsbuild-test.raw", argv[2]);
	snprintf(output_path, sizeof(output_path), "%s/ffsbuild-test.ffs", argv[2]);
	if (write_file(pe_path, pe, sizeof(pe)) ||
	    write_file(depex_path, depex, sizeof(depex)) ||
	    run(argv[1], pe_path, output_path, depex_path))
		return 1;
	file = fopen(output_path, "rb");
	if (file == NULL || fread(output, 1, sizeof(output), file) != sizeof(output) ||
	    fclose(file) != 0)
		return 1;
	if (memcmp(output + 24, depex, sizeof(depex)) != 0 ||
	    output[48 + 3] != 0x10 || memcmp(output + 52, pe, sizeof(pe)) != 0)
		return 1;
	if (run_without_depex(argv[1], pe_path, output_path))
		return 1;
	file = fopen(output_path, "rb");
	if (file == NULL || fread(output, 1, sizeof(output), file) != sizeof(output) ||
	    fclose(file) != 0 || output[24 + 3] != 0x10 ||
	    memcmp(output + 28, pe, sizeof(pe)) != 0)
		return 1;
	if (write_file(raw_path, raw, sizeof(raw)) ||
	    run_raw(argv[1], pe_path, output_path, raw_path))
		return 1;
	file = fopen(output_path, "rb");
	if (file == NULL || fread(output, 1, sizeof(output), file) != sizeof(output) ||
	    fclose(file) != 0 || output[27] != 0x19 ||
	    memcmp(output + 28, raw, sizeof(raw)) != 0 || output[39] != 0x13 ||
	    output[47] != 0x10)
		return 1;
	memcpy(mm_depex, depex, sizeof(mm_depex));
	mm_depex[3] = 0x1c;
	if (write_file(depex_path, mm_depex, sizeof(mm_depex)) ||
	    run_mm(argv[1], pe_path, output_path, depex_path, "0x1c"))
		return 1;
	file = fopen(output_path, "rb");
	if (file == NULL || fread(output, 1, sizeof(output), file) != sizeof(output) ||
	    fclose(file) != 0 || output[18] != 0x0a || output[27] != 0x1c)
		return 1;
	if (!run_mm(argv[1], pe_path, output_path, depex_path, "0x13"))
		return 1;
	if (!run_mm_partial(argv[1], pe_path, output_path, depex_path, 1) ||
	    !run_mm_partial(argv[1], pe_path, output_path, depex_path, 0))
		return 1;
	depex_path[strlen(depex_path) - 1] = 'x';
	if (write_file(depex_path, depex, sizeof(depex) - 1) ||
	    !run(argv[1], pe_path, output_path, depex_path))
		return 1;
	return 0;
}
