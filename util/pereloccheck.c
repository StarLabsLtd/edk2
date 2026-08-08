/* SPDX-License-Identifier: GPL-2.0-only */

/* Reject relocation records that are not valid for native X64 modules. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMAGE_MACHINE_X64 0x8664U
#define PE32_PLUS_MAGIC 0x020bU
#define RELOC_ABSOLUTE 0U
#define RELOC_DIR64 10U

static uint16_t get16(const uint8_t *data)
{
	return data[0] | (uint16_t)data[1] << 8;
}

static uint32_t get32(const uint8_t *data)
{
	return data[0] | (uint32_t)data[1] << 8 | (uint32_t)data[2] << 16 |
	       (uint32_t)data[3] << 24;
}

static void fail(const char *message)
{
	fprintf(stderr, "cdk2-pereloccheck: %s\n", message);
	exit(EXIT_FAILURE);
}

static size_t rva_offset(const uint8_t *image, size_t size, size_t sections,
			 uint16_t section_count, uint32_t rva, uint32_t length)
{
	uint16_t index;

	for (index = 0; index < section_count; index++) {
		const uint8_t *section = image + sections + index * 40U;
		uint32_t virtual_address;
		uint32_t raw_size;
		uint32_t raw_offset;

		if ((size_t)(section - image) > size || size - (size_t)(section - image) < 40U)
			fail("truncated section table");
		virtual_address = get32(section + 12);
		raw_size = get32(section + 16);
		raw_offset = get32(section + 20);
		if (rva >= virtual_address) {
			uint32_t delta = rva - virtual_address;

			if (delta <= raw_size && length <= raw_size - delta && raw_offset <= size &&
			    delta <= size - raw_offset && length <= size - raw_offset - delta)
				return raw_offset + delta;
		}
	}
	fail("relocation directory is outside file-backed sections");
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t *image;
	long length;
	size_t size;
	size_t pe;
	size_t optional;
	size_t sections;
	size_t offset;
	size_t end;
	uint16_t section_count;
	uint16_t optional_size;
	uint32_t reloc_rva;
	uint32_t reloc_size;
	unsigned long expected_subsystem = 0;
	const char *image_path;
	int saw_dir64 = 0;
	FILE *file;

	if (argc == 2) {
		image_path = argv[1];
	} else if (argc == 4 && strcmp(argv[1], "--subsystem") == 0) {
		expected_subsystem = strtoul(argv[2], NULL, 0);
		if (expected_subsystem == 0 || expected_subsystem > UINT16_MAX)
			fail("invalid expected subsystem");
		image_path = argv[3];
	} else {
		fail("usage: cdk2-pereloccheck [--subsystem NUMBER] IMAGE");
	}
	file = fopen(image_path, "rb");
	if (file == NULL || fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
	    fseek(file, 0, SEEK_SET) != 0)
		fail("cannot open image");
	size = (size_t)length;
	image = malloc(size == 0 ? 1 : size);
	if (image == NULL || fread(image, 1, size, file) != size || fclose(file) != 0)
		fail("cannot read image");
	if (size < 0x40 || get16(image) != 0x5a4dU)
		fail("not an MZ image");
	pe = get32(image + 0x3c);
	if (pe > size || size - pe < 24U || get32(image + pe) != 0x00004550U ||
	    get16(image + pe + 4) != IMAGE_MACHINE_X64)
		fail("not an X64 PE image");
	section_count = get16(image + pe + 6);
	optional_size = get16(image + pe + 20);
	optional = pe + 24U;
	sections = optional + optional_size;
	if (optional > size || optional_size < 160U || optional_size > size - optional ||
	    get16(image + optional) != PE32_PLUS_MAGIC)
		fail("invalid PE32+ optional header");
	if (expected_subsystem != 0 && get16(image + optional + 68U) != expected_subsystem)
		fail("PE subsystem does not match the admitted module");
	reloc_rva = get32(image + optional + 152U);
	reloc_size = get32(image + optional + 156U);
	if (reloc_rva == 0 || reloc_size < 8U)
		fail("missing base relocation directory");
	offset = rva_offset(image, size, sections, section_count, reloc_rva, reloc_size);
	end = offset + reloc_size;
	while (offset < end) {
		uint32_t block_size;
		size_t entry;

		if (end - offset < 8U || (block_size = get32(image + offset + 4)) < 8U ||
		    block_size > end - offset || (block_size & 1U) != 0)
			fail("invalid relocation block");
		for (entry = offset + 8U; entry < offset + block_size; entry += 2U) {
			uint16_t type = get16(image + entry) >> 12;

			if (type == RELOC_DIR64)
				saw_dir64 = 1;
			else if (type != RELOC_ABSOLUTE)
				fail("PE32+ image contains a non-DIR64 relocation");
		}
		offset += block_size;
	}
	free(image);
	if (!saw_dir64)
		fail("PE32+ image contains no DIR64 relocation");
	return EXIT_SUCCESS;
}
