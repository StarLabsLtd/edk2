/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 firmware-volume packer.
 *
 * This tool builds compact firmware volumes from explicit PE/COFF and FFS
 * inputs. In flat mode, the retained DXE files are placed directly in the
 * outer volume.
 */

#include <errno.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FV_HEADER_SIZE                0x48U
#define FV_SIZE_DEFAULT               0x00A00000U
#define FV_BASE_ADDRESS               0x00800000U
#define FV_EXT_HEADER_OFFSET          0x60U
#define FV_EXT_HEADER_SIZE            0x14U
#define FFS_HEADER_SIZE               0x18U
#define FFS_PAD_TYPE                  0xF0U
#define FFS_STATE_VALID               0xF8U
#define FFS_FIXED_CHECKSUM            0xAAU
#define FFS_ATTRIB_DATA_ALIGNMENT_2   0x02U
#define FFS_ATTRIB_DATA_ALIGNMENT_16  0x08U
#define FFS_ATTRIB_DATA_ALIGNMENT_128 0x10U
#define FFS_ATTRIB_DATA_ALIGNMENT     0x38U
#define FFS_TYPE_SECURITY_CORE        0x03U
#define FFS_TYPE_DXE_CORE             0x05U
#define FFS_TYPE_FV_IMAGE             0x0BU
#define SECTION_TYPE_PE32             0x10U
#define SECTION_TYPE_FV_IMAGE         0x17U
#define SECTION_TYPE_RAW              0x19U

struct fvpack_blob {
	uint8_t *data;
	size_t size;
};

struct fvpack_ffs_input {
	char *path;
	struct fvpack_blob file;
	uint8_t guid[16];
	size_t reference_offset;
	bool has_reference_offset;
	bool used;
};

struct fvpack_ffs_inputs {
	struct fvpack_ffs_input *items;
	size_t count;
	bool ordered;
};

struct fvpack_guid_list {
	uint8_t *items;
	size_t count;
};

static const uint8_t m_ffs_pad_guid[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static const uint8_t m_file_system_guid[16] = {0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F,
					    0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3};

static const uint8_t m_volume_name_guid[16] = {0x86, 0x59, 0xE7, 0x96, 0xDD, 0x6F, 0x1E, 0x49,
					    0x9F, 0xD5, 0x35, 0xE2, 0x1A, 0xC4, 0x5B, 0x45};

static const uint8_t m_payload_entry_guid[16] = {0xD7, 0xBB, 0x19, 0x21, 0x32, 0x94, 0x47, 0x4F,
					      0xB5, 0xE2, 0x5C, 0x4E, 0xA3, 0x1B, 0x6B, 0xDC};

static const uint8_t m_dxe_volume_file_guid[16] = {
	0x93, 0xFD, 0x35, 0x4E, 0x72, 0x9C, 0x15, 0x4C,
	0x8C, 0x4B, 0xE7, 0x7F, 0x1D, 0xB2, 0xD7, 0x93
};

static bool is_erased(const uint8_t *data, size_t size);
static size_t get_ffs_start_offset(const struct fvpack_blob *volume);

static void fail(const char *message)
{
	fprintf(stderr, "cdk2-fvpack: %s\n", message);
	exit(EXIT_FAILURE);
}

static void *allocate(size_t size)
{
	void *buffer;

	buffer = malloc(size == 0 ? 1 : size);
	if (buffer == NULL) {
		fail("out of memory");
	}

	return buffer;
}

static void put16(uint8_t *buffer, uint16_t value)
{
	buffer[0] = (uint8_t)value;
	buffer[1] = (uint8_t)(value >> 8);
}

static void put32(uint8_t *buffer, uint32_t value)
{
	buffer[0] = (uint8_t)value;
	buffer[1] = (uint8_t)(value >> 8);
	buffer[2] = (uint8_t)(value >> 16);
	buffer[3] = (uint8_t)(value >> 24);
}

static void put64(uint8_t *buffer, uint64_t value)
{
	put32(buffer, (uint32_t)value);
	put32(buffer + 4, (uint32_t)(value >> 32));
}

static void put24(uint8_t *buffer, size_t value)
{
	if (value > 0xFFFFFFU) {
		fail("24-bit field overflow");
	}

	buffer[0] = (uint8_t)value;
	buffer[1] = (uint8_t)(value >> 8);
	buffer[2] = (uint8_t)(value >> 16);
}

static uint8_t checksum8(const uint8_t *buffer, size_t size)
{
	uint8_t sum;
	size_t index;

	sum = 0;
	for (index = 0; index < size; index++) {
		sum = (uint8_t)(sum + buffer[index]);
	}

	return (uint8_t)(0U - sum);
}

static uint16_t checksum16(const uint8_t *buffer, size_t size)
{
	uint32_t sum;
	size_t index;

	if ((size & 1U) != 0) {
		fail("16-bit checksum has odd length");
	}

	sum = 0;
	for (index = 0; index < size; index += 2) {
		sum += (uint16_t)(buffer[index] | ((uint16_t)buffer[index + 1] << 8));
	}

	return (uint16_t)(0U - (uint16_t)sum);
}

static size_t align_up(size_t value, size_t alignment)
{
	if ((alignment == 0) || ((alignment & (alignment - 1)) != 0)) {
		fail("invalid alignment");
	}

	return (value + alignment - 1) & ~(alignment - 1);
}

static uint16_t get16(const uint8_t *buffer)
{
	return (uint16_t)(buffer[0] | ((uint16_t)buffer[1] << 8));
}

static uint32_t get32(const uint8_t *buffer)
{
	return (uint32_t)(buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) |
			  ((uint32_t)buffer[3] << 24));
}

static size_t get24(const uint8_t *buffer)
{
	return (size_t)(buffer[0] | ((size_t)buffer[1] << 8) | ((size_t)buffer[2] << 16));
}

static uint64_t get64(const uint8_t *buffer)
{
	return (uint64_t)get32(buffer) | ((uint64_t)get32(buffer + 4) << 32);
}

static size_t rva_to_file_offset(const uint8_t *image, size_t image_size, uint32_t pe_offset,
			      uint32_t rva)
{
	const uint8_t *coff;
	const uint8_t *optional;
	const uint8_t *section;
	uint16_t section_count;
	uint16_t optional_size;
	uint16_t index;
	uint32_t virtual_address;
	uint32_t virtual_size;
	uint32_t raw_size;
	uint32_t raw_offset;
	uint32_t span;

	if ((pe_offset > image_size) || (image_size - pe_offset < 24)) {
		fail("PE header is outside the entry image");
	}

	coff = image + pe_offset + 4;
	section_count = get16(coff + 2);
	optional_size = get16(coff + 16);
	optional = coff + 20;
	section = optional + optional_size;
	if ((size_t)(section - image) > image_size) {
		fail("PE section table is outside the entry image");
	}

	for (index = 0; index < section_count; index++) {
		if ((size_t)(section + 40 - image) > image_size) {
			fail("PE section header is outside the entry image");
		}

		virtual_size = get32(section + 8);
		virtual_address = get32(section + 12);
		raw_size = get32(section + 16);
		raw_offset = get32(section + 20);
		span = (virtual_size > raw_size) ? virtual_size : raw_size;
		if ((rva >= virtual_address) && (rva - virtual_address < span)) {
			if ((rva - virtual_address >= raw_size) || (raw_offset > image_size) ||
			    ((size_t)(rva - virtual_address) > image_size - raw_offset)) {
				fail("PE relocation points outside the entry image");
			}

			return (size_t)raw_offset + (rva - virtual_address);
		}

		section += 40;
	}

	fail("PE relocation RVA is not in a section");
	return 0;
}

static void relocate_pe(struct fvpack_blob *image, uint64_t target_base)
{
	uint32_t pe_offset;
	uint64_t original_base;
	uint64_t delta;
	uint32_t reloc_rva;
	uint32_t reloc_size;
	size_t optional_offset;
	size_t reloc_offset;
	size_t reloc_end;
	size_t block_offset;
	size_t data_directory_offset = 0;
	size_t image_base_offset;
	size_t fixup_size;
	uint32_t page_rva;
	uint32_t block_size;
	uint16_t entry;
	uint16_t type;
	uint16_t reloc_type;
	uint16_t offset;
	uint16_t optional_magic;
	size_t fixup_offset;
	uint64_t fixup_rva;
	uint64_t value;

	if ((image->size < 0x40) || (get16(image->data) != 0x5A4D)) {
		fail("payload entry is not a PE image");
	}

	pe_offset = get32(image->data + 0x3C);
	if ((pe_offset > image->size) || (image->size - pe_offset < 24) ||
	    (get32(image->data + pe_offset) != 0x00004550U)) {
		fail("payload entry has an invalid PE signature");
	}

	optional_offset = (size_t)pe_offset + 4 + 20;
	if ((optional_offset > image->size) || (image->size - optional_offset < 2)) {
		fail("payload entry optional header is outside the image");
	}

	optional_magic = get16(image->data + optional_offset);
	if (optional_magic == 0x010BU) {
		data_directory_offset = 96;
		image_base_offset = 28;
		fixup_size = sizeof(uint32_t);
		reloc_type = 3;
	} else if (optional_magic == 0x020BU) {
		data_directory_offset = 112;
		image_base_offset = 24;
		fixup_size = sizeof(uint64_t);
		reloc_type = 10;
	} else {
		fail("payload entry has an unsupported PE optional header");
	}

	if (image->size - optional_offset < data_directory_offset + (6 * 8)) {
		fail("payload entry data directories are outside the image");
	}

	original_base = (optional_magic == 0x020BU) ?
			       get64(image->data + optional_offset + image_base_offset) :
			       get32(image->data + optional_offset + image_base_offset);
	reloc_rva = get32(image->data + optional_offset + data_directory_offset + (5 * 8));
	reloc_size = get32(image->data + optional_offset + data_directory_offset + (5 * 8) + 4);
	if ((reloc_rva == 0) || (reloc_size == 0)) {
		/*
		 * X64 PIE entries can use RIP-relative references and advertise an
		 * image base of zero, so it does not need a relocation directory.
		 */
		if (original_base == 0) {
			if (optional_magic == 0x020BU) {
				put64(image->data + optional_offset + image_base_offset,
				      target_base);
			}

			return;
		}

		fail("payload entry has no base relocation directory");
	}

	reloc_offset = rva_to_file_offset(image->data, image->size, pe_offset, reloc_rva);
	if ((reloc_offset > image->size) || (reloc_size > image->size - reloc_offset)) {
		fail("payload relocation directory is outside the entry image");
	}

	if (optional_magic == 0x010BU && target_base > UINT32_MAX) {
		fail("PE32 relocation base overflows");
	}

	delta = target_base - original_base;
	reloc_end = reloc_offset + reloc_size;
	block_offset = reloc_offset;
	while (block_offset < reloc_end) {
		if (reloc_end - block_offset < 8) {
			fail("truncated payload relocation block");
		}

		page_rva = get32(image->data + block_offset);
		block_size = get32(image->data + block_offset + 4);
		if ((block_size < 8) || (block_size > reloc_end - block_offset) ||
		    (((block_size - 8) & 1U) != 0)) {
			fail("invalid payload relocation block");
		}

		for (size_t entry_offset = 8; entry_offset < block_size; entry_offset += 2) {
			entry = get16(image->data + block_offset + entry_offset);
			type = (uint16_t)(entry >> 12);
			offset = (uint16_t)(entry & 0x0FFFU);
			if (type == 0) {
				continue;
			}

			if (type != reloc_type) {
				fail("unsupported payload relocation type");
			}

			fixup_rva = (uint64_t)page_rva + offset;
			if (fixup_rva > UINT32_MAX) {
				fail("payload relocation fixup RVA overflows");
			}

			fixup_offset = rva_to_file_offset(image->data, image->size, pe_offset,
						      (uint32_t)fixup_rva);
			if (fixup_offset > image->size ||
			    image->size - fixup_offset < fixup_size) {
				fail("payload relocation fixup is outside the entry image");
			}

			if (fixup_size == sizeof(uint64_t)) {
				value = get64(image->data + fixup_offset);
				put64(image->data + fixup_offset, value + delta);
			} else {
				value = get32(image->data + fixup_offset);
				put32(image->data + fixup_offset,
				      (uint32_t)value + (uint32_t)delta);
			}
		}

		block_offset += block_size;
	}

	if (optional_magic == 0x020BU) {
		put64(image->data + optional_offset + image_base_offset, target_base);
	} else {
		put32(image->data + optional_offset + image_base_offset, (uint32_t)target_base);
	}
}

static struct fvpack_blob read_file(const char *path)
{
	struct fvpack_blob result;
	FILE *file;
	long length;

	file = fopen(path, "rb");
	if (file == NULL) {
		fprintf(stderr, "cdk2-fvpack: cannot open %s: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fail("cannot seek input file");
	}

	length = ftell(file);
	if (length < 0) {
		fail("cannot determine input file size");
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		fail("cannot rewind input file");
	}

	result.size = (size_t)length;
	result.data = allocate(result.size);
	if (fread(result.data, 1, result.size, file) != result.size) {
		fail("cannot read input file");
	}

	fclose(file);
	return result;
}

static char *duplicate_string(const char *string)
{
	size_t length;
	char *copy;

	length = strlen(string) + 1;
	copy = allocate(length);
	memcpy(copy, string, length);
	return copy;
}

static char *trim(char *string)
{
	char *end;

	while (isspace((unsigned char)*string)) {
		string++;
	}

	end = string + strlen(string);
	while ((end > string) && isspace((unsigned char)end[-1])) {
		end--;
		*end = '\0';
	}

	return string;
}

static char *next_token(char **cursor)
{
	char *start;
	char *end;

	start = *cursor;
	while (isspace((unsigned char)*start)) {
		start++;
	}

	if (*start == '\0') {
		*cursor = start;
		return NULL;
	}

	end = start;
	while ((*end != '\0') && !isspace((unsigned char)*end)) {
		end++;
	}

	if (*end != '\0') {
		*end = '\0';
		end++;
	}

	*cursor = end;
	return start;
}

static int hex_value(char character)
{
	if ((character >= '0') && (character <= '9')) {
		return character - '0';
	}

	if ((character >= 'a') && (character <= 'f')) {
		return character - 'a' + 10;
	}

	if ((character >= 'A') && (character <= 'F')) {
		return character - 'A' + 10;
	}

	return -1;
}

static uint32_t parse_hex_group(const char *text, size_t offset, size_t length)
{
	uint32_t value;
	int digit;
	size_t index;

	value = 0;
	for (index = 0; index < length; index++) {
		digit = hex_value(text[offset + index]);
		if (digit < 0) {
			fail("manifest contains an invalid GUID");
		}

		value = (value << 4) | (uint32_t)digit;
	}

	return value;
}

static void parse_guid(const char *text, uint8_t *guid)
{
	uint32_t data1;
	uint32_t data2;
	uint32_t data3;
	size_t index;

	if ((strlen(text) != 36) || (text[8] != '-') || (text[13] != '-') ||
	    (text[18] != '-') || (text[23] != '-')) {
		fail("manifest contains an invalid GUID");
	}

	data1 = parse_hex_group(text, 0, 8);
	data2 = parse_hex_group(text, 9, 4);
	data3 = parse_hex_group(text, 14, 4);

	guid[0] = (uint8_t)data1;
	guid[1] = (uint8_t)(data1 >> 8);
	guid[2] = (uint8_t)(data1 >> 16);
	guid[3] = (uint8_t)(data1 >> 24);
	guid[4] = (uint8_t)data2;
	guid[5] = (uint8_t)(data2 >> 8);
	guid[6] = (uint8_t)data3;
	guid[7] = (uint8_t)(data3 >> 8);
	guid[8] = (uint8_t)parse_hex_group(text, 19, 2);
	guid[9] = (uint8_t)parse_hex_group(text, 21, 2);
	for (index = 0; index < 6; index++) {
		guid[10 + index] = (uint8_t)parse_hex_group(text, 24 + (index * 2), 2);
	}
}

static size_t parse_size(const char *text)
{
	unsigned long long value;
	char *end;

	if (text[0] == '-') {
		fail("manifest contains an invalid number");
	}

	errno = 0;
	value = strtoull(text, &end, 0);
	if ((errno != 0) || (*end != '\0') || (value > SIZE_MAX)) {
		fail("manifest contains an invalid number");
	}

	return (size_t)value;
}

static void validate_ffs_input(const struct fvpack_ffs_input *input)
{
	uint8_t header[FFS_HEADER_SIZE];
	size_t file_size;

	if (input->file.size < FFS_HEADER_SIZE) {
		fail("FFS input is smaller than its header");
	}

	file_size = get24(input->file.data + 20);
	if (file_size == 0xFFFFFFU) {
		fail("large FFS inputs are not supported by the native packer");
	}

	if ((file_size < FFS_HEADER_SIZE) || (file_size != input->file.size)) {
		fail("FFS input size does not match its header");
	}

	if (input->file.data[17] != FFS_FIXED_CHECKSUM) {
		fail("FFS input has an unsupported data checksum mode");
	}

	memcpy(header, input->file.data, sizeof(header));
	header[16] = 0;
	header[17] = 0;
	header[23] = 0;
	if (checksum8(header, sizeof(header)) != input->file.data[16]) {
		fail("FFS input header checksum does not match");
	}
}

static struct fvpack_ffs_input *append_ffs_input(struct fvpack_ffs_inputs *inputs)
{
	struct fvpack_ffs_input *item;

	item = realloc(inputs->items, (inputs->count + 1) * sizeof(*item));
	if (item == NULL) {
		fail("out of memory reading FFS inputs");
	}

	inputs->items = item;
	item = &inputs->items[inputs->count++];
	memset(item, 0, sizeof(*item));
	return item;
}

static bool has_earlier_guid(const struct fvpack_ffs_inputs *inputs, const uint8_t *guid)
{
	size_t index;

	for (index = 0; index + 1 < inputs->count; index++) {
		if (memcmp(inputs->items[index].guid, guid, 16) == 0) {
			return true;
		}
	}

	return false;
}

static void read_ffs_list(const char *path, struct fvpack_ffs_inputs *inputs)
{
	FILE *file;
	char line[4096];
	char *path_text;
	struct fvpack_ffs_input *item;

	file = fopen(path, "r");
	if (file == NULL) {
		fprintf(stderr, "cdk2-fvpack: cannot open FFS list %s: %s\n", path,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (fgets(line, sizeof(line), file) != NULL) {
		path_text = trim(line);

		if ((path_text[0] == '\0') || (path_text[0] == '#')) {
			continue;
		}

		item = append_ffs_input(inputs);
		item->path = duplicate_string(path_text);
		item->file = read_file(path_text);
		validate_ffs_input(item);
		memcpy(item->guid, item->file.data, sizeof(item->guid));
		if (has_earlier_guid(inputs, item->guid)) {
			fail("FFS input list contains a duplicate file GUID");
		}
	}

	if (ferror(file) != 0) {
		fail("cannot read FFS list");
	}

	fclose(file);
}

static void read_ffs_manifest(const char *path, struct fvpack_ffs_inputs *inputs)
{
	FILE *file;
	char line[4096];
	char *cursor;
	char *keyword;
	char *offset_text;
	char *guid_text;
	char *path_text;
	struct fvpack_ffs_input *item;
	uint8_t guid[16];
	bool saw_version;
	bool saw_file;
	size_t last_offset;
	size_t offset;

	file = fopen(path, "r");
	if (file == NULL) {
		fprintf(stderr, "cdk2-fvpack: cannot open FFS manifest %s: %s\n", path,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	inputs->ordered = true;
	saw_version = false;
	saw_file = false;
	last_offset = 0;
	while (fgets(line, sizeof(line), file) != NULL) {
		cursor = trim(line);
		if ((cursor[0] == '\0') || (cursor[0] == '#')) {
			continue;
		}

		keyword = next_token(&cursor);
		if ((keyword != NULL) && (strcmp(keyword, "VERSION") == 0)) {
			offset_text = next_token(&cursor);
			if ((offset_text == NULL) || (strcmp(offset_text, "1") != 0) ||
			    (trim(cursor)[0] != '\0') || saw_version) {
				fail("FFS manifest has an unsupported version");
			}

			saw_version = true;
			continue;
		}

		if ((keyword == NULL) || (strcmp(keyword, "FILE") != 0)) {
			fail("FFS manifest contains an unsupported record");
		}

		if (!saw_version) {
			fail("FFS manifest must start with VERSION 1");
		}

		offset_text = next_token(&cursor);
		guid_text = next_token(&cursor);
		path_text = trim(cursor);
		if ((offset_text == NULL) || (guid_text == NULL) || (path_text[0] == '\0')) {
			fail("FFS manifest FILE record is incomplete");
		}

		parse_guid(guid_text, guid);
		offset = parse_size(offset_text);
		if (saw_file && (offset <= last_offset)) {
			fail("FFS manifest offsets are not strictly increasing");
		}

		saw_file = true;
		last_offset = offset;

		item = append_ffs_input(inputs);
		item->reference_offset = offset;
		item->has_reference_offset = true;
		memcpy(item->guid, guid, sizeof(item->guid));
		if (has_earlier_guid(inputs, item->guid)) {
			fail("FFS manifest contains a duplicate file GUID");
		}

		item->path = duplicate_string(path_text);
		item->file = read_file(path_text);
		validate_ffs_input(item);
		if (memcmp(item->file.data, item->guid, sizeof(item->guid)) != 0) {
			fail("FFS manifest GUID does not match its input file");
		}
	}

	if (ferror(file) != 0) {
		fail("cannot read FFS manifest");
	}

	fclose(file);
	if (!saw_version || (inputs->count == 0)) {
		fail("FFS manifest contains no files");
	}
}

static struct fvpack_ffs_input *
find_ffs_input(const struct fvpack_ffs_inputs *inputs, const uint8_t *guid)
{
	size_t index;

	for (index = 0; index < inputs->count; index++) {
		if (memcmp(inputs->items[index].file.data, guid, 16) == 0) {
			return &inputs->items[index];
		}
	}

	return NULL;
}

static void print_guid(const uint8_t *guid)
{
	size_t index;

	for (index = 0; index < 16; index++) {
		fprintf(stderr, "%02x", guid[index]);
	}
}

static void free_ffs_inputs(struct fvpack_ffs_inputs *inputs)
{
	size_t index;

	for (index = 0; index < inputs->count; index++) {
		free(inputs->items[index].path);
		free(inputs->items[index].file.data);
	}

	free(inputs->items);
	inputs->items = NULL;
	inputs->count = 0;
	inputs->ordered = false;
}

static void verify_all_ffs_inputs_used(const struct fvpack_ffs_inputs *inputs)
{
	size_t index;

	for (index = 0; index < inputs->count; index++) {
		if (!inputs->items[index].used) {
			fprintf(stderr, "cdk2-fvpack: unused DXE FV FFS input: %s guid=",
				inputs->items[index].path);
			print_guid(inputs->items[index].file.data);
			fputc('\n', stderr);
			fail("FFS input list contains a file that is not in the DXE FV reference");
		}
	}
}

static void write_file(const char *path, const uint8_t *data, size_t size)
{
	FILE *file;

	file = fopen(path, "wb");
	if (file == NULL) {
		fprintf(stderr, "cdk2-fvpack: cannot create %s: %s\n", path, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fwrite(data, 1, size, file) != size) {
		fail("cannot write output file");
	}

	if (fclose(file) != 0) {
		fail("cannot close output file");
	}
}

static struct fvpack_blob make_ffs(const uint8_t *guid, uint8_t type, uint8_t attributes,
				   const uint8_t *body, size_t body_size)
{
	struct fvpack_blob result;
	uint8_t header_checksum;

	if (body_size > 0xFFFFFFU - FFS_HEADER_SIZE) {
		fail("FFS file is too large");
	}

	result.size = FFS_HEADER_SIZE + body_size;
	result.data = allocate(result.size);
	memset(result.data, 0, result.size);
	memcpy(result.data, guid, 16);
	result.data[18] = type;
	result.data[19] = attributes;
	put24(result.data + 20, result.size);
	result.data[23] = 0;

	header_checksum = checksum8(result.data, FFS_HEADER_SIZE);
	result.data[16] = header_checksum;
	result.data[17] = FFS_FIXED_CHECKSUM;
	result.data[23] = FFS_STATE_VALID;
	memcpy(result.data + FFS_HEADER_SIZE, body, body_size);
	return result;
}

static struct fvpack_blob make_pad(size_t size, const uint8_t *extension)
{
	struct fvpack_blob result;
	uint8_t *body;

	if (size < FFS_HEADER_SIZE) {
		fail("padding file is smaller than an FFS header");
	}

	body = allocate(size - FFS_HEADER_SIZE);
	memset(body, 0xFF, size - FFS_HEADER_SIZE);
	if (extension != NULL) {
		if (size - FFS_HEADER_SIZE < FV_EXT_HEADER_SIZE) {
			fail("padding file cannot contain the FV extension header");
		}

		memcpy(body, extension, FV_EXT_HEADER_SIZE);
	}

	result = make_ffs(m_ffs_pad_guid, FFS_PAD_TYPE, 0, body, size - FFS_HEADER_SIZE);
	free(body);
	return result;
}

static bool guid_list_contains(const struct fvpack_guid_list *list, const uint8_t *guid)
{
	size_t index;

	for (index = 0; index < list->count; index++) {
		if (memcmp(list->items + (index * 16), guid, 16) == 0) {
			return true;
		}
	}

	return false;
}

static void append_guid(struct fvpack_guid_list *list, const char *text)
{
	uint8_t guid[16];
	uint8_t *items;

	parse_guid(text, guid);
	if (guid_list_contains(list, guid)) {
		fail("duplicate FFS removal GUID");
	}

	items = realloc(list->items, (list->count + 1) * 16);
	if (items == NULL) {
		fail("out of memory reading FFS removal GUIDs");
	}

	list->items = items;
	memcpy(list->items + (list->count * 16), guid, 16);
	list->count++;
}

static struct fvpack_blob prune_dxe_volume(const struct fvpack_blob *reference,
					   const struct fvpack_guid_list *remove)
{
	struct fvpack_blob result;
	struct fvpack_blob padding;
	bool *removed;
	size_t volume_size;
	size_t file_offset;
	size_t file_size;
	size_t remove_index;
	uint8_t file_type;
	bool has_dxe_core;

	if (remove->count == 0) {
		fail("DXE FV pruning requires at least one removal GUID");
	}

	file_offset = get_ffs_start_offset(reference);
	volume_size = (size_t)get64(reference->data + 0x20);
	result.size = volume_size;
	result.data = allocate(result.size);
	memcpy(result.data, reference->data, result.size);
	removed = calloc(remove->count, sizeof(*removed));
	if (removed == NULL) {
		fail("out of memory tracking FFS removals");
	}

	has_dxe_core = false;
	while (file_offset <= volume_size - FFS_HEADER_SIZE) {
		uint8_t *file;

		file = result.data + file_offset;
		if (is_erased(file, FFS_HEADER_SIZE)) {
			break;
		}

		file_size = get24(file + 20);
		file_type = file[18];
		if ((file_size < FFS_HEADER_SIZE) || (file_size > volume_size - file_offset)) {
			fail("DXE FV contains an invalid FFS file");
		}

		if (file_type == FFS_TYPE_DXE_CORE) {
			has_dxe_core = true;
		}

		for (remove_index = 0; remove_index < remove->count; remove_index++) {
			if (memcmp(file, remove->items + (remove_index * 16), 16) != 0) {
				continue;
			}

			if (removed[remove_index]) {
				fail("DXE FV contains a duplicate removal GUID");
			}

			if ((file_type == FFS_PAD_TYPE) || (file_type == FFS_TYPE_DXE_CORE)) {
				fail("refusing to remove a pad file or DXE core");
			}

			padding = make_pad(file_size, NULL);
			memcpy(file, padding.data, padding.size);
			free(padding.data);
			removed[remove_index] = true;
			break;
		}

		file_offset = align_up(file_offset + file_size, 8);
	}

	if (!has_dxe_core) {
		fail("DXE FV does not contain a DXE core");
	}

	for (remove_index = 0; remove_index < remove->count; remove_index++) {
		if (!removed[remove_index]) {
			fail("FFS removal GUID is not present in the DXE FV");
		}
	}

	free(removed);
	return result;
}

static size_t make_section_prefix(size_t file_offset, size_t section_alignment)
{
	size_t raw_section_size;

	raw_section_size = 4;
	while (((file_offset + FFS_HEADER_SIZE + raw_section_size + 4) % section_alignment) != 0) {
		raw_section_size += 4;
	}

	return raw_section_size;
}

static struct fvpack_blob
make_section_file(const uint8_t *guid, uint8_t type, uint8_t attributes, size_t file_offset,
		  size_t section_alignment, uint8_t section_type, const struct fvpack_blob *payload)
{
	struct fvpack_blob result;
	size_t raw_section_size;
	size_t body_size;
	uint8_t *body;

	raw_section_size = make_section_prefix(file_offset, section_alignment);

	body_size = raw_section_size + 4 + payload->size;
	body = allocate(body_size);
	memset(body, 0, body_size);
	put24(body, raw_section_size);
	body[3] = SECTION_TYPE_RAW;
	put24(body + raw_section_size, 4 + payload->size);
	body[raw_section_size + 3] = section_type;
	memcpy(body + raw_section_size + 4, payload->data, payload->size);

	result = make_ffs(guid, type, attributes, body, body_size);
	free(body);
	return result;
}

static size_t ffs_data_alignment(uint8_t attributes)
{
	static const size_t alignments[8] = {
		1U,
		16U,
		128U,
		512U,
		1024U,
		4096U,
		32768U,
		65536U,
	};
	static const size_t extended_alignments[8] = {
		128U * 1024U,
		256U * 1024U,
		512U * 1024U,
		1024U * 1024U,
		2U * 1024U * 1024U,
		4U * 1024U * 1024U,
		8U * 1024U * 1024U,
		16U * 1024U * 1024U,
	};
	size_t index;

	index = (attributes & FFS_ATTRIB_DATA_ALIGNMENT) >> 3;
	if ((attributes & FFS_ATTRIB_DATA_ALIGNMENT_2) != 0) {
		return extended_alignments[index];
	}

	return alignments[index];
}

static size_t placed_ffs_offset(size_t current_offset, const struct fvpack_blob *file)
{
	size_t alignment;
	size_t start;

	alignment = ffs_data_alignment(file->data[19]);
	start = align_up(current_offset + FFS_HEADER_SIZE, alignment) - FFS_HEADER_SIZE;
	if ((start > current_offset) && ((start - current_offset) < FFS_HEADER_SIZE)) {
		/*
		 * A pad FFS must contain a complete header. GenFv skips to the
		 * next aligned data slot when the first gap cannot hold one.
		 */
		start += alignment;
	}

	return start;
}

static size_t place_ffs(uint8_t *volume, size_t volume_size, size_t current_offset,
		       const struct fvpack_blob *file)
{
	size_t start;

	if (current_offset > volume_size) {
		fail("FFS file does not fit in the firmware volume");
	}

	start = placed_ffs_offset(current_offset, file);
	if (start > current_offset) {
		struct fvpack_blob padding;
		size_t padding_size;

		padding_size = start - current_offset;
		if (padding_size > volume_size - current_offset) {
			fail("FFS file does not fit in the firmware volume");
		}

		padding = make_pad(padding_size, NULL);
		memcpy(volume + current_offset, padding.data, padding.size);
		free(padding.data);
		current_offset = align_up(current_offset + padding_size, 8);
	}

	if ((current_offset != start) || (start > volume_size) ||
	    (file->size > volume_size - start)) {
		fail("FFS file does not fit in the firmware volume");
	}

	memcpy(volume + start, file->data, file->size);
	return align_up(start + file->size, 8);
}

static bool is_erased(const uint8_t *data, size_t size)
{
	size_t index;

	for (index = 0; index < size; index++) {
		if (data[index] != 0xFF) {
			return false;
		}
	}

	return true;
}

static size_t get_ffs_start_offset(const struct fvpack_blob *volume);

static struct fvpack_blob
pack_dxe_volume(const struct fvpack_blob *reference, const struct fvpack_ffs_inputs *inputs)
{
	struct fvpack_blob result;
	struct fvpack_ffs_input *input;
	size_t volume_size;
	size_t header_length;
	size_t extended_header_offset;
	size_t extended_header_size;
	size_t ffs_offset;
	size_t reference_offset;
	size_t current_offset;
	size_t file_size;
	uint8_t file_type;
	const uint8_t *reference_file;

	if (reference->size < FV_HEADER_SIZE) {
		fail("DXE FV reference is smaller than its header");
	}

	volume_size = (size_t)get64(reference->data + 0x20);
	header_length = get16(reference->data + 0x30);
	if ((volume_size < header_length) || (volume_size > reference->size) ||
	    (header_length < FV_HEADER_SIZE)) {
		fail("DXE FV reference has invalid volume bounds");
	}

	extended_header_offset = get16(reference->data + 0x34);
	if (extended_header_offset != 0) {
		if ((extended_header_offset < header_length) ||
		    (extended_header_offset > volume_size) ||
		    (volume_size - extended_header_offset < 20)) {
			fail("DXE FV reference has an invalid extended header offset");
		}

		extended_header_size = (size_t)get32(reference->data + extended_header_offset + 16);
		if ((extended_header_size < FV_EXT_HEADER_SIZE) ||
		    (extended_header_size > volume_size - extended_header_offset)) {
			fail("DXE FV reference has an invalid extended header size");
		}

		ffs_offset = align_up(extended_header_offset + extended_header_size, 8);
	} else {
		ffs_offset = align_up(header_length, 8);
	}

	if (ffs_offset > volume_size) {
		fail("DXE FV reference has no room after its headers");
	}

	result.size = volume_size;
	result.data = allocate(result.size);
	memset(result.data, 0xFF, result.size);
	memcpy(result.data, reference->data, ffs_offset);
	current_offset = ffs_offset;

	for (reference_offset = current_offset; reference_offset <= volume_size - FFS_HEADER_SIZE;
	     reference_offset = align_up(reference_offset + file_size, 8)) {
		reference_file = reference->data + reference_offset;
		if (is_erased(reference_file, FFS_HEADER_SIZE)) {
			break;
		}

		file_size = get24(reference_file + 20);
		file_type = reference_file[18];
		if ((file_size < FFS_HEADER_SIZE) || (file_size > volume_size - reference_offset)) {
			fail("DXE FV reference contains an invalid FFS file");
		}

		if (file_type == FFS_PAD_TYPE) {
			if (reference_offset != current_offset) {
				fail("DXE FV native cursor diverged at an FFS pad file");
			}

			memcpy(result.data + reference_offset, reference_file, file_size);
			current_offset = align_up(reference_offset + file_size, 8);
			continue;
		}

		input = find_ffs_input(inputs, reference_file);
		if ((input == NULL) || (input->file.size != file_size)) {
			fprintf(stderr,
				"cdk2-fvpack: DXE FV input mismatch: type=0x%02x size=0x%zx guid=",
				file_type, file_size);
			print_guid(reference_file);
			fputc('\n', stderr);
			if (input == NULL) {
				fail("DXE FV reference file is missing from the FFS input list");
			}

			fail("DXE FV FFS input size differs from the reference");
		}

		/*
		 * GenFfs leaves the state byte in the build-time state; GenFv
		 * commits it.
		 */
		input->used = true;
		input->file.data[23] = FFS_STATE_VALID;
		current_offset = place_ffs(result.data, result.size, current_offset, &input->file);
	}

	if (memcmp(result.data, reference->data, volume_size) != 0) {
		size_t difference;

		for (difference = 0; difference < volume_size; difference++) {
			if (result.data[difference] != reference->data[difference]) {
				fprintf(stderr,
					"cdk2-fvpack: first native DXE FV difference at 0x%zx: ",
					difference);
				fprintf(stderr, "native=0x%02x reference=0x%02x\n",
					result.data[difference], reference->data[difference]);
				break;
			}
		}
		fail("native DXE FV does not match the reference FV");
	}

	return result;
}

static struct fvpack_blob
pack_dxe_volume_from_manifest(const struct fvpack_blob *reference,
			      const struct fvpack_ffs_inputs *inputs)
{
	struct fvpack_blob result;
	size_t volume_size;
	size_t ffs_offset;
	size_t current_offset;
	size_t file_offset;
	size_t index;
	bool found_dxe_core;

	if ((inputs == NULL) || !inputs->ordered || (inputs->count == 0)) {
		fail("DXE FV manifest is not ordered");
	}

	ffs_offset = get_ffs_start_offset(reference);
	volume_size = (size_t)get64(reference->data + 0x20);

	result.size = volume_size;
	result.data = allocate(result.size);
	memset(result.data, 0xFF, result.size);
	memcpy(result.data, reference->data, ffs_offset);

	current_offset = ffs_offset;
	found_dxe_core = false;
	for (index = 0; index < inputs->count; index++) {
		struct fvpack_ffs_input *input;

		input = &inputs->items[index];
		if (input->file.data[18] == FFS_PAD_TYPE) {
			fail("DXE FV manifest must not contain pad FFS files");
		}

		file_offset = placed_ffs_offset(current_offset, &input->file);
		if (input->has_reference_offset) {
			if (input->reference_offset < ffs_offset) {
				fail("DXE FV manifest file offset is before the file area");
			}

			if (input->reference_offset != file_offset) {
				fprintf(stderr,
					"cdk2-fvpack: DXE FV manifest offset mismatch: manifest=0x%zx actual=0x%zx guid=",
					input->reference_offset, file_offset);
				print_guid(input->file.data);
				fputc('\n', stderr);
				fail("DXE FV manifest file offset does not match the reference");
			}
		}

		input->used = true;
		input->file.data[23] = FFS_STATE_VALID;
		current_offset = place_ffs(result.data, result.size, current_offset, &input->file);
		found_dxe_core = found_dxe_core || (input->file.data[18] == FFS_TYPE_DXE_CORE);
	}

	if (!found_dxe_core) {
		fail("DXE FV manifest does not contain a DXE core");
	}

	if (memcmp(result.data, reference->data, volume_size) != 0) {
		size_t difference;

		for (difference = 0; difference < volume_size; difference++) {
			if (result.data[difference] != reference->data[difference]) {
				fprintf(stderr,
					"cdk2-fvpack: first manifest DXE FV difference at 0x%zx: ",
					difference);
				fprintf(stderr, "native=0x%02x reference=0x%02x\n",
					result.data[difference], reference->data[difference]);
				break;
			}
		}

		fail("manifest DXE FV does not match the reference FV");
	}

	return result;
}

static size_t get_ffs_start_offset(const struct fvpack_blob *volume)
{
	size_t volume_length;
	size_t header_length;
	size_t extended_header_offset;
	size_t extended_header_size;
	size_t ffs_offset;

	if (volume->size < FV_HEADER_SIZE) {
		fail("firmware volume is smaller than its header");
	}

	volume_length = (size_t)get64(volume->data + 0x20);
	header_length = (size_t)get16(volume->data + 0x30);
	if ((volume_length < header_length) || (volume_length > volume->size) ||
	    (header_length < FV_HEADER_SIZE)) {
		fail("firmware volume has invalid bounds");
	}

	extended_header_offset = (size_t)get16(volume->data + 0x34);
	if (extended_header_offset == 0) {
		ffs_offset = align_up(header_length, 8);
	} else {
		if ((extended_header_offset < header_length) ||
		    (extended_header_offset > volume_length) ||
		    (volume_length - extended_header_offset < FV_EXT_HEADER_SIZE)) {
			fail("firmware volume has an invalid extended header offset");
		}

		extended_header_size = (size_t)get32(volume->data + extended_header_offset + 16);
		if ((extended_header_size < FV_EXT_HEADER_SIZE) ||
		    (extended_header_size > volume_length - extended_header_offset)) {
			fail("firmware volume has an invalid extended header size");
		}

		ffs_offset = align_up(extended_header_offset + extended_header_size, 8);
	}

	if (ffs_offset > volume_length) {
		fail("firmware volume has no room after its headers");
	}

	return ffs_offset;
}

static size_t
place_flat_dxe_manifest(uint8_t *volume, size_t volume_size, size_t current_offset,
			const struct fvpack_ffs_inputs *dxe_inputs)
{
	size_t index;
	bool found_dxe_core;

	if ((dxe_inputs == NULL) || !dxe_inputs->ordered || (dxe_inputs->count == 0)) {
		fail("flat DXE FV requires an ordered FFS manifest");
	}

	found_dxe_core = false;
	for (index = 0; index < dxe_inputs->count; index++) {
		struct fvpack_ffs_input *input;

		input = &dxe_inputs->items[index];
		if (input->file.data[18] == FFS_PAD_TYPE) {
			fail("flat DXE FV manifest must not contain pad FFS files");
		}

		input->used = true;
		input->file.data[23] = FFS_STATE_VALID;
		current_offset = place_ffs(volume, volume_size, current_offset, &input->file);
		found_dxe_core = found_dxe_core || (input->file.data[18] == FFS_TYPE_DXE_CORE);
	}

	if (!found_dxe_core) {
		fail("flat DXE FV manifest does not contain a DXE core");
	}

	return current_offset;
}

static struct fvpack_blob
pack_payload(struct fvpack_blob *payload_entry, const struct fvpack_blob *dxe_volume,
	     const struct fvpack_ffs_inputs *dxe_inputs, bool flatten_dxe, size_t volume_size)
{
	struct fvpack_blob result;
	struct fvpack_blob entry_file;
	struct fvpack_blob dxe_file;
	struct fvpack_ffs_input *input;
	size_t current_offset;
	size_t entry_offset;
	size_t entry_prefix_size;
	size_t dxe_ffs_offset;
	size_t reference_offset;
	size_t file_size;
	uint8_t file_type;
	bool found_dxe_core;
	uint8_t extension_data[FV_EXT_HEADER_SIZE];

	if (volume_size < FV_HEADER_SIZE) {
		fail("firmware volume is smaller than its header");
	}

	result.size = volume_size;
	result.data = allocate(result.size);
	memset(result.data, 0xFF, result.size);
	memset(result.data, 0, FV_HEADER_SIZE);
	memcpy(result.data + 0x10, m_file_system_guid, sizeof(m_file_system_guid));
	put64(result.data + 0x20, volume_size);
	memcpy(result.data + 0x28, "_FVH", 4);
	put32(result.data + 0x2C, 0x0007FEFFU);
	put16(result.data + 0x30, FV_HEADER_SIZE);
	put16(result.data + 0x32, 0);
	put16(result.data + 0x34, FV_EXT_HEADER_OFFSET);
	result.data[0x36] = 0;
	result.data[0x37] = 2;
	put32(result.data + 0x38, (uint32_t)(volume_size / 0x1000U));
	put32(result.data + 0x3C, 0x1000U);
	put32(result.data + 0x40, 0);
	put32(result.data + 0x44, 0);
	put16(result.data + 0x32, checksum16(result.data, FV_HEADER_SIZE));

	memcpy(extension_data, m_volume_name_guid, sizeof(m_volume_name_guid));
	put32(extension_data + 16, FV_EXT_HEADER_SIZE);
	current_offset = FV_HEADER_SIZE;
	{
		struct fvpack_blob padding;

		padding = make_pad(FV_EXT_HEADER_OFFSET + FV_EXT_HEADER_SIZE - FV_HEADER_SIZE,
				  extension_data);
		if (current_offset > result.size || padding.size > result.size - current_offset) {
			fail("firmware volume is too small for its extension header");
		}

		memcpy(result.data + current_offset, padding.data, padding.size);
		free(padding.data);
		current_offset = align_up(current_offset + padding.size, 8);
	}

	entry_offset = align_up(current_offset + FFS_HEADER_SIZE, 128) - FFS_HEADER_SIZE;
	entry_prefix_size = make_section_prefix(entry_offset, 32);
	relocate_pe(payload_entry, FV_BASE_ADDRESS + (uint64_t)(entry_offset + FFS_HEADER_SIZE +
							      entry_prefix_size + 4));

	entry_file = make_section_file(m_payload_entry_guid, FFS_TYPE_SECURITY_CORE,
				    FFS_ATTRIB_DATA_ALIGNMENT_128, entry_offset, 32,
				    SECTION_TYPE_PE32, payload_entry);
	current_offset = place_ffs(result.data, result.size, current_offset, &entry_file);
	free(entry_file.data);

	if (!flatten_dxe) {
		if (dxe_volume == NULL) {
			fail("nested DXE FV requires a DXE FV input");
		}

		dxe_file = make_section_file(
			m_dxe_volume_file_guid, FFS_TYPE_FV_IMAGE, FFS_ATTRIB_DATA_ALIGNMENT_16,
			align_up(current_offset + FFS_HEADER_SIZE, 16) - FFS_HEADER_SIZE, 16,
			SECTION_TYPE_FV_IMAGE, dxe_volume);
		current_offset = place_ffs(result.data, result.size, current_offset, &dxe_file);
		free(dxe_file.data);
	} else {
		if ((dxe_inputs != NULL) && dxe_inputs->ordered) {
			current_offset = place_flat_dxe_manifest(result.data, result.size,
							     current_offset, dxe_inputs);
			goto finish_payload;
		}

		if (dxe_inputs == NULL || dxe_inputs->count == 0) {
			fail("flat DXE FV requires an FFS input list");
		}

		if (dxe_volume == NULL) {
			fail("flat DXE FV input list requires a DXE FV reference");
		}

		dxe_ffs_offset = get_ffs_start_offset(dxe_volume);

		found_dxe_core = false;
		for (reference_offset = dxe_ffs_offset;
		     reference_offset <= dxe_volume->size - FFS_HEADER_SIZE;
		     reference_offset = align_up(reference_offset + file_size, 8)) {
			const uint8_t *reference_file;

			reference_file = dxe_volume->data + reference_offset;
			if (is_erased(reference_file, FFS_HEADER_SIZE)) {
				break;
			}

			file_size = get24(reference_file + 20);
			file_type = reference_file[18];
			if ((file_size < FFS_HEADER_SIZE) ||
			    (file_size > dxe_volume->size - reference_offset)) {
				fail("flat DXE FV contains an invalid FFS file");
			}

			if (file_type == FFS_PAD_TYPE) {
				continue;
			}

			input = find_ffs_input(dxe_inputs, reference_file);
			if ((input == NULL) || (input->file.size != file_size)) {
				fail("flat DXE FV input does not match the reference");
			}

			input->used = true;
			input->file.data[23] = FFS_STATE_VALID;
			current_offset =
				place_ffs(result.data, result.size, current_offset, &input->file);
			found_dxe_core = found_dxe_core || (file_type == FFS_TYPE_DXE_CORE);
		}

		if (!found_dxe_core) {
			fail("flat DXE FV does not contain a DXE core");
		}
	}

finish_payload:
	/*
	 * The requested volume size is a build-time upper bound. Keeping the
	 * unused tail in the linked image makes an otherwise small payload
	 * exceed coreboot's CBFS slot, and it needlessly mirrors erased bytes.
	 * Emit only the used FFS range, aligned to the FV block size, and make
	 * the header describe the compact volume.
	 */
	{
		size_t compact_size;

		compact_size = align_up(current_offset, 0x1000U);
		if (compact_size > result.size) {
			fail("packed firmware volume exceeds the configured maximum size");
		}

		put64(result.data + 0x20, compact_size);
		put32(result.data + 0x38, (uint32_t)(compact_size / 0x1000U));
		put16(result.data + 0x32, 0);
		put16(result.data + 0x32, checksum16(result.data, FV_HEADER_SIZE));
		result.size = compact_size;
	}

	fprintf(stdout, "cdk2 native FV%s: used=0x%zx free=0x%zx\n",
		flatten_dxe ? " (flat)" : "", current_offset, result.size - current_offset);
	return result;
}

static void print_usage(const char *program)
{
	fprintf(stderr, "usage: %s --output FILE --entry-efi FILE ", program);
	fputs("(--dxe-manifest FILE --flatten-dxe | --dxe-fv FILE ", stderr);
	fputs("[--dxe-ffs-list FILE] [--flatten-dxe]) [--size BYTES]\n", stderr);
	fprintf(stderr, "       %s --verify-dxe-manifest --dxe-manifest FILE ", program);
	fputs("--reference-dxe-fv FILE\n", stderr);
	fprintf(stderr, "       %s --prune-dxe-fv --dxe-fv FILE --output FILE ", program);
	fputs("--remove-guid GUID [--remove-guid GUID ...]\n", stderr);
}

int main(int argc, char **argv)
{
	const char *output_path;
	const char *entry_path;
	const char *dxe_path;
	const char *dxe_ffs_list_path;
	const char *dxe_manifest_path;
	const char *reference_dxe_path;
	bool flatten_dxe;
	bool verify_dxe_manifest;
	bool prune_dxe_fv;
	size_t volume_size;
	int index;
	struct fvpack_blob entry;
	struct fvpack_blob dxe;
	struct fvpack_blob volume;
	struct fvpack_ffs_inputs dxe_inputs;
	struct fvpack_guid_list remove_guids;

	output_path = NULL;
	entry_path = NULL;
	dxe_path = NULL;
	dxe_ffs_list_path = NULL;
	dxe_manifest_path = NULL;
	reference_dxe_path = NULL;
	flatten_dxe = false;
	verify_dxe_manifest = false;
	prune_dxe_fv = false;
	volume_size = FV_SIZE_DEFAULT;
	entry.data = NULL;
	entry.size = 0;
	dxe.data = NULL;
	dxe.size = 0;
	volume.data = NULL;
	volume.size = 0;
	dxe_inputs.items = NULL;
	dxe_inputs.count = 0;
	dxe_inputs.ordered = false;
	remove_guids.items = NULL;
	remove_guids.count = 0;
	for (index = 1; index < argc; index++) {
		if ((strcmp(argv[index], "--output") == 0) && (index + 1 < argc)) {
			output_path = argv[++index];
		} else if ((strcmp(argv[index], "--entry-efi") == 0) && (index + 1 < argc)) {
			entry_path = argv[++index];
		} else if ((strcmp(argv[index], "--dxe-fv") == 0) && (index + 1 < argc)) {
			dxe_path = argv[++index];
		} else if ((strcmp(argv[index], "--dxe-ffs-list") == 0) && (index + 1 < argc)) {
			dxe_ffs_list_path = argv[++index];
		} else if ((strcmp(argv[index], "--dxe-manifest") == 0) && (index + 1 < argc)) {
			dxe_manifest_path = argv[++index];
		} else if ((strcmp(argv[index], "--reference-dxe-fv") == 0) &&
			   (index + 1 < argc)) {
			reference_dxe_path = argv[++index];
		} else if (strcmp(argv[index], "--verify-dxe-manifest") == 0) {
			verify_dxe_manifest = true;
		} else if (strcmp(argv[index], "--prune-dxe-fv") == 0) {
			prune_dxe_fv = true;
		} else if ((strcmp(argv[index], "--remove-guid") == 0) &&
			   (index + 1 < argc)) {
			append_guid(&remove_guids, argv[++index]);
		} else if (strcmp(argv[index], "--flatten-dxe") == 0) {
			flatten_dxe = true;
		} else if ((strcmp(argv[index], "--size") == 0) && (index + 1 < argc)) {
			char *end;

			volume_size = (size_t)strtoull(argv[++index], &end, 0);
			if ((*end != '\0') || (volume_size == 0)) {
				print_usage(argv[0]);
				return EXIT_FAILURE;
			}
		} else {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if ((dxe_manifest_path != NULL) && (dxe_ffs_list_path != NULL)) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (prune_dxe_fv) {
		struct fvpack_blob pruned_dxe;

		if ((output_path == NULL) || (dxe_path == NULL) || (entry_path != NULL) ||
		    (dxe_manifest_path != NULL) || (dxe_ffs_list_path != NULL) || flatten_dxe ||
		    verify_dxe_manifest) {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}

		dxe = read_file(dxe_path);
		pruned_dxe = prune_dxe_volume(&dxe, &remove_guids);
		write_file(output_path, pruned_dxe.data, pruned_dxe.size);
		free(pruned_dxe.data);
		free(dxe.data);
		free(remove_guids.items);
		return EXIT_SUCCESS;
	}

	if (remove_guids.count != 0) {
		print_usage(argv[0]);
		free(remove_guids.items);
		return EXIT_FAILURE;
	}

	if (verify_dxe_manifest) {
		struct fvpack_blob native_dxe;

		if ((dxe_manifest_path == NULL) || (reference_dxe_path == NULL)) {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}

		read_ffs_manifest(dxe_manifest_path, &dxe_inputs);
		dxe = read_file(reference_dxe_path);
		native_dxe = pack_dxe_volume_from_manifest(&dxe, &dxe_inputs);
		verify_all_ffs_inputs_used(&dxe_inputs);
		free(native_dxe.data);
		free(dxe.data);
		free_ffs_inputs(&dxe_inputs);
		return EXIT_SUCCESS;
	}

	if ((output_path == NULL) || (entry_path == NULL) || (!flatten_dxe && (dxe_path == NULL)) ||
	    (flatten_dxe && (dxe_manifest_path == NULL) &&
	     ((dxe_path == NULL) || (dxe_ffs_list_path == NULL)))) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	entry = read_file(entry_path);
	if (dxe_manifest_path != NULL) {
		read_ffs_manifest(dxe_manifest_path, &dxe_inputs);
	} else if (dxe_ffs_list_path != NULL) {
		dxe = read_file(dxe_path);
		read_ffs_list(dxe_ffs_list_path, &dxe_inputs);
		{
			struct fvpack_blob native_dxe;

			native_dxe = pack_dxe_volume(&dxe, &dxe_inputs);
			verify_all_ffs_inputs_used(&dxe_inputs);
			free(dxe.data);
			dxe = native_dxe;
		}
	} else if (dxe_path != NULL) {
		dxe = read_file(dxe_path);
	}

	volume = pack_payload(&entry, dxe.data == NULL ? NULL : &dxe, &dxe_inputs, flatten_dxe,
			     volume_size);
	if (dxe_manifest_path != NULL) {
		verify_all_ffs_inputs_used(&dxe_inputs);
	}

	write_file(output_path, volume.data, volume.size);
	free(entry.data);
	free(dxe.data);
	free(volume.data);
	free_ffs_inputs(&dxe_inputs);
	free(remove_guids.items);
	return EXIT_SUCCESS;
}
