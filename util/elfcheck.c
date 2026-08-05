/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host checks for the native cdk2 ELF layout contract.
 */

#include <errno.h>
#include <elf.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define CDK2_LINK_BASE                    0x00100000ULL
#define CDK2_MODULE_ENTRY_SIZE            16ULL
#define CDK2_FV_ALIGNMENT                 128ULL
#define CDK2_ENTRY32_PAGE_SIZE            0x1000ULL
#define CDK2_ENTRY32_ONE_GIB              0x40000000ULL
#define CDK2_ENTRY32_MAP_TOP              0x2000000000ULL
#define CDK2_ENTRY32_BOOT_STACK_SIZE      0x8000ULL
#define CDK2_ENTRY32_BOOT_STACK_ALIGNMENT 16ULL
#define CDK2_STARBOOK_RAM_END             0x1080000000ULL

struct elf_image {
	uint8_t *data;
	size_t size;
	Elf64_Ehdr header_storage;
	const Elf64_Ehdr *header;
	Elf64_Phdr *program_headers;
	Elf64_Shdr *section_headers;
	const char *section_strings;
	size_t section_strings_size;
};

struct elf_symbol {
	uint64_t value;
	uint64_t size;
	uint16_t section_index;
};

static void fail(const char *format, ...)
{
	va_list args;

	fprintf(stderr, "cdk2-elfcheck: ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

static bool range_in_file(uint64_t offset, uint64_t size, size_t file_size)
{
	return (offset <= (uint64_t)file_size) && (size <= (uint64_t)file_size - offset);
}

static bool range_contains(uint64_t container_base, uint64_t container_size, uint64_t address,
			  uint64_t size)
{
	return (address >= container_base) && (size <= container_size) &&
	       (address - container_base <= container_size - size);
}

static uint64_t checked_table_size(uint64_t count, uint64_t entry_size)
{
	if ((entry_size != 0) && (count > UINT64_MAX / entry_size)) {
		fail("ELF table size overflows");
	}

	return count * entry_size;
}

static size_t checked_host_size(uint64_t size, const char *description)
{
	if (size > SIZE_MAX) {
		fail("%s is too large for this host", description);
	}

	return (size_t)size;
}

static bool is_power_of_two(uint64_t value)
{
	return (value != 0) && ((value & (value - 1U)) == 0);
}

static uint64_t section_span(const Elf64_Shdr *section)
{
	return (section->sh_size == 0) ? 1 : section->sh_size;
}

static const char *checked_string(const char *table, size_t table_size, uint32_t offset,
				 const char *description)
{
	const char *string;

	if (offset >= table_size) {
		fail("%s string offset is outside its table", description);
	}

	string = table + offset;
	if (memchr(string, '\0', table_size - offset) == NULL) {
		fail("%s string is not nul-terminated", description);
	}

	return string;
}

static const char *section_name(const struct elf_image *image, const Elf64_Shdr *section)
{
	return checked_string(image->section_strings, image->section_strings_size, section->sh_name,
			     "section");
}

static uint8_t *read_file(const char *path, size_t *size)
{
	FILE *file;
	long length;
	uint8_t *data;
	size_t allocation_size;

	file = fopen(path, "rb");
	if (file == NULL) {
		fail("cannot open %s: %s", path, strerror(errno));
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fail("cannot seek %s", path);
	}

	length = ftell(file);
	if (length < 0) {
		fail("cannot determine size of %s", path);
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		fail("cannot rewind %s", path);
	}

	allocation_size = (size_t)length;
	if (allocation_size < sizeof(Elf64_Ehdr)) {
		allocation_size = sizeof(Elf64_Ehdr);
	}

	data = malloc(allocation_size);
	if (data == NULL) {
		fail("out of memory");
	}

	if (fread(data, 1, (size_t)length, file) != (size_t)length) {
		fail("cannot read %s", path);
	}

	fclose(file);
	*size = (size_t)length;
	return data;
}

static void open_elf(struct elf_image *image, const char *path)
{
	uint64_t program_header_size;
	uint64_t section_header_size;
	size_t program_header_bytes;
	size_t section_header_bytes;
	const Elf64_Shdr *section_strings;

	memset(image, 0, sizeof(*image));
	image->data = read_file(path, &image->size);
	if (image->size < sizeof(Elf64_Ehdr)) {
		fail("%s is smaller than an ELF header", path);
	}

	memcpy(&image->header_storage, image->data, sizeof(image->header_storage));
	image->header = &image->header_storage;
	if (image->header->e_ident[EI_MAG0] != ELFMAG0 ||
	    image->header->e_ident[EI_MAG1] != ELFMAG1 ||
	    image->header->e_ident[EI_MAG2] != ELFMAG2 ||
	    image->header->e_ident[EI_MAG3] != ELFMAG3 ||
	    image->header->e_ident[EI_CLASS] != ELFCLASS64 ||
	    image->header->e_ident[EI_DATA] != ELFDATA2LSB ||
	    image->header->e_ident[EI_VERSION] != EV_CURRENT) {
		fail("%s is not an ELF64 little-endian image", path);
	}

	if (image->header->e_type != ET_EXEC || image->header->e_machine != EM_X86_64 ||
	    image->header->e_version != EV_CURRENT ||
	    image->header->e_ehsize != sizeof(Elf64_Ehdr) ||
	    image->header->e_phentsize != sizeof(Elf64_Phdr) ||
	    image->header->e_shentsize != sizeof(Elf64_Shdr) || image->header->e_phnum == 0 ||
	    image->header->e_shnum == 0 || image->header->e_shstrndx == SHN_UNDEF ||
	    image->header->e_shstrndx >= image->header->e_shnum) {
		fail("%s has an unsupported ELF header", path);
	}

	program_header_size = checked_table_size(image->header->e_phnum, sizeof(Elf64_Phdr));
	section_header_size = checked_table_size(image->header->e_shnum, sizeof(Elf64_Shdr));
	if (!range_in_file(image->header->e_phoff, program_header_size, image->size) ||
	    !range_in_file(image->header->e_shoff, section_header_size, image->size)) {
		fail("%s has an ELF table outside the file", path);
	}

	program_header_bytes = checked_host_size(program_header_size, "program header table");
	section_header_bytes = checked_host_size(section_header_size, "section header table");
	image->program_headers = malloc(program_header_bytes);
	image->section_headers = malloc(section_header_bytes);
	if (image->program_headers == NULL || image->section_headers == NULL) {
		fail("out of memory");
	}

	memcpy(image->program_headers, image->data + image->header->e_phoff, program_header_bytes);
	memcpy(image->section_headers, image->data + image->header->e_shoff, section_header_bytes);
	section_strings = &image->section_headers[image->header->e_shstrndx];
	if (!range_in_file(section_strings->sh_offset, section_strings->sh_size, image->size)) {
		fail("%s has an invalid section string table", path);
	}

	image->section_strings = (const char *)image->data + section_strings->sh_offset;
	image->section_strings_size = (size_t)section_strings->sh_size;
}

static const Elf64_Shdr *find_section(const struct elf_image *image, const char *name)
{
	uint16_t index;

	for (index = 0; index < image->header->e_shnum; index++) {
		if (strcmp(section_name(image, &image->section_headers[index]), name) == 0) {
			return &image->section_headers[index];
		}
	}

	return NULL;
}

static const Elf64_Shdr *require_section(const struct elf_image *image, const char *name)
{
	const Elf64_Shdr *section;

	section = find_section(image, name);
	if (section == NULL) {
		fail("missing section %s", name);
	}

	return section;
}

static const Elf64_Phdr *find_load_segment(const struct elf_image *image, uint64_t address,
					 uint64_t size)
{
	uint16_t index;
	const Elf64_Phdr *program_header;

	for (index = 0; index < image->header->e_phnum; index++) {
		program_header = &image->program_headers[index];
		if (program_header->p_type != PT_LOAD) {
			continue;
		}

		if (range_contains(program_header->p_vaddr, program_header->p_memsz, address,
				  size)) {
			return program_header;
		}
	}

	return NULL;
}

static void check_section_placement(const struct elf_image *image, const Elf64_Shdr *section,
				  const char *name, bool expect_executable, bool expect_writable)
{
	const Elf64_Phdr *load;
	uint64_t span;

	if ((section->sh_flags & SHF_ALLOC) == 0) {
		fail("%s is not allocated", name);
	}

	if (expect_executable != ((section->sh_flags & SHF_EXECINSTR) != 0)) {
		fail("%s has unexpected executable section flags", name);
	}

	if (expect_writable != ((section->sh_flags & SHF_WRITE) != 0)) {
		fail("%s has unexpected writable section flags", name);
	}

	span = section_span(section);
	load = find_load_segment(image, section->sh_addr, span);
	if (load == NULL) {
		fail("%s is not covered by a PT_LOAD segment", name);
	}

	if ((load->p_flags & PF_R) == 0) {
		fail("%s load segment is not readable", name);
	}

	if (expect_executable != ((load->p_flags & PF_X) != 0)) {
		fail("%s has unexpected executable load flags", name);
	}

	if (expect_writable != ((load->p_flags & PF_W) != 0)) {
		fail("%s has unexpected writable load flags", name);
	}
}

static void check_section_image_bounds(const Elf64_Shdr *section, const char *name,
				    uint64_t image_start, uint64_t image_size)
{
	if (!range_contains(image_start, image_size, section->sh_addr, section_span(section))) {
		fail("%s is outside native image bounds", name);
	}
}

static bool find_symbol(const struct elf_image *image, const char *name, struct elf_symbol *symbol)
{
	uint16_t section_index;
	uint64_t symbol_count;
	uint64_t symbol_index;
	const Elf64_Shdr *symtab;
	const Elf64_Shdr *strtab;
	Elf64_Sym symbol_entry;
	const char *strings;
	const char *symbol_name;
	uint64_t symbol_offset;

	for (section_index = 0; section_index < image->header->e_shnum; section_index++) {
		symtab = &image->section_headers[section_index];
		if (symtab->sh_type != SHT_SYMTAB) {
			continue;
		}

		if (symtab->sh_entsize != sizeof(Elf64_Sym) ||
		    (symtab->sh_size % sizeof(Elf64_Sym)) != 0 ||
		    symtab->sh_link >= image->header->e_shnum ||
		    !range_in_file(symtab->sh_offset, symtab->sh_size, image->size)) {
			fail("invalid ELF symbol table");
		}

		strtab = &image->section_headers[symtab->sh_link];
		if (!range_in_file(strtab->sh_offset, strtab->sh_size, image->size)) {
			fail("invalid ELF symbol string table");
		}

		strings = (const char *)image->data + strtab->sh_offset;
		symbol_count = symtab->sh_size / sizeof(Elf64_Sym);
		for (symbol_index = 0; symbol_index < symbol_count; symbol_index++) {
			symbol_offset = symtab->sh_offset + symbol_index * sizeof(symbol_entry);
			memcpy(&symbol_entry, image->data + symbol_offset, sizeof(symbol_entry));
			if (symbol_entry.st_name == 0) {
				continue;
			}

			symbol_name = checked_string(strings, (size_t)strtab->sh_size,
						   symbol_entry.st_name, "symbol");
			if (strcmp(symbol_name, name) == 0) {
				symbol->value = symbol_entry.st_value;
				symbol->size = symbol_entry.st_size;
				symbol->section_index = symbol_entry.st_shndx;
				return true;
			}
		}
	}

	return false;
}

static struct elf_symbol require_symbol(const struct elf_image *image, const char *name)
{
	struct elf_symbol symbol;

	if (!find_symbol(image, name, &symbol)) {
		fail("missing symbol %s", name);
	}

	return symbol;
}

static void check_entry32_bss_object(const struct elf_image *image, const Elf64_Shdr *bss,
				  const struct elf_symbol *symbol, const char *name, uint64_t size,
				  uint64_t alignment)
{
	uint16_t bss_index;

	bss_index = (uint16_t)(bss - image->section_headers);
	if (symbol->section_index != bss_index) {
		fail("%s is not in .bss", name);
	}

	if (symbol->size != size) {
		fail("%s has unexpected size", name);
	}

	if ((symbol->value & (alignment - 1U)) != 0) {
		fail("%s does not meet the required alignment", name);
	}

	if (symbol->value < bss->sh_addr || size > bss->sh_size ||
	    symbol->value - bss->sh_addr > bss->sh_size - size) {
		fail("%s is outside .bss bounds", name);
	}
}

static void check_coreboot_entry32_paging_contract(const struct elf_image *image)
{
	const Elf64_Shdr *bss;
	struct elf_symbol pml4;
	struct elf_symbol pdpt;
	struct elf_symbol pd;
	struct elf_symbol boot_stack;
	struct elf_symbol boot_stack_top;
	struct elf_symbol boot_stack_size;
	struct elf_symbol map_top;
	struct elf_symbol page_directory_count;
	uint64_t expected_page_directory_count;
	uint64_t expected_page_directory_bytes;
	uint64_t table_end;

	bss = require_section(image, ".bss");
	pml4 = require_symbol(image, "cdk2_pml4");
	pdpt = require_symbol(image, "cdk2_pdpt");
	pd = require_symbol(image, "cdk2_pd");
	boot_stack = require_symbol(image, "cdk2_boot_stack");
	boot_stack_top = require_symbol(image, "cdk2_boot_stack_top");
	boot_stack_size = require_symbol(image, "cdk2_entry32_boot_stack_size");
	map_top = require_symbol(image, "cdk2_entry32_identity_map_top");
	page_directory_count = require_symbol(image, "cdk2_entry32_page_directory_count");

	if (map_top.value != CDK2_ENTRY32_MAP_TOP || map_top.value < CDK2_STARBOOK_RAM_END ||
	    (map_top.value % CDK2_ENTRY32_ONE_GIB) != 0) {
		fail("entry32 identity-map top does not cover the high-memory contract");
	}

	expected_page_directory_count = map_top.value / CDK2_ENTRY32_ONE_GIB;
	if (page_directory_count.value != expected_page_directory_count ||
	    page_directory_count.value == 0 ||
	    page_directory_count.value > UINT64_MAX / CDK2_ENTRY32_PAGE_SIZE) {
		fail("entry32 page-directory count does not match the map top");
	}

	expected_page_directory_bytes = page_directory_count.value * CDK2_ENTRY32_PAGE_SIZE;
	check_entry32_bss_object(image, bss, &pml4, "cdk2_pml4", CDK2_ENTRY32_PAGE_SIZE,
			      CDK2_ENTRY32_PAGE_SIZE);
	check_entry32_bss_object(image, bss, &pdpt, "cdk2_pdpt", CDK2_ENTRY32_PAGE_SIZE,
			      CDK2_ENTRY32_PAGE_SIZE);
	check_entry32_bss_object(image, bss, &pd, "cdk2_pd", expected_page_directory_bytes,
			      CDK2_ENTRY32_PAGE_SIZE);

	if (boot_stack_size.value != CDK2_ENTRY32_BOOT_STACK_SIZE) {
		fail("entry32 boot stack size does not match the handoff contract");
	}

	check_entry32_bss_object(image, bss, &boot_stack, "cdk2_boot_stack", boot_stack_size.value,
			      CDK2_ENTRY32_BOOT_STACK_ALIGNMENT);

	if (pdpt.value != pml4.value + CDK2_ENTRY32_PAGE_SIZE ||
	    pd.value != pdpt.value + CDK2_ENTRY32_PAGE_SIZE) {
		fail("entry32 page-table storage is not contiguous");
	}

	table_end = pd.value + pd.size;
	if (table_end < pd.value || table_end > 0x100000000ULL) {
		fail("entry32 page-table storage is not 32-bit addressable");
	}

	if (boot_stack.value < table_end) {
		fail("entry32 boot stack overlaps page-table storage");
	}

	if (boot_stack_top.section_index != (uint16_t)(bss - image->section_headers) ||
	    (boot_stack_top.value & (CDK2_ENTRY32_BOOT_STACK_ALIGNMENT - 1U)) != 0 ||
	    boot_stack_top.value != boot_stack.value + boot_stack_size.value) {
		fail("entry32 boot stack top does not match the handoff contract");
	}
}

static void check_load_segments(const struct elf_image *image)
{
	uint16_t index;
	uint16_t previous_index;
	const Elf64_Phdr *program_header;
	const Elf64_Phdr *previous_header;
	uint64_t segment_end;
	uint64_t previous_end;
	bool has_executable;
	bool has_read_only;
	bool has_writable;

	has_executable = false;
	has_read_only = false;
	has_writable = false;
	for (index = 0; index < image->header->e_phnum; index++) {
		program_header = &image->program_headers[index];
		if (program_header->p_type != PT_LOAD) {
			continue;
		}

		if ((program_header->p_flags & PF_R) == 0) {
			fail("PT_LOAD segment is not readable");
		}

		if ((program_header->p_flags & PF_W) != 0 &&
		    (program_header->p_flags & PF_X) != 0) {
			fail("PT_LOAD segment is both writable and executable");
		}

		if (program_header->p_filesz > program_header->p_memsz ||
		    !range_in_file(program_header->p_offset, program_header->p_filesz,
				 image->size) ||
		    program_header->p_memsz > UINT64_MAX - program_header->p_vaddr ||
		    program_header->p_vaddr != program_header->p_paddr ||
		    program_header->p_align < 0x1000 || !is_power_of_two(program_header->p_align) ||
		    ((program_header->p_vaddr - program_header->p_offset) &
		     (program_header->p_align - 1U)) != 0) {
			fail("PT_LOAD segment has invalid bounds or alignment");
		}

		segment_end = program_header->p_vaddr + program_header->p_memsz;
		for (previous_index = 0; previous_index < index; previous_index++) {
			previous_header = &image->program_headers[previous_index];
			if (previous_header->p_type != PT_LOAD || program_header->p_memsz == 0 ||
			    previous_header->p_memsz == 0) {
				continue;
			}

			previous_end = previous_header->p_vaddr + previous_header->p_memsz;
			if ((program_header->p_vaddr < previous_end) &&
			    (previous_header->p_vaddr < segment_end)) {
				fail("PT_LOAD segments overlap");
			}
		}

		has_executable = has_executable || ((program_header->p_flags & PF_X) != 0);
		has_read_only = has_read_only || ((program_header->p_flags & (PF_W | PF_X)) == 0);
		has_writable = has_writable || ((program_header->p_flags & PF_W) != 0);
	}

	if (!has_executable || !has_read_only || !has_writable) {
		fail("ELF must have executable, read-only, and writable PT_LOAD segments");
	}
}

static void check_section_file_bounds(const struct elf_image *image)
{
	uint16_t index;
	const Elf64_Shdr *section;

	for (index = 0; index < image->header->e_shnum; index++) {
		section = &image->section_headers[index];
		if (section->sh_size != 0 && section->sh_type != SHT_NOBITS &&
		    !range_in_file(section->sh_offset, section->sh_size, image->size)) {
			fail("%s section data is outside the file",
			     section_name(image, section));
		}

		if (section->sh_addralign != 0 && !is_power_of_two(section->sh_addralign)) {
			fail("%s has invalid section alignment", section_name(image, section));
		}
	}
}

static void check_image_contract(const struct elf_image *image, const char *entry_symbol_name,
			       bool require_fv)
{
	struct elf_symbol entry_symbol;
	struct elf_symbol image_start;
	struct elf_symbol image_end;
	struct elf_symbol modules_start;
	struct elf_symbol modules_end;
	struct elf_symbol fv_start;
	struct elf_symbol fv_end;
	const Elf64_Shdr *text_entry;
	const Elf64_Shdr *modules;
	const Elf64_Shdr *fv;
	const Elf64_Shdr *bss;
	uint64_t module_table_size;
	uint64_t image_size;
	uint64_t fv_size;

	check_load_segments(image);
	check_section_file_bounds(image);

	text_entry = require_section(image, ".text.entry");
	modules = require_section(image, ".cdk2.modules");
	bss = require_section(image, ".bss");
	fv = find_section(image, ".cdk2.fv");

	check_section_placement(image, text_entry, ".text.entry", true, false);
	check_section_placement(image, modules, ".cdk2.modules", false, false);
	check_section_placement(image, bss, ".bss", false, true);
	if (fv != NULL) {
		check_section_placement(image, fv, ".cdk2.fv", false, false);
	}

	if (strcmp(entry_symbol_name, "cdk2_coreboot_entry32") == 0) {
		check_coreboot_entry32_paging_contract(image);
	}

	entry_symbol = require_symbol(image, entry_symbol_name);
	image_start = require_symbol(image, "__cdk2_image_start");
	image_end = require_symbol(image, "__cdk2_image_end");
	modules_start = require_symbol(image, "__cdk2_modules_start");
	modules_end = require_symbol(image, "__cdk2_modules_end");
	fv_start = require_symbol(image, "__cdk2_fv_start");
	fv_end = require_symbol(image, "__cdk2_fv_end");

	if (image->header->e_entry != entry_symbol.value) {
		fail("ELF entry does not match %s", entry_symbol_name);
	}

	if (image_start.value != CDK2_LINK_BASE || text_entry->sh_addr != image_start.value ||
	    image_end.value <= image_start.value) {
		fail("native image start/end symbols do not match the link contract");
	}

	image_size = image_end.value - image_start.value;
	check_section_image_bounds(text_entry, ".text.entry", image_start.value, image_size);
	check_section_image_bounds(modules, ".cdk2.modules", image_start.value, image_size);
	check_section_image_bounds(bss, ".bss", image_start.value, image_size);
	if (fv != NULL) {
		check_section_image_bounds(fv, ".cdk2.fv", image_start.value, image_size);
	}

	if (entry_symbol.value < text_entry->sh_addr ||
	    entry_symbol.value >= text_entry->sh_addr + text_entry->sh_size) {
		fail("%s is outside .text.entry", entry_symbol_name);
	}

	if (modules_start.value != modules->sh_addr ||
	    modules_end.value != modules->sh_addr + modules->sh_size ||
	    modules_end.value < modules_start.value) {
		fail("native module table symbols do not match .cdk2.modules");
	}

	module_table_size = modules_end.value - modules_start.value;
	if (module_table_size == 0 || (module_table_size % CDK2_MODULE_ENTRY_SIZE) != 0) {
		fail("native module table has invalid size");
	}

	if (fv_end.value < fv_start.value || fv_start.value < image_start.value ||
	    (fv_start.value & (CDK2_FV_ALIGNMENT - 1U)) != 0 || fv_end.value > image_end.value) {
		fail("native FV symbols have invalid bounds");
	}

	fv_size = fv_end.value - fv_start.value;
	if (require_fv) {
		if (fv == NULL || fv->sh_size == 0 || fv_size == 0) {
			fail("final coreboot image has no embedded FV section");
		}

		if (fv_start.value != fv->sh_addr || fv_end.value != fv->sh_addr + fv->sh_size) {
			fail("embedded FV symbols do not match .cdk2.fv");
		}
	} else if (fv != NULL &&
		   (fv_start.value != fv->sh_addr || fv_end.value != fv->sh_addr + fv->sh_size)) {
		fail("FV symbols do not match .cdk2.fv");
	}
}

static void print_usage(const char *program)
{
	fprintf(stderr, "usage: %s --entry SYMBOL [--require-fv] FILE\n", program);
}

int main(int argc, char **argv)
{
	const char *path;
	const char *entry_symbol;
	bool require_fv;
	struct elf_image image;

	path = NULL;
	entry_symbol = NULL;
	require_fv = false;
	for (int index = 1; index < argc; index++) {
		if ((strcmp(argv[index], "--entry") == 0) && (index + 1 < argc)) {
			entry_symbol = argv[++index];
		} else if (strcmp(argv[index], "--require-fv") == 0) {
			require_fv = true;
		} else if (path == NULL) {
			path = argv[index];
		} else {
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (path == NULL || entry_symbol == NULL) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	open_elf(&image, path);
	check_image_contract(&image, entry_symbol, require_fv);
	printf("cdk2 ELF layout: PASS (%s)\n", path);
	free(image.section_headers);
	free(image.program_headers);
	free(image.data);
	return EXIT_SUCCESS;
}
