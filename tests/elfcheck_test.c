/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host regressions for the native cdk2 ELF layout checker.
 */

#define _POSIX_C_SOURCE 200809L

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CDK2_LINK_BASE                    0x00100000ULL
#define CDK2_MODULE_ENTRY_SIZE            16ULL
#define CDK2_FV_ALIGNMENT                 128ULL
#define CDK2_ENTRY32_PAGE_SIZE            0x1000ULL
#define CDK2_ENTRY32_ONE_GIB              0x40000000ULL
#define CDK2_ENTRY32_MAP_TOP              0x2000000000ULL
#define CDK2_ENTRY32_PAGE_DIRECTORY_COUNT (CDK2_ENTRY32_MAP_TOP / CDK2_ENTRY32_ONE_GIB)
#define CDK2_ENTRY32_PAGE_DIRECTORY_BYTES \
	(CDK2_ENTRY32_PAGE_DIRECTORY_COUNT * CDK2_ENTRY32_PAGE_SIZE)
#define CDK2_ENTRY32_BOOT_STACK_SIZE 0x8000ULL

#define TEST_FILE_SIZE          0x2010U
#define TEST_PATH_SIZE          4096U
#define TEST_SYMTAB_OFFSET      0x0100U
#define TEST_STRTAB_OFFSET      0x0400U
#define TEST_SHSTRTAB_OFFSET    0x0800U
#define TEST_SECTION_OFFSET     0x0900U
#define TEST_TEXT_OFFSET        0x1000U
#define TEST_MODULES_OFFSET     0x2000U
#define TEST_TEXT_ADDRESS       CDK2_LINK_BASE
#define TEST_MODULES_ADDRESS    0x00101000ULL
#define TEST_BSS_ADDRESS        0x00102000ULL
#define TEST_PML4_ADDRESS       TEST_BSS_ADDRESS
#define TEST_PDPT_ADDRESS       (TEST_PML4_ADDRESS + CDK2_ENTRY32_PAGE_SIZE)
#define TEST_PD_ADDRESS         (TEST_PDPT_ADDRESS + CDK2_ENTRY32_PAGE_SIZE)
#define TEST_BOOT_STACK_ADDRESS (TEST_PD_ADDRESS + CDK2_ENTRY32_PAGE_DIRECTORY_BYTES)
#define TEST_BOOT_STACK_TOP     (TEST_BOOT_STACK_ADDRESS + CDK2_ENTRY32_BOOT_STACK_SIZE)
#define TEST_BSS_SIZE           ((TEST_BOOT_STACK_TOP - TEST_BSS_ADDRESS) + CDK2_ENTRY32_PAGE_SIZE)

enum elf_fixture_kind {
	elf_fixture_valid,
	elf_fixture_bad_load_file_range,
	elf_fixture_overlapping_load,
	elf_fixture_wrapping_load,
	elf_fixture_bss_outside_image,
	elf_fixture_coreboot_valid,
	elf_fixture_coreboot_bad_map_top,
	elf_fixture_coreboot_bad_stack_top
};

enum {
	section_null,
	section_text_entry,
	section_modules,
	section_bss,
	section_shstrtab,
	section_symtab,
	section_strtab,
	section_count
};

enum { program_text, program_modules, program_bss, program_extra, program_count };

enum {
	symbol_null,
	symbol_entry,
	symbol_image_start,
	symbol_image_end,
	symbol_modules_start,
	symbol_modules_end,
	symbol_fv_start,
	symbol_fv_end,
	symbol_coreboot_entry,
	symbol_entry32_map_top,
	symbol_entry32_page_directory_count,
	symbol_entry32_boot_stack_size,
	symbol_pml4,
	symbol_pdpt,
	symbol_pd,
	symbol_boot_stack,
	symbol_boot_stack_top,
	symbol_count
};

enum {
	section_name_text_entry = 1,
	section_name_modules = section_name_text_entry + sizeof(".text.entry"),
	section_name_bss = section_name_modules + sizeof(".cdk2.modules"),
	section_name_shstrtab = section_name_bss + sizeof(".bss"),
	section_name_symtab = section_name_shstrtab + sizeof(".shstrtab"),
	section_name_strtab = section_name_symtab + sizeof(".symtab")
};

enum {
	symbol_name_entry = 1,
	symbol_name_image_start = symbol_name_entry + sizeof("cdk2_native_stage_entry"),
	symbol_name_image_end = symbol_name_image_start + sizeof("__cdk2_image_start"),
	symbol_name_modules_start = symbol_name_image_end + sizeof("__cdk2_image_end"),
	symbol_name_modules_end = symbol_name_modules_start + sizeof("__cdk2_modules_start"),
	symbol_name_fv_start = symbol_name_modules_end + sizeof("__cdk2_modules_end"),
	symbol_name_fv_end = symbol_name_fv_start + sizeof("__cdk2_fv_start"),
	symbol_name_coreboot_entry = symbol_name_fv_end + sizeof("__cdk2_fv_end"),
	symbol_name_entry32_map_top = symbol_name_coreboot_entry + sizeof("cdk2_coreboot_entry32"),
	symbol_name_entry32_page_directory_count =
		symbol_name_entry32_map_top + sizeof("cdk2_entry32_identity_map_top"),
	symbol_name_entry32_boot_stack_size = symbol_name_entry32_page_directory_count +
					 sizeof("cdk2_entry32_page_directory_count"),
	symbol_name_pml4 =
		symbol_name_entry32_boot_stack_size + sizeof("cdk2_entry32_boot_stack_size"),
	symbol_name_pdpt = symbol_name_pml4 + sizeof("cdk2_pml4"),
	symbol_name_pd = symbol_name_pdpt + sizeof("cdk2_pdpt"),
	symbol_name_boot_stack = symbol_name_pd + sizeof("cdk2_pd"),
	symbol_name_boot_stack_top = symbol_name_boot_stack + sizeof("cdk2_boot_stack")
};

static const char m_section_strings[] =
	"\0.text.entry\0.cdk2.modules\0.bss\0.shstrtab\0.symtab\0.strtab\0";
static const char m_symbol_strings[] =
	"\0cdk2_native_stage_entry\0__cdk2_image_start\0__cdk2_image_end\0"
	"__cdk2_modules_start\0__cdk2_modules_end\0__cdk2_fv_start\0"
	"__cdk2_fv_end\0cdk2_coreboot_entry32\0cdk2_entry32_identity_map_top\0"
	"cdk2_entry32_page_directory_count\0cdk2_entry32_boot_stack_size\0"
	"cdk2_pml4\0cdk2_pdpt\0cdk2_pd\0cdk2_boot_stack\0cdk2_boot_stack_top\0";

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 ELF checker test: %s\n", message);
		return 1;
	}

	return 0;
}

static int build_path(char *path, size_t path_size, const char *directory, const char *suffix)
{
	int count;

	count = snprintf(path, path_size, "%s/cdk2-elfcheck-test-%ld-%s.elf", directory,
			 (long)getpid(), suffix);
	if ((count < 0) || ((size_t)count >= path_size)) {
		fprintf(stderr, "cdk2 ELF checker test: temporary path is too long\n");
		return 1;
	}

	return 0;
}

static void fill_load(Elf64_Phdr *header, uint32_t flags, uint64_t offset, uint64_t address,
		     uint64_t file_size, uint64_t memory_size)
{
	header->p_type = PT_LOAD;
	header->p_flags = flags;
	header->p_offset = offset;
	header->p_vaddr = address;
	header->p_paddr = address;
	header->p_filesz = file_size;
	header->p_memsz = memory_size;
	header->p_align = 0x1000;
}

static void
fill_symbol(Elf64_Sym *symbol, uint32_t name, uint16_t section_index, uint64_t value,
	    uint64_t size)
{
	symbol->st_name = name;
	symbol->st_shndx = section_index;
	symbol->st_value = value;
	symbol->st_size = size;
}

static size_t build_elf(uint8_t *storage, size_t storage_size, enum elf_fixture_kind kind)
{
	Elf64_Ehdr *elf;
	Elf64_Phdr *programs;
	Elf64_Shdr *sections;
	Elf64_Sym *symbols;
	uint64_t entry32_map_top;
	uint64_t boot_stack_top;

	if (storage_size < TEST_FILE_SIZE) {
		return 0;
	}

	memset(storage, 0, storage_size);

	elf = (Elf64_Ehdr *)(void *)storage;
	elf->e_ident[EI_MAG0] = ELFMAG0;
	elf->e_ident[EI_MAG1] = ELFMAG1;
	elf->e_ident[EI_MAG2] = ELFMAG2;
	elf->e_ident[EI_MAG3] = ELFMAG3;
	elf->e_ident[EI_CLASS] = ELFCLASS64;
	elf->e_ident[EI_DATA] = ELFDATA2LSB;
	elf->e_ident[EI_VERSION] = EV_CURRENT;
	elf->e_type = ET_EXEC;
	elf->e_machine = EM_X86_64;
	elf->e_version = EV_CURRENT;
	elf->e_entry = TEST_TEXT_ADDRESS;
	elf->e_phoff = sizeof(*elf);
	elf->e_shoff = TEST_SECTION_OFFSET;
	elf->e_ehsize = sizeof(*elf);
	elf->e_phentsize = sizeof(Elf64_Phdr);
	elf->e_phnum = (kind == elf_fixture_overlapping_load || kind == elf_fixture_wrapping_load) ?
			       program_count :
			       program_extra;
	elf->e_shentsize = sizeof(Elf64_Shdr);
	elf->e_shnum = section_count;
	elf->e_shstrndx = section_shstrtab;

	programs = (Elf64_Phdr *)(void *)(storage + elf->e_phoff);
	fill_load(&programs[program_text], PF_R | PF_X,
		 (kind == elf_fixture_bad_load_file_range) ? 0x3000U : TEST_TEXT_OFFSET,
		 TEST_TEXT_ADDRESS, 1, 1);
	fill_load(&programs[program_modules], PF_R, TEST_MODULES_OFFSET, TEST_MODULES_ADDRESS,
		 CDK2_MODULE_ENTRY_SIZE, CDK2_MODULE_ENTRY_SIZE);
	fill_load(&programs[program_bss], PF_R | PF_W, 0, TEST_BSS_ADDRESS, 0, TEST_BSS_SIZE);
	if (kind == elf_fixture_overlapping_load) {
		fill_load(&programs[program_extra], PF_R, TEST_TEXT_OFFSET, TEST_TEXT_ADDRESS, 0,
			 1);
	} else if (kind == elf_fixture_wrapping_load) {
		fill_load(&programs[program_extra], PF_R, 0, UINT64_MAX - 0xfffU, 0, 0x2000);
	}

	sections = (Elf64_Shdr *)(void *)(storage + TEST_SECTION_OFFSET);
	sections[section_text_entry].sh_name = section_name_text_entry;
	sections[section_text_entry].sh_type = SHT_PROGBITS;
	sections[section_text_entry].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	sections[section_text_entry].sh_addr = TEST_TEXT_ADDRESS;
	sections[section_text_entry].sh_offset = TEST_TEXT_OFFSET;
	sections[section_text_entry].sh_size = 1;
	sections[section_text_entry].sh_addralign = 1;
	sections[section_modules].sh_name = section_name_modules;
	sections[section_modules].sh_type = SHT_PROGBITS;
	sections[section_modules].sh_flags = SHF_ALLOC;
	sections[section_modules].sh_addr = TEST_MODULES_ADDRESS;
	sections[section_modules].sh_offset = TEST_MODULES_OFFSET;
	sections[section_modules].sh_size = CDK2_MODULE_ENTRY_SIZE;
	sections[section_modules].sh_addralign = 16;
	sections[section_bss].sh_name = section_name_bss;
	sections[section_bss].sh_type = SHT_NOBITS;
	sections[section_bss].sh_flags = SHF_ALLOC | SHF_WRITE;
	sections[section_bss].sh_addr = TEST_BSS_ADDRESS;
	sections[section_bss].sh_size = TEST_BSS_SIZE;
	sections[section_bss].sh_addralign = 0x1000;
	sections[section_shstrtab].sh_name = section_name_shstrtab;
	sections[section_shstrtab].sh_type = SHT_STRTAB;
	sections[section_shstrtab].sh_offset = TEST_SHSTRTAB_OFFSET;
	sections[section_shstrtab].sh_size = sizeof(m_section_strings);
	sections[section_shstrtab].sh_addralign = 1;
	sections[section_symtab].sh_name = section_name_symtab;
	sections[section_symtab].sh_type = SHT_SYMTAB;
	sections[section_symtab].sh_offset = TEST_SYMTAB_OFFSET;
	sections[section_symtab].sh_size = symbol_count * sizeof(Elf64_Sym);
	sections[section_symtab].sh_link = section_strtab;
	sections[section_symtab].sh_addralign = 8;
	sections[section_symtab].sh_entsize = sizeof(Elf64_Sym);
	sections[section_strtab].sh_name = section_name_strtab;
	sections[section_strtab].sh_type = SHT_STRTAB;
	sections[section_strtab].sh_offset = TEST_STRTAB_OFFSET;
	sections[section_strtab].sh_size = sizeof(m_symbol_strings);
	sections[section_strtab].sh_addralign = 1;

	symbols = (Elf64_Sym *)(void *)(storage + TEST_SYMTAB_OFFSET);
	fill_symbol(&symbols[symbol_entry], symbol_name_entry, section_text_entry, TEST_TEXT_ADDRESS,
		   1);
	fill_symbol(&symbols[symbol_coreboot_entry], symbol_name_coreboot_entry, section_text_entry,
		   TEST_TEXT_ADDRESS, 1);
	fill_symbol(&symbols[symbol_image_start], symbol_name_image_start, section_text_entry,
		   TEST_TEXT_ADDRESS, 0);
	fill_symbol(&symbols[symbol_image_end], symbol_name_image_end, section_bss,
		   (kind == elf_fixture_bss_outside_image) ?
			   TEST_MODULES_ADDRESS + CDK2_FV_ALIGNMENT :
			   TEST_BSS_ADDRESS + TEST_BSS_SIZE,
		   0);
	fill_symbol(&symbols[symbol_modules_start], symbol_name_modules_start, section_modules,
		   TEST_MODULES_ADDRESS, 0);
	fill_symbol(&symbols[symbol_modules_end], symbol_name_modules_end, section_modules,
		   TEST_MODULES_ADDRESS + CDK2_MODULE_ENTRY_SIZE, 0);
	fill_symbol(&symbols[symbol_fv_start], symbol_name_fv_start, section_modules,
		   TEST_MODULES_ADDRESS + CDK2_FV_ALIGNMENT, 0);
	fill_symbol(&symbols[symbol_fv_end], symbol_name_fv_end, section_modules,
		   TEST_MODULES_ADDRESS + CDK2_FV_ALIGNMENT, 0);
	entry32_map_top = (kind == elf_fixture_coreboot_bad_map_top) ?
				CDK2_ENTRY32_MAP_TOP - CDK2_ENTRY32_ONE_GIB :
				CDK2_ENTRY32_MAP_TOP;
	boot_stack_top = (kind == elf_fixture_coreboot_bad_stack_top) ? TEST_BOOT_STACK_TOP - 16 :
								 TEST_BOOT_STACK_TOP;
	fill_symbol(&symbols[symbol_entry32_map_top], symbol_name_entry32_map_top, SHN_ABS,
		   entry32_map_top, 0);
	fill_symbol(&symbols[symbol_entry32_page_directory_count],
		   symbol_name_entry32_page_directory_count, SHN_ABS,
		   CDK2_ENTRY32_PAGE_DIRECTORY_COUNT, 0);
	fill_symbol(&symbols[symbol_entry32_boot_stack_size], symbol_name_entry32_boot_stack_size,
		   SHN_ABS, CDK2_ENTRY32_BOOT_STACK_SIZE, 0);
	fill_symbol(&symbols[symbol_pml4], symbol_name_pml4, section_bss, TEST_PML4_ADDRESS,
		   CDK2_ENTRY32_PAGE_SIZE);
	fill_symbol(&symbols[symbol_pdpt], symbol_name_pdpt, section_bss, TEST_PDPT_ADDRESS,
		   CDK2_ENTRY32_PAGE_SIZE);
	fill_symbol(&symbols[symbol_pd], symbol_name_pd, section_bss, TEST_PD_ADDRESS,
		   CDK2_ENTRY32_PAGE_DIRECTORY_BYTES);
	fill_symbol(&symbols[symbol_boot_stack], symbol_name_boot_stack, section_bss,
		   TEST_BOOT_STACK_ADDRESS, CDK2_ENTRY32_BOOT_STACK_SIZE);
	fill_symbol(&symbols[symbol_boot_stack_top], symbol_name_boot_stack_top, section_bss,
		   boot_stack_top, 0);

	memcpy(storage + TEST_STRTAB_OFFSET, m_symbol_strings, sizeof(m_symbol_strings));
	memcpy(storage + TEST_SHSTRTAB_OFFSET, m_section_strings, sizeof(m_section_strings));
	storage[TEST_TEXT_OFFSET] = 0xc3;
	memset(storage + TEST_MODULES_OFFSET, 0xa5, CDK2_MODULE_ENTRY_SIZE);
	return TEST_FILE_SIZE;
}

static int write_binary_file(const char *path, const uint8_t *data, size_t size)
{
	FILE *file;
	int result;

	file = fopen(path, "wb");
	if (file == NULL) {
		fprintf(stderr, "cdk2 ELF checker test: cannot create %s: %s\n", path,
			strerror(errno));
		return 1;
	}

	result = 0;
	if (fwrite(data, 1, size, file) != size) {
		fprintf(stderr, "cdk2 ELF checker test: cannot write %s\n", path);
		result = 1;
	}

	if (fclose(file) != 0) {
		fprintf(stderr, "cdk2 ELF checker test: cannot close %s\n", path);
		result = 1;
	}

	return result;
}

static void redirect_to_null(void)
{
	int null_file;
	int redirected_file;

	null_file = open("/dev/null", O_WRONLY);
	if (null_file < 0) {
		return;
	}

	if (null_file <= STDERR_FILENO) {
		redirected_file = fcntl(null_file, F_DUPFD, STDERR_FILENO + 1);
		close(null_file);
		if (redirected_file < 0) {
			return;
		}

		null_file = redirected_file;
	}

	(void)dup2(null_file, STDOUT_FILENO);
	(void)dup2(null_file, STDERR_FILENO);
	close(null_file);
}

static int run_checker(const char *checker, const char *path, const char *entry,
		      int expect_success)
{
	pid_t child;
	int status;
	int succeeded;

	child = fork();
	if (child == 0) {
		redirect_to_null();
		execl(checker, checker, "--entry", entry, path, (char *)NULL);
		_exit(127);
	}

	if (child < 0) {
		fprintf(stderr, "cdk2 ELF checker test: cannot fork: %s\n", strerror(errno));
		return 1;
	}

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "cdk2 ELF checker test: cannot wait for checker: %s\n",
			strerror(errno));
		return 1;
	}

	if (!WIFEXITED(status)) {
		fprintf(stderr, "cdk2 ELF checker test: checker exited abnormally\n");
		return 1;
	}

	succeeded = (WEXITSTATUS(status) == 0);
	if (succeeded != expect_success) {
		fprintf(stderr, "cdk2 ELF checker test: checker %s %s unexpectedly\n",
			succeeded ? "accepted" : "rejected", path);
		return 1;
	}

	return 0;
}

static int run_fixture(const char *checker, const char *directory, const char *suffix,
		      enum elf_fixture_kind kind, const char *entry, int expect_success)
{
	uint8_t storage[TEST_FILE_SIZE];
	char path[TEST_PATH_SIZE];
	size_t size;
	int result;

	if (build_path(path, sizeof(path), directory, suffix) != 0) {
		return 1;
	}

	size = build_elf(storage, sizeof(storage), kind);
	if (size == 0) {
		return expect(0, "fixture storage is too small");
	}

	result = write_binary_file(path, storage, size);
	if (result == 0) {
		result = run_checker(checker, path, entry, expect_success);
	}

	if (unlink(path) != 0 && result == 0) {
		fprintf(stderr, "cdk2 ELF checker test: cannot remove %s: %s\n", path,
			strerror(errno));
		result = 1;
	}

	return result;
}

int main(int argument_count, char **arguments)
{
	int failures;

	if (argument_count != 3) {
		fprintf(stderr, "usage: %s ELFCHECK BUILD_DIR\n", arguments[0]);
		return 1;
	}

	failures = 0;
	failures += run_fixture(arguments[1], arguments[2], "valid", elf_fixture_valid,
			       "cdk2_native_stage_entry", 1);
	failures += run_fixture(arguments[1], arguments[2], "bad-load-file-range",
			       elf_fixture_bad_load_file_range, "cdk2_native_stage_entry", 0);
	failures += run_fixture(arguments[1], arguments[2], "overlapping-load",
			       elf_fixture_overlapping_load, "cdk2_native_stage_entry", 0);
	failures += run_fixture(arguments[1], arguments[2], "wrapping-load",
			       elf_fixture_wrapping_load, "cdk2_native_stage_entry", 0);
	failures += run_fixture(arguments[1], arguments[2], "bss-outside-image",
			       elf_fixture_bss_outside_image, "cdk2_native_stage_entry", 0);
	failures += run_fixture(arguments[1], arguments[2], "coreboot-valid",
			       elf_fixture_coreboot_valid, "cdk2_coreboot_entry32", 1);
	failures += run_fixture(arguments[1], arguments[2], "coreboot-bad-map-top",
			       elf_fixture_coreboot_bad_map_top, "cdk2_coreboot_entry32", 0);
	failures += run_fixture(arguments[1], arguments[2], "coreboot-bad-stack-top",
			       elf_fixture_coreboot_bad_stack_top, "cdk2_coreboot_entry32", 0);

	if (failures != 0) {
		return 1;
	}

	puts("cdk2 ELF checker test: PASS");
	return 0;
}
