/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host checks for native firmware-volume packing.
 */

#define _POSIX_C_SOURCE 200809L

#include <uefi.h>
#include <industry_standard/pe_image.h>
#include <pi/firmware_file.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_ENTRY_SIZE  0x400U
#define TEST_DXE_FV_SIZE 0x100U
#define TEST_FFS_SIZE    0x20U
#define TEST_PATH_SIZE   4096U
#define FV_BASE_ADDRESS  0x00800000ULL
#define FFS_HEADER_SIZE  0x18U
#define FFS_STATE_VALID  0xF8U

static UINT16 get16(const UINT8 *buffer)
{
	return (UINT16)(buffer[0] | ((UINT16)buffer[1] << 8));
}

static UINT32 get32(const UINT8 *buffer)
{
	return (UINT32)(buffer[0] | ((UINT32)buffer[1] << 8) | ((UINT32)buffer[2] << 16) |
			((UINT32)buffer[3] << 24));
}

static UINT64 get64(const UINT8 *buffer)
{
	return (UINT64)get32(buffer) | ((UINT64)get32(buffer + 4) << 32);
}

static UINTN get24(const UINT8 *buffer)
{
	return (UINTN)(buffer[0] | ((UINTN)buffer[1] << 8) | ((UINTN)buffer[2] << 16));
}

static void put16(UINT8 *buffer, UINT16 value)
{
	buffer[0] = (UINT8)value;
	buffer[1] = (UINT8)(value >> 8);
}

static void put32(UINT8 *buffer, UINT32 value)
{
	buffer[0] = (UINT8)value;
	buffer[1] = (UINT8)(value >> 8);
	buffer[2] = (UINT8)(value >> 16);
	buffer[3] = (UINT8)(value >> 24);
}

static void put24(UINT8 *buffer, UINTN value)
{
	buffer[0] = (UINT8)value;
	buffer[1] = (UINT8)(value >> 8);
	buffer[2] = (UINT8)(value >> 16);
}

static void put64(UINT8 *buffer, UINT64 value)
{
	put32(buffer, (UINT32)value);
	put32(buffer + 4, (UINT32)(value >> 32));
}

static UINTN align_up(UINTN value, UINTN alignment)
{
	return (value + alignment - 1U) & ~(alignment - 1U);
}

static UINT8 checksum8(const UINT8 *buffer, UINTN size)
{
	UINT8 sum;
	UINTN index;

	sum = 0;
	for (index = 0; index < size; index++) {
		sum = (UINT8)(sum + buffer[index]);
	}

	return (UINT8)(0U - sum);
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 fvpack test: %s\n", message);
		return 1;
	}

	return 0;
}

static int build_path(char *path, size_t path_size, const char *directory, const char *suffix)
{
	int count;

	count = snprintf(path, path_size, "%s/cdk2-fvpack-test-%ld-%s", directory,
			 (long)getpid(), suffix);
	if ((count < 0) || ((size_t)count >= path_size)) {
		fprintf(stderr, "cdk2 fvpack test: temporary path is too long\n");
		return 1;
	}

	return 0;
}

static UINTN build_no_reloc_pe32_plus(UINT8 *storage, UINTN storage_size)
{
	EFI_IMAGE_DOS_HEADER *dos;
	EFI_IMAGE_NT_HEADERS64 *nt;
	EFI_IMAGE_SECTION_HEADER *section;
	UINTN pe_offset;

	if (storage_size < TEST_ENTRY_SIZE) {
		return 0;
	}

	memset(storage, 0, storage_size);
	pe_offset = 0x80;
	dos = (EFI_IMAGE_DOS_HEADER *)(void *)storage;
	dos->e_magic = EFI_IMAGE_DOS_SIGNATURE;
	dos->e_lfanew = (UINT32)pe_offset;

	nt = (EFI_IMAGE_NT_HEADERS64 *)(void *)(storage + pe_offset);
	nt->signature = EFI_IMAGE_NT_SIGNATURE;
	nt->file_header.machine = IMAGE_FILE_MACHINE_X64;
	nt->file_header.number_of_sections = 1;
	nt->file_header.size_of_optional_header = sizeof(EFI_IMAGE_OPTIONAL_HEADER64);
	nt->file_header.characteristics = EFI_IMAGE_FILE_EXECUTABLE_IMAGE |
					 EFI_IMAGE_FILE_LARGE_ADDRESS_AWARE;
	nt->optional_header.magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt->optional_header.image_base = 0;
	nt->optional_header.section_alignment = 0x1000;
	nt->optional_header.file_alignment = 0x200;
	nt->optional_header.size_of_image = 0x2000;
	nt->optional_header.size_of_headers = 0x200;
	nt->optional_header.address_of_entry_point = 0x1000;
	nt->optional_header.number_of_rva_and_sizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;

	section = (EFI_IMAGE_SECTION_HEADER *)(void *)((UINT8 *)nt +
						       sizeof(EFI_IMAGE_NT_HEADERS64));
	memcpy(section->name, ".text", 5);
	section->misc.virtual_size = 0x10;
	section->virtual_address = 0x1000;
	section->size_of_raw_data = 0x200;
	section->pointer_to_raw_data = 0x200;
	storage[0x200] = 0xC3;
	return TEST_ENTRY_SIZE;
}

static UINTN build_wrapped_reloc_pe32_plus(UINT8 *storage, UINTN storage_size)
{
	EFI_IMAGE_NT_HEADERS64 *nt;
	EFI_IMAGE_BASE_RELOCATION *reloc;
	UINT16 *reloc_entry;

	if (build_no_reloc_pe32_plus(storage, storage_size) == 0) {
		return 0;
	}

	nt = (EFI_IMAGE_NT_HEADERS64 *)(void *)(storage + 0x80);
	nt->optional_header.image_base = 0x00400000;
	nt->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address =
		0x1100;
	nt->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].size = 12;
	*(UINT64 *)(void *)(storage + 0x200) = 0x00400123;

	reloc = (EFI_IMAGE_BASE_RELOCATION *)(void *)(storage + 0x300);
	reloc->virtual_address = MAX_UINT32 - 0x0fffU + 1U;
	reloc->size_of_block = 12;
	reloc_entry = (UINT16 *)(void *)(reloc + 1);
	reloc_entry[0] = (UINT16)((EFI_IMAGE_REL_BASED_DIR64 << 12) | 0x0fffU);
	reloc_entry[1] = 0;
	return TEST_ENTRY_SIZE;
}

static UINTN build_downward_reloc_pe32_plus(UINT8 *storage, UINTN storage_size)
{
	EFI_IMAGE_NT_HEADERS64 *nt;
	EFI_IMAGE_BASE_RELOCATION *reloc;
	UINT16 *reloc_entry;

	if (build_no_reloc_pe32_plus(storage, storage_size) == 0) {
		return 0;
	}

	nt = (EFI_IMAGE_NT_HEADERS64 *)(void *)(storage + 0x80);
	nt->optional_header.image_base = 0x01000000;
	nt->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address =
		0x1100;
	nt->optional_header.data_directory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].size = 12;
	*(UINT64 *)(void *)(storage + 0x200) = 0x01000123;

	reloc = (EFI_IMAGE_BASE_RELOCATION *)(void *)(storage + 0x300);
	reloc->virtual_address = 0x1000;
	reloc->size_of_block = 12;
	reloc_entry = (UINT16 *)(void *)(reloc + 1);
	reloc_entry[0] = (UINT16)((EFI_IMAGE_REL_BASED_DIR64 << 12) | 0);
	reloc_entry[1] = 0;
	return TEST_ENTRY_SIZE;
}

static UINTN build_dxe_volume(UINT8 *storage, UINTN storage_size)
{
	if (storage_size < TEST_DXE_FV_SIZE) {
		return 0;
	}

	memset(storage, 0xFF, storage_size);
	memset(storage, 0, 0x48);
	put64(storage + 0x20, TEST_DXE_FV_SIZE);
	memcpy(storage + 0x28, "_FVH", 4);
	put16(storage + 0x30, 0x48);
	storage[0x37] = 2;
	return TEST_DXE_FV_SIZE;
}

static void finalize_ffs(UINT8 *storage)
{
	storage[16] = 0;
	storage[17] = 0;
	storage[23] = 0;
	storage[16] = checksum8(storage, FFS_HEADER_SIZE);
	storage[17] = FFS_FIXED_CHECKSUM;
	storage[23] = FFS_STATE_VALID;
}

static UINTN build_ffs(UINT8 *storage, UINTN storage_size, const UINT8 *guid, UINT8 type)
{
	if (storage_size < TEST_FFS_SIZE) {
		return 0;
	}

	memset(storage, 0, TEST_FFS_SIZE);
	memcpy(storage, guid, 16);
	storage[18] = type;
	put24(storage + 20, TEST_FFS_SIZE);
	memset(storage + FFS_HEADER_SIZE, type, TEST_FFS_SIZE - FFS_HEADER_SIZE);
	finalize_ffs(storage);
	return TEST_FFS_SIZE;
}

static UINTN build_dxe_volume_with_ffs_at(UINT8 *storage, UINTN storage_size, const UINT8 *ffs,
				     UINTN ffs_size, UINTN ffs_offset)
{
	UINTN volume_size;

	volume_size = build_dxe_volume(storage, storage_size);
	if ((volume_size == 0) || (ffs_offset > volume_size) || (ffs_size > volume_size - ffs_offset)) {
		return 0;
	}

	memcpy(storage + ffs_offset, ffs, ffs_size);
	return volume_size;
}

static UINTN build_dxe_volume_with_ffs(UINT8 *storage, UINTN storage_size, const UINT8 *ffs,
				   UINTN ffs_size)
{
	return build_dxe_volume_with_ffs_at(storage, storage_size, ffs, ffs_size, 0x48U);
}

static int write_binary_file(const char *path, const UINT8 *data, UINTN size)
{
	FILE *file;
	int result;

	file = fopen(path, "wb");
	if (file == NULL) {
		fprintf(stderr, "cdk2 fvpack test: cannot create %s: %s\n", path,
			strerror(errno));
		return 1;
	}

	result = 0;
	if (fwrite(data, 1, (size_t)size, file) != (size_t)size) {
		fprintf(stderr, "cdk2 fvpack test: cannot write %s\n", path);
		result = 1;
	}

	if (fclose(file) != 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot close %s\n", path);
		result = 1;
	}

	return result;
}

static int write_text_file(const char *path, const char *text)
{
	FILE *file;
	int result;
	size_t length;

	file = fopen(path, "w");
	if (file == NULL) {
		fprintf(stderr, "cdk2 fvpack test: cannot create %s: %s\n", path,
			strerror(errno));
		return 1;
	}

	length = strlen(text);
	result = 0;
	if (fwrite(text, 1, length, file) != length) {
		fprintf(stderr, "cdk2 fvpack test: cannot write %s\n", path);
		result = 1;
	}

	if (fclose(file) != 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot close %s\n", path);
		result = 1;
	}

	return result;
}

static int guid_text(const UINT8 *guid, char *text, size_t text_size)
{
	static const UINT8 guid_order[16] = {3, 2, 1, 0, 5, 4, 7, 6,
					     8, 9, 10, 11, 12, 13, 14, 15};
	static const char hex[] = "0123456789ABCDEF";
	size_t index;
	size_t offset;
	UINT8 value;

	if (text_size < 37) {
		fprintf(stderr, "cdk2 fvpack test: GUID text buffer is too small\n");
		return 1;
	}

	offset = 0;
	for (index = 0; index < sizeof(guid_order); index++) {
		if (index == 4 || index == 6 || index == 8 || index == 10) {
			text[offset++] = '-';
		}

		value = guid[guid_order[index]];
		text[offset++] = hex[value >> 4];
		text[offset++] = hex[value & 0xfU];
	}

	text[offset] = '\0';
	return 0;
}

static int write_manifest(const char *path, UINTN first_offset, const UINT8 *first_guid,
			 const char *first_path, UINTN second_offset, const UINT8 *second_guid,
			 const char *second_path)
{
	char text[(TEST_PATH_SIZE * 2) + 256];
	char first_guid_text[37];
	char second_guid_text[37];
	int count;

	if (guid_text(first_guid, first_guid_text, sizeof(first_guid_text)) != 0) {
		return 1;
	}

	if (second_path == NULL) {
		count = snprintf(
			text, sizeof(text),
			"# cdk2 native fvpack manifest\n"
			"# Format: FILE <reference-dxe-fv-offset> <file-guid> <ffs-path>\n"
			"VERSION 1\n"
			"FILE 0x%zx %s %s\n",
			(size_t)first_offset, first_guid_text, first_path);
	} else {
		if (guid_text(second_guid, second_guid_text, sizeof(second_guid_text)) != 0) {
			return 1;
		}

		count = snprintf(
			text, sizeof(text),
			"# cdk2 native fvpack manifest\n"
			"# Format: FILE <reference-dxe-fv-offset> <file-guid> <ffs-path>\n"
			"VERSION 1\n"
			"FILE 0x%zx %s %s\n"
			"FILE 0x%zx %s %s\n",
			(size_t)first_offset, first_guid_text, first_path, (size_t)second_offset,
			second_guid_text, second_path);
	}

	if ((count < 0) || ((size_t)count >= sizeof(text))) {
		fprintf(stderr, "cdk2 fvpack test: manifest path is too long\n");
		return 1;
	}

	return write_text_file(path, text);
}

static UINT8 *read_binary_file(const char *path, size_t *size)
{
	FILE *file;
	long length;
	UINT8 *data;

	file = fopen(path, "rb");
	if ((file == NULL) || (fseek(file, 0, SEEK_END) != 0)) {
		if (file != NULL) {
			fclose(file);
		}

		fprintf(stderr, "cdk2 fvpack test: cannot open %s\n", path);
		return NULL;
	}

	length = ftell(file);
	if ((length <= 0) || (fseek(file, 0, SEEK_SET) != 0)) {
		fclose(file);
		fprintf(stderr, "cdk2 fvpack test: invalid size for %s\n", path);
		return NULL;
	}

	data = malloc((size_t)length);
	if (data == NULL) {
		fclose(file);
		fprintf(stderr, "cdk2 fvpack test: out of memory\n");
		return NULL;
	}

	if (fread(data, 1, (size_t)length, file) != (size_t)length) {
		free(data);
		fclose(file);
		fprintf(stderr, "cdk2 fvpack test: cannot read %s\n", path);
		return NULL;
	}

	fclose(file);
	*size = (size_t)length;
	return data;
}

static int
run_packer_with_size(const char *packer, const char *output_path, const char *entry_path,
		     const char *dxe_path, const char *volume_size, int expect_success)
{
	pid_t child;
	int status;
	int succeeded;

	child = fork();
	if (child == 0) {
		execl(packer, packer, "--output", output_path, "--entry-efi", entry_path,
		      "--dxe-fv", dxe_path, "--size", volume_size, (char *)NULL);
		_exit(127);
	}

	if (child < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot fork: %s\n", strerror(errno));
		return 1;
	}

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot wait for packer: %s\n",
			strerror(errno));
		return 1;
	}

	succeeded = WIFEXITED(status) && (WEXITSTATUS(status) == 0);
	if (expect_success ? !succeeded : (!WIFEXITED(status) || succeeded)) {
		fprintf(stderr, "cdk2 fvpack test: packer %s unexpectedly\n",
			succeeded ? "succeeded" : "did not exit successfully");
		return 1;
	}

	return 0;
}

static int run_packer(const char *packer, const char *output_path, const char *entry_path,
		     const char *dxe_path, int expect_success)
{
	return run_packer_with_size(packer, output_path, entry_path, dxe_path, "0x2000",
				 expect_success);
}

static int
run_ffs_list_packer(const char *packer, const char *output_path, const char *entry_path,
		    const char *dxe_path, const char *ffs_list_path, int expect_success)
{
	pid_t child;
	int status;
	int succeeded;

	child = fork();
	if (child == 0) {
		execl(packer, packer, "--output", output_path, "--entry-efi", entry_path,
		      "--dxe-fv", dxe_path, "--dxe-ffs-list", ffs_list_path, "--flatten-dxe", "--size",
		      "0x2000", (char *)NULL);
		_exit(127);
	}

	if (child < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot fork: %s\n", strerror(errno));
		return 1;
	}

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot wait for packer: %s\n",
			strerror(errno));
		return 1;
	}

	succeeded = WIFEXITED(status) && (WEXITSTATUS(status) == 0);
	if (expect_success ? !succeeded : (!WIFEXITED(status) || succeeded)) {
		fprintf(stderr, "cdk2 fvpack test: FFS-list packer %s unexpectedly\n",
			succeeded ? "succeeded" : "failed");
		return 1;
	}

	return 0;
}

static int
run_manifest_packer(const char *packer, const char *output_path, const char *entry_path,
		    const char *manifest_path, int expect_success)
{
	pid_t child;
	int status;
	int succeeded;

	child = fork();
	if (child == 0) {
		execl(packer, packer, "--output", output_path, "--entry-efi", entry_path,
		      "--dxe-manifest", manifest_path, "--flatten-dxe", "--size", "0x2000",
		      (char *)NULL);
		_exit(127);
	}

	if (child < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot fork: %s\n", strerror(errno));
		return 1;
	}

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot wait for packer: %s\n",
			strerror(errno));
		return 1;
	}

	succeeded = WIFEXITED(status) && (WEXITSTATUS(status) == 0);
	if (expect_success ? !succeeded : (!WIFEXITED(status) || succeeded)) {
		fprintf(stderr, "cdk2 fvpack test: manifest packer %s unexpectedly\n",
			succeeded ? "succeeded" : "failed");
		return 1;
	}

	return 0;
}

static int run_manifest_verifier(const char *packer, const char *dxe_path,
			       const char *manifest_path, int expect_success)
{
	pid_t child;
	int status;
	int succeeded;

	child = fork();
	if (child == 0) {
		execl(packer, packer, "--verify-dxe-manifest", "--dxe-manifest", manifest_path,
		      "--reference-dxe-fv", dxe_path, (char *)NULL);
		_exit(127);
	}

	if (child < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot fork: %s\n", strerror(errno));
		return 1;
	}

	if (waitpid(child, &status, 0) < 0) {
		fprintf(stderr, "cdk2 fvpack test: cannot wait for packer: %s\n",
			strerror(errno));
		return 1;
	}

	succeeded = WIFEXITED(status) && (WEXITSTATUS(status) == 0);
	if (succeeded != expect_success) {
		fprintf(stderr, "cdk2 fvpack test: manifest verifier %s unexpectedly\n",
			succeeded ? "succeeded" : "failed");
		return 1;
	}

	return 0;
}

static int
find_packed_entry_image_base(const UINT8 *volume, size_t volume_size, UINT64 *image_base,
			     UINT64 *expected_base)
{
	UINTN file_offset;
	UINTN file_size;
	UINTN file_end;
	UINTN raw_section_size;
	UINTN pe_section_offset;
	UINTN pe_section_size;
	UINTN pe_offset;
	UINTN pe_header_offset;
	UINTN optional_offset;
	UINT16 optional_magic;

	if (volume_size < 0x48) {
		return expect(0, "packed FV is smaller than its header");
	}

	file_offset = align_up((UINTN)get16(volume + 0x30), 8);
	while (file_offset + FFS_HEADER_SIZE <= volume_size) {
		file_size = get24(volume + file_offset + 20);
		if (file_size == 0xFFFFFFU) {
			return expect(0, "packed FV does not contain an entry file");
		}

		if ((file_size < FFS_HEADER_SIZE) || (file_size > volume_size - file_offset)) {
			return expect(0, "packed FV contains an invalid FFS file");
		}

		if (volume[file_offset + 18] == EFI_FV_FILETYPE_FFS_PAD) {
			file_offset = align_up(file_offset + file_size, 8);
			continue;
		}

		if (volume[file_offset + 18] != EFI_FV_FILETYPE_SECURITY_CORE) {
			return expect(0, "packed FV first non-pad file is not the entry image");
		}

		file_end = file_offset + file_size;
		raw_section_size = get24(volume + file_offset + FFS_HEADER_SIZE);
		if ((raw_section_size < 4) ||
		    (file_offset + FFS_HEADER_SIZE + raw_section_size + 4 > file_end) ||
		    (volume[file_offset + FFS_HEADER_SIZE + 3] != EFI_SECTION_RAW)) {
			return expect(0, "packed entry raw section is invalid");
		}

		pe_section_offset = file_offset + FFS_HEADER_SIZE + raw_section_size;
		pe_section_size = get24(volume + pe_section_offset);
		if ((pe_section_size < 4) || (pe_section_offset + pe_section_size > file_end) ||
		    (volume[pe_section_offset + 3] != EFI_SECTION_PE32)) {
			return expect(0, "packed entry PE section is invalid");
		}

		pe_offset = pe_section_offset + 4;
		if ((pe_offset + 0x40 > volume_size) ||
		    (get16(volume + pe_offset) != EFI_IMAGE_DOS_SIGNATURE)) {
			return expect(0, "packed entry PE image is invalid");
		}

		pe_header_offset = pe_offset + get32(volume + pe_offset + 0x3C);
		if ((pe_header_offset + 24 > volume_size) ||
		    (get32(volume + pe_header_offset) != EFI_IMAGE_NT_SIGNATURE)) {
			return expect(0, "packed entry PE header is invalid");
		}

		optional_offset = pe_header_offset + 4 + 20;
		if (optional_offset + 32 > volume_size) {
			return expect(0, "packed entry optional header is invalid");
		}

		optional_magic = get16(volume + optional_offset);
		if (optional_magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			return expect(0, "packed entry is not PE32+");
		}

		*image_base = get64(volume + optional_offset + 24);
		*expected_base = FV_BASE_ADDRESS + (UINT64)pe_offset;
		return 0;
	}

	return expect(0, "packed FV does not contain an entry file");
}

int main(int argument_count, char **arguments)
{
	UINT8 entry[TEST_ENTRY_SIZE];
	UINT8 dxe[TEST_DXE_FV_SIZE];
	UINT8 selected_ffs[TEST_FFS_SIZE];
	UINT8 stale_ffs[TEST_FFS_SIZE];
	UINT8 short_ffs[1];
	static const UINT8 dxe_core_guid[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
					      0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10};
	static const UINT8 stale_guid[16] = {0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
					    0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f, 0x20};
	char entry_path[TEST_PATH_SIZE];
	char dxe_path[TEST_PATH_SIZE];
	char output_path[TEST_PATH_SIZE];
	char selected_ffs_path[TEST_PATH_SIZE];
	char stale_ffs_path[TEST_PATH_SIZE];
	char short_ffs_path[TEST_PATH_SIZE];
	char ffs_list_path[TEST_PATH_SIZE];
	char manifest_path[TEST_PATH_SIZE];
	char ffs_list_text[TEST_PATH_SIZE + 2];
	UINTN entry_size;
	UINTN dxe_size;
	UINTN selected_ffs_size;
	UINTN stale_ffs_size;
	UINT8 *packed;
	size_t packed_size;
	UINT64 image_base;
	UINT64 expected_base;
	int count;
	int failures;

	if (argument_count != 3) {
		fprintf(stderr, "usage: %s PACKER BUILD_DIR\n", arguments[0]);
		return 1;
	}

	entry_path[0] = '\0';
	dxe_path[0] = '\0';
	output_path[0] = '\0';
	selected_ffs_path[0] = '\0';
	stale_ffs_path[0] = '\0';
	short_ffs_path[0] = '\0';
	ffs_list_path[0] = '\0';
	manifest_path[0] = '\0';
	short_ffs[0] = 0;
	selected_ffs_size = 0;
	stale_ffs_size = 0;
	packed = NULL;
	packed_size = 0;
	image_base = 0;
	expected_base = 0;
	failures = 0;

	failures += build_path(entry_path, sizeof(entry_path), arguments[2], "entry.efi");
	failures += build_path(dxe_path, sizeof(dxe_path), arguments[2], "dxe.fv");
	failures += build_path(output_path, sizeof(output_path), arguments[2], "packed.fv");
	failures += build_path(selected_ffs_path, sizeof(selected_ffs_path), arguments[2],
			      "selected.ffs");
	failures += build_path(stale_ffs_path, sizeof(stale_ffs_path), arguments[2], "stale.ffs");
	failures += build_path(short_ffs_path, sizeof(short_ffs_path), arguments[2], "short.ffs");
	failures += build_path(ffs_list_path, sizeof(ffs_list_path), arguments[2], "ffs-list.txt");
	failures +=
		build_path(manifest_path, sizeof(manifest_path), arguments[2], "fvpack.manifest");

	entry_size = build_no_reloc_pe32_plus(entry, sizeof(entry));
	dxe_size = build_dxe_volume(dxe, sizeof(dxe));
	failures += expect(entry_size != 0, "cannot build test PE32+ entry");
	failures += expect(dxe_size != 0, "cannot build test DXE FV");

	if (failures == 0) {
		failures += write_binary_file(entry_path, entry, entry_size);
		failures += write_binary_file(dxe_path, dxe, dxe_size);
	}

	if (failures == 0) {
		failures += run_packer(arguments[1], output_path, entry_path, dxe_path, 1);
	}

	if (failures == 0) {
		failures += run_packer_with_size(arguments[1], output_path, entry_path, dxe_path,
					     "0x80", 0);
	}

	if (failures == 0) {
		packed = read_binary_file(output_path, &packed_size);
		failures += expect(packed != NULL, "cannot read packed FV");
	}

	if (failures == 0) {
		failures += find_packed_entry_image_base(packed, packed_size, &image_base,
						     &expected_base);
	}

	if (failures == 0) {
		if (image_base != expected_base) {
			fprintf(stderr,
				"cdk2 fvpack test: packed no-relocation PE32+ image_base is 0x%llx, expected 0x%llx\n",
				(unsigned long long)image_base,
				(unsigned long long)expected_base);
			failures++;
		}
	}

	if (failures == 0) {
		entry_size = build_wrapped_reloc_pe32_plus(entry, sizeof(entry));
		failures +=
			expect(entry_size != 0, "cannot build wrapped-relocation PE32+ entry");
		if (failures == 0) {
			failures += write_binary_file(entry_path, entry, entry_size);
		}
		if (failures == 0) {
			failures += run_packer(arguments[1], output_path, entry_path, dxe_path, 0);
		}
	}

	if (failures == 0) {
		entry_size = build_downward_reloc_pe32_plus(entry, sizeof(entry));
		failures +=
			expect(entry_size != 0, "cannot build downward-relocation PE32+ entry");
		if (failures == 0) {
			failures += write_binary_file(entry_path, entry, entry_size);
		}
		if (failures == 0) {
			failures += run_packer(arguments[1], output_path, entry_path, dxe_path, 1);
		}
		if (failures == 0) {
			free(packed);
			packed = read_binary_file(output_path, &packed_size);
			failures += expect(packed != NULL, "cannot read downward-relocated FV");
		}
		if (failures == 0) {
			failures += find_packed_entry_image_base(packed, packed_size, &image_base,
							     &expected_base);
			failures += expect(image_base == expected_base,
					   "downward-relocated image base is wrong");
		}
	}

	if (failures == 0) {
		entry_size = build_no_reloc_pe32_plus(entry, sizeof(entry));
		failures += expect(entry_size != 0, "cannot rebuild test PE32+ entry");
		if (failures == 0) {
			failures += write_binary_file(entry_path, entry, entry_size);
		}
	}

	if (failures == 0) {
		selected_ffs_size = build_ffs(selected_ffs, sizeof(selected_ffs), dxe_core_guid,
					   EFI_FV_FILETYPE_DXE_CORE);
		stale_ffs_size =
			build_ffs(stale_ffs, sizeof(stale_ffs), stale_guid, EFI_FV_FILETYPE_DRIVER);
		dxe_size = build_dxe_volume_with_ffs(dxe, sizeof(dxe), selected_ffs, selected_ffs_size);
		failures += expect(selected_ffs_size != 0, "cannot build selected test FFS");
		failures += expect(stale_ffs_size != 0, "cannot build stale test FFS");
		failures += expect(dxe_size != 0, "cannot build flat test DXE FV");
	}

	if (failures == 0) {
		failures += write_binary_file(selected_ffs_path, selected_ffs, selected_ffs_size);
		failures += write_binary_file(stale_ffs_path, stale_ffs, stale_ffs_size);
		failures += write_binary_file(dxe_path, dxe, dxe_size);
	}

	if (failures == 0) {
		failures += write_manifest(manifest_path, 0x48, dxe_core_guid, selected_ffs_path, 0,
					  NULL, NULL);
		failures += run_manifest_verifier(arguments[1], dxe_path, manifest_path, 1);
		failures +=
			run_manifest_packer(arguments[1], output_path, entry_path, manifest_path, 1);
	}

	if (failures == 0) {
		failures += write_manifest(manifest_path, 0x50, dxe_core_guid, selected_ffs_path, 0,
					  NULL, NULL);
		failures += run_manifest_verifier(arguments[1], dxe_path, manifest_path, 0);
	}

	if (failures == 0) {
		failures += write_manifest(manifest_path, 0x48, stale_guid, selected_ffs_path, 0,
					  NULL, NULL);
		failures +=
			run_manifest_packer(arguments[1], output_path, entry_path, manifest_path, 0);
	}

	if (failures == 0) {
		failures += write_manifest(manifest_path, 0x48, dxe_core_guid, selected_ffs_path,
					  align_up(0x48 + selected_ffs_size, 8), stale_guid,
					  stale_ffs_path);
		failures += run_manifest_verifier(arguments[1], dxe_path, manifest_path, 0);
	}

	if (failures == 0) {
		failures += write_binary_file(short_ffs_path, short_ffs, sizeof(short_ffs));
		count = snprintf(ffs_list_text, sizeof(ffs_list_text), "%s\n", short_ffs_path);
		if (count < 0 || (size_t)count >= sizeof(ffs_list_text)) {
			failures += expect(0, "FFS list path is too long");
		}
	}

	if (failures == 0) {
		failures += write_text_file(ffs_list_path, ffs_list_text);
		failures += run_ffs_list_packer(arguments[1], output_path, entry_path, dxe_path,
					     ffs_list_path, 0);
	}

	free(packed);
	if (entry_path[0] != '\0') {
		remove(entry_path);
	}

	if (dxe_path[0] != '\0') {
		remove(dxe_path);
	}

	if (output_path[0] != '\0') {
		remove(output_path);
	}

	if (selected_ffs_path[0] != '\0') {
		remove(selected_ffs_path);
	}

	if (stale_ffs_path[0] != '\0') {
		remove(stale_ffs_path);
	}

	if (short_ffs_path[0] != '\0') {
		remove(short_ffs_path);
	}

	if (ffs_list_path[0] != '\0') {
		remove(ffs_list_path);
	}

	if (manifest_path[0] != '\0') {
		remove(manifest_path);
	}

	if (failures != 0) {
		return 1;
	}

	puts("cdk2 fvpack test: PASS");
	return 0;
}
