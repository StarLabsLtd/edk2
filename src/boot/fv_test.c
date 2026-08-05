/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host checks for native firmware-volume discovery.
 */

#include "fv.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FV_SIZE       0x200U
#define CDK2_FV_BLOCK_SIZE 0x1000U
#define TEST_FV_EXT_OFFSET 0x50U

static UINT32 get24(const UINT8 *value)
{
	return (UINT32)value[0] | ((UINT32)value[1] << 8) | ((UINT32)value[2] << 16);
}

static int read_uint24(const UINT8 *buffer, UINTN buffer_size, UINTN offset, UINTN *value)
{
	if (offset > buffer_size || (buffer_size - offset) < 3U) {
		return 0;
	}

	*value = (UINTN)get24(buffer + offset);
	return 1;
}

static int read_uint64(const UINT8 *buffer, UINTN buffer_size, UINTN offset, UINTN *value)
{
	UINT64 local_value;

	if (offset > buffer_size || (buffer_size - offset) < sizeof(local_value)) {
		return 0;
	}

	memcpy(&local_value, buffer + offset, sizeof(local_value));
	*value = (UINTN)local_value;
	return 1;
}

static UINTN align_up8(UINTN value)
{
	return (value + 7U) & ~(UINTN)7U;
}

static void put24(UINT8 *value, UINTN size)
{
	value[0] = (UINT8)size;
	value[1] = (UINT8)(size >> 8);
	value[2] = (UINT8)(size >> 16);
}

static int is_erased(const UINT8 *data, UINTN size)
{
	UINTN index;

	for (index = 0; index < size; index++) {
		if (data[index] != 0xFF) {
			return 0;
		}
	}

	return 1;
}

static UINT8 checksum8(const UINT8 *buffer, UINTN length)
{
	UINT8 sum;
	UINTN index;

	sum = 0;
	for (index = 0; index < length; index++) {
		sum = (UINT8)(sum + buffer[index]);
	}

	return (UINT8)(0U - sum);
}

static UINT16 checksum16(const UINT8 *buffer, UINTN length)
{
	UINT32 sum;
	UINTN index;

	sum = 0;
	for (index = 0; index < length; index += 2) {
		sum += (UINT32)buffer[index] | ((UINT32)buffer[index + 1] << 8);
	}

	return (UINT16)(0U - (UINT16)sum);
}

static EFI_FFS_FILE_HEADER *first_file(UINT8 *storage)
{
	return (EFI_FFS_FILE_HEADER *)(void *)(storage +
					       ((sizeof(EFI_FIRMWARE_VOLUME_HEADER) + 7U) &
						~(UINTN)7U));
}

static void finalize_ffs_header(EFI_FFS_FILE_HEADER *file, UINTN header_size)
{
	file->integrity_check.checksum.header = 0;
	file->integrity_check.checksum.file = 0;
	file->state = 0;
	file->integrity_check.checksum.header = checksum8((const UINT8 *)file, header_size);
	file->integrity_check.checksum.file = FFS_FIXED_CHECKSUM;
	file->state =
		(UINT8)~(EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID |
			 EFI_FILE_DATA_VALID);
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 FV test: %s\n", message);
		return 1;
	}

	return 0;
}

static UINTN build_volume_at(UINT8 *storage, UINTN storage_size, UINTN file_offset)
{
	EFI_FIRMWARE_VOLUME_HEADER *volume;
	EFI_FFS_FILE_HEADER *file;
	EFI_COMMON_SECTION_HEADER *section;
	UINTN file_size;

	memset(storage, 0xff, storage_size);
	volume = (EFI_FIRMWARE_VOLUME_HEADER *)(void *)storage;
	volume->fv_length = 0x180;
	volume->signature = EFI_FVH_SIGNATURE;
	volume->header_length = sizeof(*volume);
	volume->ext_header_offset = 0;
	volume->revision = 2;
	file = (EFI_FFS_FILE_HEADER *)(void *)(storage + file_offset);
	memset(file, 0, sizeof(*file));
	file->type = EFI_FV_FILETYPE_DXE_CORE;
	file->state = 0xf8;
	file_size = sizeof(*file) + sizeof(*section) + 8;
	file->size[0] = (UINT8)file_size;
	file->size[1] = (UINT8)(file_size >> 8);
	file->size[2] = (UINT8)(file_size >> 16);
	section = (EFI_COMMON_SECTION_HEADER *)(void *)((UINT8 *)file + sizeof(*file));
	section->size[0] = (UINT8)(sizeof(*section) + 8);
	section->size[1] = (UINT8)((sizeof(*section) + 8) >> 8);
	section->size[2] = 0;
	section->type = EFI_SECTION_PE32;
	memcpy((UINT8 *)section + sizeof(*section), "MZCDK2!!", 8);
	finalize_ffs_header(file, sizeof(*file));

	volume->checksum = 0;
	volume->checksum = checksum16(storage, volume->header_length);
	return (UINTN)volume->fv_length;
}

static UINTN build_volume(UINT8 *storage, UINTN storage_size)
{
	return build_volume_at(storage, storage_size,
			       align_up8(sizeof(EFI_FIRMWARE_VOLUME_HEADER)));
}

static UINTN build_extended_header_volume(UINT8 *storage, UINTN storage_size)
{
	EFI_FIRMWARE_VOLUME_HEADER *volume;
	EFI_FIRMWARE_VOLUME_EXT_HEADER *extension;
	UINTN volume_size;
	UINTN file_offset;

	file_offset = align_up8(TEST_FV_EXT_OFFSET + sizeof(*extension));
	volume_size = build_volume_at(storage, storage_size, file_offset);
	volume = (EFI_FIRMWARE_VOLUME_HEADER *)(void *)storage;
	volume->ext_header_offset = TEST_FV_EXT_OFFSET;
	extension = (EFI_FIRMWARE_VOLUME_EXT_HEADER *)(void *)(storage + TEST_FV_EXT_OFFSET);
	memset(extension, 0, sizeof(*extension));
	extension->ext_header_size = sizeof(*extension);
	volume->checksum = 0;
	volume->checksum = checksum16(storage, volume->header_length);
	return volume_size;
}

static UINTN build_nested_volume(UINT8 *storage, UINTN storage_size, BOOLEAN nested_ext_header)
{
	EFI_FIRMWARE_VOLUME_HEADER *volume;
	EFI_FFS_FILE_HEADER *file;
	EFI_COMMON_SECTION_HEADER *section;
	UINTN file_offset;
	UINTN nested_size;
	UINTN file_size;

	memset(storage, 0xff, storage_size);
	volume = (EFI_FIRMWARE_VOLUME_HEADER *)(void *)storage;
	volume->fv_length = storage_size;
	volume->signature = EFI_FVH_SIGNATURE;
	volume->header_length = sizeof(*volume);
	volume->ext_header_offset = 0;
	volume->revision = 2;
	file_offset = (sizeof(*volume) + 7U) & ~(UINTN)7U;
	file = (EFI_FFS_FILE_HEADER *)(void *)(storage + file_offset);
	memset(file, 0, sizeof(*file));
	file->type = EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE;
	file->state = 0xf8;
	section = (EFI_COMMON_SECTION_HEADER *)(void *)((UINT8 *)file + sizeof(*file));
	if (nested_ext_header) {
		nested_size = build_extended_header_volume(
			(UINT8 *)section + sizeof(*section),
			storage_size - file_offset - sizeof(*file) - sizeof(*section));
	} else {
		nested_size = build_volume((UINT8 *)section + sizeof(*section),
					   storage_size - file_offset - sizeof(*file) -
						   sizeof(*section));
	}
	file_size = sizeof(*file) + sizeof(*section) + nested_size;
	put24(file->size, file_size);
	put24(section->size, sizeof(*section) + nested_size);
	section->type = EFI_SECTION_FIRMWARE_VOLUME_IMAGE;
	finalize_ffs_header(file, sizeof(*file));

	volume->checksum = 0;
	volume->checksum = checksum16(storage, volume->header_length);
	return (UINTN)volume->fv_length;
}

static UINTN
build_large_file_volume(UINT8 *storage, UINTN storage_size, UINTN encoded_file_size)
{
	EFI_FIRMWARE_VOLUME_HEADER *volume;
	EFI_FFS_FILE_HEADER2 *file;
	EFI_COMMON_SECTION_HEADER *section;
	UINTN file_offset;
	UINTN file_size;

	memset(storage, 0xff, storage_size);
	volume = (EFI_FIRMWARE_VOLUME_HEADER *)(void *)storage;
	volume->fv_length = 0x180;
	volume->signature = EFI_FVH_SIGNATURE;
	volume->header_length = sizeof(*volume);
	volume->ext_header_offset = 0;
	volume->revision = 2;
	file_offset = (sizeof(*volume) + 7U) & ~(UINTN)7U;
	file = (EFI_FFS_FILE_HEADER2 *)(void *)(storage + file_offset);
	memset(file, 0, sizeof(*file));
	file->type = EFI_FV_FILETYPE_DXE_CORE;
	file->attributes = FFS_ATTRIB_LARGE_FILE;
	file->state = 0xf8;
	file_size = sizeof(*file) + sizeof(*section) + 8;
	file->size[0] = (UINT8)encoded_file_size;
	file->size[1] = (UINT8)(encoded_file_size >> 8);
	file->size[2] = (UINT8)(encoded_file_size >> 16);
	file->extended_size = file_size;
	section = (EFI_COMMON_SECTION_HEADER *)(void *)((UINT8 *)file + sizeof(*file));
	section->size[0] = (UINT8)(sizeof(*section) + 8);
	section->size[1] = (UINT8)((sizeof(*section) + 8) >> 8);
	section->size[2] = 0;
	section->type = EFI_SECTION_PE32;
	memcpy((UINT8 *)section + sizeof(*section), "MZCDK2!!", 8);
	finalize_ffs_header((EFI_FFS_FILE_HEADER *)file, sizeof(*file));

	volume->checksum = 0;
	volume->checksum = checksum16(storage, volume->header_length);
	return (UINTN)volume->fv_length;
}

static int validate_file(const char *path)
{
	FILE *file;
	long length;
	UINT8 *storage;
	const EFI_FIRMWARE_VOLUME_HEADER *volume;
	const EFI_FFS_FILE_HEADER *ffs_file;
	struct cdk2_native_dxe_core dxe_core;
	EFI_STATUS status;
	UINTN file_offset;
	UINTN file_size;
	UINTN file_header_size;
	UINTN occupied_file_size;
	UINTN remaining;
	int failures;
	int found_payload_entry;
	int found_dxe_core;
	int found_non_pad_file;

	file = fopen(path, "rb");
	if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
		if (file != NULL) {
			fclose(file);
		}

		fprintf(stderr, "cdk2 FV test: cannot open %s\n", path);
		return 1;
	}

	length = ftell(file);
	if (length <= 0 || fseek(file, 0, SEEK_SET) != 0) {
		fclose(file);
		fprintf(stderr, "cdk2 FV test: invalid size for %s\n", path);
		return 1;
	}

	storage = malloc((size_t)length);
	if (storage == NULL || fread(storage, 1, (size_t)length, file) != (size_t)length) {
		free(storage);
		fclose(file);
		fprintf(stderr, "cdk2 FV test: cannot read %s\n", path);
		return 1;
	}

	fclose(file);

	failures = 0;
	if ((UINTN)length < sizeof(EFI_FIRMWARE_VOLUME_HEADER)) {
		free(storage);
		fprintf(stderr, "cdk2 FV test: %s is smaller than an FV header\n", path);
		return 1;
	}

	volume = (const EFI_FIRMWARE_VOLUME_HEADER *)(const void *)storage;
	failures += expect(volume->signature == EFI_FVH_SIGNATURE,
			   "native FV has an invalid signature");
	failures += expect((UINT64)(UINTN)length == volume->fv_length,
			   "native FV file is not compact");
	failures += expect((((UINTN)length & (CDK2_FV_BLOCK_SIZE - 1U)) == 0),
			   "native FV file is not block aligned");

	if (volume->header_length < sizeof(EFI_FIRMWARE_VOLUME_HEADER) ||
	    volume->header_length > (UINTN)length) {
		free(storage);
		fprintf(stderr, "cdk2 FV test: native FV has invalid header bounds\n");
		return 1;
	}

	file_offset = (volume->header_length + 7U) & ~(UINTN)7U;
	remaining = ((UINTN)length > file_offset) ? (UINTN)length - file_offset : 0;
	found_payload_entry = 0;
	found_dxe_core = 0;
	found_non_pad_file = 0;
	while (remaining >= sizeof(EFI_FFS_FILE_HEADER)) {
		ffs_file = (const EFI_FFS_FILE_HEADER *)(const void *)(storage + file_offset);
		if (is_erased((const UINT8 *)ffs_file, sizeof(*ffs_file))) {
			break;
		}

		file_header_size = sizeof(EFI_FFS_FILE_HEADER);
		if (!read_uint24(storage, (UINTN)length,
				 file_offset + offsetof(EFI_FFS_FILE_HEADER, size),
				 &file_size)) {
			failures += expect(0, "native FV contains a truncated FFS file size");
			break;
		}

		if ((ffs_file->attributes & FFS_ATTRIB_LARGE_FILE) != 0) {
			file_header_size = sizeof(EFI_FFS_FILE_HEADER2);
			if (remaining < file_header_size ||
			    !read_uint64(storage, (UINTN)length,
					 file_offset +
						 offsetof(EFI_FFS_FILE_HEADER2, extended_size),
					 &file_size)) {
				failures += expect(0, "native FV contains a truncated large FFS file");
				break;
			}
		}

		if (file_size < file_header_size || file_size > remaining) {
			failures += expect(0, "native FV contains an invalid FFS file");
			break;
		}

		if (ffs_file->type != EFI_FV_FILETYPE_FFS_PAD) {
			if (!found_non_pad_file) {
				failures += expect(
					ffs_file->type == EFI_FV_FILETYPE_SECURITY_CORE,
					"native FV first payload file is not the entry image");
				found_payload_entry =
					(ffs_file->type == EFI_FV_FILETYPE_SECURITY_CORE);
			}

			found_non_pad_file = 1;
			found_dxe_core |=
				(ffs_file->type == EFI_FV_FILETYPE_DXE_CORE ||
				 ffs_file->type == EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE);
		}

		occupied_file_size = (file_size + 7U) & ~(UINTN)7U;
		if (occupied_file_size > remaining) {
			failures += expect(0, "native FV FFS file alignment overflows");
			break;
		}

		file_offset += occupied_file_size;
		remaining -= occupied_file_size;
	}

	failures += expect(found_payload_entry, "native FV has no payload entry file");
	failures += expect(found_dxe_core, "native FV has no DXE core carrier file");

	status = cdk2_native_find_dxe_core(storage, (UINTN)length, &dxe_core);
	free(storage);
	if (status != EFI_SUCCESS || dxe_core.pe32_image == NULL || dxe_core.pe32_size == 0) {
		fprintf(stderr, "cdk2 FV test: no valid DXE core in %s\n", path);
		return 1;
	}

	if (failures != 0) {
		return 1;
	}

	printf("cdk2 FV file: PASS (%s)\n", path);
	return 0;
}

int main(int argument_count, char **arguments)
{
	UINT8 storage[TEST_FV_SIZE];
	struct cdk2_native_dxe_core dxe_core;
	UINTN volume_size;
	EFI_STATUS status;
	EFI_FFS_FILE_HEADER *file;
	EFI_COMMON_SECTION_HEADER *section;
	int failures;

	if (argument_count == 2) {
		return validate_file(arguments[1]);
	}

	failures = 0;
	volume_size = build_volume(storage, sizeof(storage));
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_SUCCESS, "valid FV rejected");
	failures += expect(dxe_core.pe32_size == 8, "PE32 section size is wrong");
	failures += expect(memcmp(dxe_core.pe32_image, "MZCDK2!!", 8) == 0,
			   "PE32 section data is wrong");

	volume_size = build_extended_header_volume(storage, sizeof(storage));
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_SUCCESS, "extended-header FV rejected");
	failures += expect(dxe_core.pe32_size == 8, "extended-header PE32 section size is wrong");
	failures += expect(memcmp(dxe_core.pe32_image, "MZCDK2!!", 8) == 0,
			   "extended-header PE32 section data is wrong");

	volume_size = build_nested_volume(storage, sizeof(storage), FALSE);
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_SUCCESS, "nested DXE FV rejected");
	failures += expect(dxe_core.pe32_size == 8, "nested PE32 section size is wrong");
	failures += expect(memcmp(dxe_core.pe32_image, "MZCDK2!!", 8) == 0,
			   "nested PE32 section data is wrong");

	volume_size = build_nested_volume(storage, sizeof(storage), TRUE);
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_SUCCESS, "nested extended-header DXE FV rejected");
	failures += expect(dxe_core.pe32_size == 8,
			   "nested extended-header PE32 section size is wrong");
	failures += expect(memcmp(dxe_core.pe32_image, "MZCDK2!!", 8) == 0,
			   "nested extended-header PE32 section data is wrong");

	status = cdk2_native_find_dxe_core(storage, volume_size - 1, &dxe_core);
	failures += expect(status == EFI_COMPROMISED_DATA, "truncated FV accepted");

	storage[offsetof(EFI_FIRMWARE_VOLUME_HEADER, checksum)] ^= 1;
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad FV checksum accepted");
	volume_size = build_volume(storage, sizeof(storage));

	file = first_file(storage);
	file->integrity_check.checksum.header ^= 1U;
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad FFS header checksum accepted");
	volume_size = build_volume(storage, sizeof(storage));

	file = first_file(storage);
	file->integrity_check.checksum.file = 0;
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_COMPROMISED_DATA, "bad FFS data checksum accepted");
	volume_size = build_volume(storage, sizeof(storage));

	file = first_file(storage);
	file->state = (UINT8)~EFI_FILE_DELETED;
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_NOT_FOUND, "deleted DXE core was selected");
	volume_size = build_volume(storage, sizeof(storage));

	file = first_file(storage);
	file->state =
		(UINT8)~(EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID |
			 EFI_FILE_DATA_VALID | EFI_FILE_MARKED_FOR_UPDATE);
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_SUCCESS, "marked-for-update DXE core was rejected");
	volume_size = build_volume(storage, sizeof(storage));

	file = first_file(storage);
	file->state = 0xffU;
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_COMPROMISED_DATA, "invalid FFS state accepted");
	volume_size = build_volume(storage, sizeof(storage));

	section = (EFI_COMMON_SECTION_HEADER *)(void *)(storage +
							((sizeof(EFI_FIRMWARE_VOLUME_HEADER) +
							  7U) &
							 ~(UINTN)7U) +
							sizeof(EFI_FFS_FILE_HEADER));
	section->size[0] = 3;
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_COMPROMISED_DATA, "short section accepted");

	volume_size = build_large_file_volume(storage, sizeof(storage), 0);
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_SUCCESS, "valid large FFS header rejected");

	volume_size =
		build_large_file_volume(storage, sizeof(storage), sizeof(EFI_FFS_FILE_HEADER2));
	status = cdk2_native_find_dxe_core(storage, volume_size, &dxe_core);
	failures += expect(status == EFI_COMPROMISED_DATA,
			   "large FFS header with nonzero size accepted");

	if (failures != 0) {
		return 1;
	}

	puts("cdk2 FV test: PASS");
	return 0;
}
