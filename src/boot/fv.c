/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Bounds-checked firmware-volume discovery for native cdk2.
 */

#include "fv.h"

#define CDK2_NATIVE_FV_MAX_DEPTH 4U

static UINT32 cdk2_native_get24(const UINT8 *value)
{
	return (UINT32)value[0] | ((UINT32)value[1] << 8) | ((UINT32)value[2] << 16);
}

static UINT8 cdk2_native_sum8(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT8 sum;
	UINTN index;

	bytes = (const UINT8 *)buffer;
	sum = 0;
	for (index = 0; index < length; index++) {
		sum = (UINT8)(sum + bytes[index]);
	}

	return sum;
}

static UINT8 cdk2_native_checksum8(const void *buffer, UINTN length)
{
	return (UINT8)(0U - cdk2_native_sum8(buffer, length));
}

static BOOLEAN cdk2_native_align_up8(UINTN value, UINTN *aligned_value)
{
	if (aligned_value == NULL || value > MAX_UINTN - 7U) {
		return FALSE;
	}

	*aligned_value = (value + 7U) & ~(UINTN)7U;
	return TRUE;
}

static UINT16 cdk2_native_checksum16(const void *buffer, UINTN length)
{
	const UINT8 *bytes;
	UINT32 sum;
	UINTN index;

	bytes = (const UINT8 *)buffer;
	sum = 0;
	for (index = 0; index < length; index += 2) {
		sum += (UINT32)bytes[index] | ((UINT32)bytes[index + 1] << 8);
	}

	return (UINT16)(0U - (UINT16)sum);
}

static BOOLEAN cdk2_native_buffer_erased(const UINT8 *buffer, UINTN length,
					 BOOLEAN erase_polarity)
{
	UINT8 erased_byte;
	UINTN index;

	erased_byte = erase_polarity ? 0xffU : 0U;
	for (index = 0; index < length; index++) {
		if (buffer[index] != erased_byte) {
			return FALSE;
		}
	}

	return TRUE;
}

static EFI_FFS_FILE_STATE cdk2_native_file_state(const EFI_FFS_FILE_HEADER *file,
						 BOOLEAN erase_polarity)
{
	EFI_FFS_FILE_STATE file_state;
	EFI_FFS_FILE_STATE highest_bit;

	file_state = file->state;
	if (erase_polarity) {
		file_state = (EFI_FFS_FILE_STATE)~file_state;
	}

	highest_bit = 0x80U;
	while (highest_bit != 0 && (file_state & highest_bit) == 0) {
		highest_bit >>= 1;
	}

	return highest_bit;
}

static EFI_STATUS
cdk2_native_get_ffs_start_offset(const EFI_FIRMWARE_VOLUME_HEADER *volume, UINTN volume_length,
				 UINTN *file_offset)
{
	const EFI_FIRMWARE_VOLUME_EXT_HEADER *extension;
	UINTN offset;
	UINTN extension_size;

	if (volume == NULL || file_offset == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (volume->ext_header_offset == 0) {
		offset = volume->header_length;
	} else {
		offset = volume->ext_header_offset;
		if (offset < volume->header_length || offset > volume_length ||
		    volume_length - offset < sizeof(*extension)) {
			return EFI_COMPROMISED_DATA;
		}

		extension =
			(const EFI_FIRMWARE_VOLUME_EXT_HEADER *)(const void *)((const UINT8 *)volume +
									       offset);
		extension_size = extension->ext_header_size;
		if (extension_size < sizeof(*extension) ||
		    extension_size > volume_length - offset) {
			return EFI_COMPROMISED_DATA;
		}

		offset += extension_size;
	}

	if (!cdk2_native_align_up8(offset, file_offset) || *file_offset > volume_length) {
		return EFI_COMPROMISED_DATA;
	}

	return EFI_SUCCESS;
}

static BOOLEAN cdk2_native_ffs_header_checksum_valid(const EFI_FFS_FILE_HEADER *file,
						     UINTN file_header_size)
{
	UINT8 header_sum;

	header_sum = cdk2_native_sum8(file, file_header_size);
	header_sum = (UINT8)(header_sum - file->state - file->integrity_check.checksum.file);
	return header_sum == 0;
}

static BOOLEAN cdk2_native_ffs_data_checksum_valid(const EFI_FFS_FILE_HEADER *file,
						   UINTN file_size, UINTN file_header_size)
{
	UINT8 data_checksum;

	data_checksum = FFS_FIXED_CHECKSUM;
	if ((file->attributes & FFS_ATTRIB_CHECKSUM) != 0) {
		data_checksum =
			cdk2_native_checksum8((const UINT8 *)file + file_header_size,
					      file_size - file_header_size);
	}

	return file->integrity_check.checksum.file == data_checksum;
}

static EFI_STATUS
cdk2_native_find_section(const UINT8 *file, UINTN file_size, EFI_SECTION_TYPE section_type,
			 const void **section_data, UINTN *section_data_size)
{
	const UINT8 *section;
	UINTN header_size;
	UINTN remaining;
	UINTN section_size;
	UINTN occupied_size;

	if (file == NULL || section_data == NULL || section_data_size == NULL ||
	    file_size < sizeof(EFI_FFS_FILE_HEADER)) {
		return EFI_INVALID_PARAMETER;
	}

	header_size = sizeof(EFI_FFS_FILE_HEADER);
	if ((((const EFI_FFS_FILE_HEADER *)file)->attributes & FFS_ATTRIB_LARGE_FILE) != 0) {
		if (cdk2_native_get24(((const EFI_FFS_FILE_HEADER *)file)->size) != 0) {
			return EFI_COMPROMISED_DATA;
		}

		header_size = sizeof(EFI_FFS_FILE_HEADER2);
		if (file_size < header_size) {
			return EFI_COMPROMISED_DATA;
		}
	}

	if (header_size > file_size) {
		return EFI_COMPROMISED_DATA;
	}

	section = file + header_size;
	remaining = file_size - header_size;
	while (remaining != 0) {
		if (remaining < sizeof(EFI_COMMON_SECTION_HEADER)) {
			return EFI_COMPROMISED_DATA;
		}

		section_size = cdk2_native_get24(section);
		if (section_size == 0x00ffffffU) {
			if (remaining < sizeof(EFI_COMMON_SECTION_HEADER2)) {
				return EFI_COMPROMISED_DATA;
			}

			section_size =
				((const EFI_COMMON_SECTION_HEADER2 *)section)->extended_size;
			header_size = sizeof(EFI_COMMON_SECTION_HEADER2);
		} else {
			header_size = sizeof(EFI_COMMON_SECTION_HEADER);
		}

		if (section_size < header_size || section_size > remaining) {
			return EFI_COMPROMISED_DATA;
		}

		occupied_size = (section_size + 3U) & ~(UINTN)3U;
		if (occupied_size > remaining) {
			return EFI_COMPROMISED_DATA;
		}

		if (section[3] == section_type) {
			*section_data = section + header_size;
			*section_data_size = section_size - header_size;
			return EFI_SUCCESS;
		}

		section += occupied_size;
		remaining -= occupied_size;
	}

	return EFI_NOT_FOUND;
}

static EFI_STATUS
cdk2_native_find_dxe_core_at_depth(const void *firmware_volume, UINTN firmware_volume_size,
				   struct cdk2_native_dxe_core *dxe_core, UINTN depth)
{
	const EFI_FIRMWARE_VOLUME_HEADER *volume;
	const EFI_FFS_FILE_HEADER *file;
	UINTN volume_length;
	UINTN header_length;
	UINTN file_offset;
	UINTN remaining;
	UINTN file_size;
	UINTN file_header_size;
	UINTN occupied_file_size;
	EFI_FFS_FILE_STATE file_state;
	BOOLEAN erase_polarity;
	const void *section_data;
	UINTN section_data_size;
	struct cdk2_native_dxe_core child_dxe_core;
	EFI_STATUS status;

	if (firmware_volume == NULL || dxe_core == NULL ||
	    firmware_volume_size < sizeof(EFI_FIRMWARE_VOLUME_HEADER)) {
		return EFI_INVALID_PARAMETER;
	}

	if (depth >= CDK2_NATIVE_FV_MAX_DEPTH) {
		return EFI_COMPROMISED_DATA;
	}

	volume = (const EFI_FIRMWARE_VOLUME_HEADER *)firmware_volume;
	header_length = volume->header_length;
	if (volume->signature != EFI_FVH_SIGNATURE || (volume->fv_length & 1U) != 0 ||
	    volume->fv_length < header_length || volume->fv_length > firmware_volume_size ||
	    header_length < sizeof(EFI_FIRMWARE_VOLUME_HEADER) ||
	    header_length > firmware_volume_size || (header_length & 1U) != 0 ||
	    cdk2_native_checksum16(volume, header_length) != 0) {
		return EFI_COMPROMISED_DATA;
	}

	volume_length = (UINTN)volume->fv_length;
	erase_polarity = ((volume->attributes & EFI_FVB2_ERASE_POLARITY) != 0);
	*dxe_core = (struct cdk2_native_dxe_core){0};
	dxe_core->volume = volume;
	dxe_core->volume_size = volume_length;

	status = cdk2_native_get_ffs_start_offset(volume, volume_length, &file_offset);
	if (EFI_ERROR(status)) {
		return status;
	}

	remaining = volume_length - file_offset;
	while (remaining >= sizeof(EFI_FFS_FILE_HEADER)) {
		file = (const EFI_FFS_FILE_HEADER *)((const UINT8 *)volume + file_offset);
		if (cdk2_native_buffer_erased((const UINT8 *)file, sizeof(*file),
					      erase_polarity)) {
			break;
		}

		file_header_size = sizeof(EFI_FFS_FILE_HEADER);
		file_size = cdk2_native_get24(file->size);
		if ((file->attributes & FFS_ATTRIB_LARGE_FILE) != 0) {
			if (file_size != 0) {
				return EFI_COMPROMISED_DATA;
			}

			file_header_size = sizeof(EFI_FFS_FILE_HEADER2);
			if (remaining < file_header_size) {
				return EFI_COMPROMISED_DATA;
			}

			file_size = (UINTN)((const EFI_FFS_FILE_HEADER2 *)file)->extended_size;
		}

		if (file_size == 0 || file_size < file_header_size || file_size > remaining) {
			return EFI_COMPROMISED_DATA;
		}

		file_state = cdk2_native_file_state(file, erase_polarity);
		if (file_state == EFI_FILE_HEADER_CONSTRUCTION ||
		    file_state == EFI_FILE_HEADER_INVALID || file_state == 0 ||
		    !cdk2_native_ffs_header_checksum_valid(file, file_header_size)) {
			return EFI_COMPROMISED_DATA;
		}

		if (file_state != EFI_FILE_DATA_VALID &&
		    file_state != EFI_FILE_MARKED_FOR_UPDATE) {
			occupied_file_size = (file_size + 7U) & ~(UINTN)7U;
			if (occupied_file_size > remaining) {
				return EFI_COMPROMISED_DATA;
			}

			file_offset += occupied_file_size;
			remaining -= occupied_file_size;
			continue;
		}

		if (!cdk2_native_ffs_data_checksum_valid(file, file_size,
							 file_header_size)) {
			return EFI_COMPROMISED_DATA;
		}

		if (file->type == EFI_FV_FILETYPE_DXE_CORE) {
			status = cdk2_native_find_section((const UINT8 *)file, file_size,
							  EFI_SECTION_PE32,
							  &section_data,
							  &section_data_size);
			if (!EFI_ERROR(status)) {
				dxe_core->volume = volume;
				dxe_core->volume_size = volume_length;
				dxe_core->dxe_core_file = file;
				dxe_core->pe32_image = section_data;
				dxe_core->pe32_size = section_data_size;
				return EFI_SUCCESS;
			}

			if (status != EFI_NOT_FOUND) {
				return status;
			}
		} else if (file->type == EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE) {
			status = cdk2_native_find_section(
				(const UINT8 *)file, file_size,
				EFI_SECTION_FIRMWARE_VOLUME_IMAGE, &section_data,
				&section_data_size);
			if (EFI_ERROR(status)) {
				return status;
			}

			status = cdk2_native_find_dxe_core_at_depth(
				section_data, section_data_size, &child_dxe_core, depth + 1U);
			if (!EFI_ERROR(status)) {
				*dxe_core = child_dxe_core;
				return EFI_SUCCESS;
			}

			if (status != EFI_NOT_FOUND) {
				return status;
			}
		}

		occupied_file_size = (file_size + 7U) & ~(UINTN)7U;
		if (occupied_file_size > remaining) {
			return EFI_COMPROMISED_DATA;
		}

		file_offset += occupied_file_size;
		remaining -= occupied_file_size;
	}

	return EFI_NOT_FOUND;
}

EFI_STATUS
cdk2_native_find_dxe_core(const void *firmware_volume, UINTN firmware_volume_size,
			  struct cdk2_native_dxe_core *dxe_core)
{
	return cdk2_native_find_dxe_core_at_depth(firmware_volume, firmware_volume_size,
						  dxe_core, 0);
}
