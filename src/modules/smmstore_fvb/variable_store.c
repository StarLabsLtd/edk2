/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

#define FV_HEADER_LENGTH 72U
#define VARIABLE_STORE_HEADER_LENGTH 28U
#define AUTH_VARIABLE_HEADER_LENGTH 60U
#define FV_SIGNATURE 0x4856465fU
#define FV_ATTRIBUTES 0x00000c36U
#define FV_REVISION 2U
#define VARIABLE_FORMATTED 0x5aU
#define VARIABLE_HEALTHY 0xfeU
#define VARIABLE_START_ID 0x55aaU

static const EFI_GUID system_nv_fv_guid = {
	0xfff12b8dU,
	0x7696U,
	0x4c8bU,
	{0xa9U, 0x85U, 0x27U, 0x47U, 0x07U, 0x5bU, 0x4fU, 0x50U}};
static const EFI_GUID authenticated_store_guid = {
	0xaaf32c78U,
	0x947bU,
	0x439aU,
	{0xa1U, 0x80U, 0x2eU, 0x14U, 0x4eU, 0xc3U, 0x77U, 0x92U}};

static UINT16 read16(const UINT8 *bytes)
{
	return (UINT16)bytes[0] | (UINT16)bytes[1] << 8;
}

static UINT32 read32(const UINT8 *bytes)
{
	return (UINT32)read16(bytes) | (UINT32)read16(bytes + 2) << 16;
}

static UINT64 read64(const UINT8 *bytes)
{
	return (UINT64)read32(bytes) | (UINT64)read32(bytes + 4) << 32;
}

static void write16(UINT8 *bytes, UINT16 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
}

static void write32(UINT8 *bytes, UINT32 value)
{
	write16(bytes, (UINT16)value);
	write16(bytes + 2, (UINT16)(value >> 16));
}

static void write64(UINT8 *bytes, UINT64 value)
{
	write32(bytes, (UINT32)value);
	write32(bytes + 4, (UINT32)(value >> 32));
}

static void fill(UINT8 *bytes, UINT8 value, UINTN size)
{
	while (size-- != 0)
		*bytes++ = value;
}

static void copy_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *out = destination;
	const UINT8 *in = source;

	while (size-- != 0)
		*out++ = *in++;
}

static BOOLEAN guid_equal(const UINT8 *bytes, const EFI_GUID *guid)
{
	const UINT8 *guid_bytes = (const UINT8 *)guid;
	UINTN index;

	for (index = 0; index < sizeof(*guid); index++)
		if (bytes[index] != guid_bytes[index])
			return FALSE;
	return TRUE;
}

static EFI_STATUS read_linear(struct cdk2_smmstore *store, UINT64 offset,
			      UINTN size, void *buffer)
{
	UINT8 *out = buffer;
	UINT64 total;
	EFI_STATUS status;

	status = cdk2_smmstore_total_size(store, &total);
	if (EFI_ERROR(status) || offset > total || size > total - offset)
		return EFI_COMPROMISED_DATA;
	while (size != 0) {
		UINT32 block = (UINT32)(offset / store->info.block_size);
		UINT32 block_offset = (UINT32)(offset % store->info.block_size);
		UINTN part = store->info.block_size - block_offset;

		if (part > size)
			part = size;
		status = cdk2_smmstore_read(store, block, block_offset, &part,
					    out);
		if (EFI_ERROR(status))
			return status;
		offset += part;
		out += part;
		size -= part;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_variable_store_format(struct cdk2_smmstore *store)
{
	UINT8 header[FV_HEADER_LENGTH + VARIABLE_STORE_HEADER_LENGTH];
	UINT64 total;
	UINT32 block;
	UINT32 checksum = 0;
	UINTN size;
	UINTN index;
	EFI_STATUS status;

	status = cdk2_smmstore_total_size(store, &total);
	if (EFI_ERROR(status) || total > MAX_UINT32 ||
	    store->info.block_size < sizeof(header))
		return EFI_UNSUPPORTED;
	for (block = 0; block < store->info.num_blocks; block++) {
		status = cdk2_smmstore_erase(store, block);
		if (EFI_ERROR(status))
			return status;
	}
	fill(header, 0, FV_HEADER_LENGTH);
	copy_bytes(header + 16, &system_nv_fv_guid, sizeof(system_nv_fv_guid));
	write64(header + 32, total);
	write32(header + 40, FV_SIGNATURE);
	write32(header + 44, FV_ATTRIBUTES);
	write16(header + 48, FV_HEADER_LENGTH);
	write16(header + 52, 0);
	header[55] = FV_REVISION;
	write32(header + 56, store->info.num_blocks);
	write32(header + 60, store->info.block_size);
	write32(header + 64, 0);
	write32(header + 68, 0);
	for (index = 0; index < FV_HEADER_LENGTH; index += 2U)
		checksum += read16(header + index);
	write16(header + 50, (UINT16)(0U - checksum));
	fill(header + FV_HEADER_LENGTH, 0, VARIABLE_STORE_HEADER_LENGTH);
	copy_bytes(header + FV_HEADER_LENGTH, &authenticated_store_guid,
		   sizeof(authenticated_store_guid));
	write32(header + FV_HEADER_LENGTH + 16U,
		(UINT32)total - FV_HEADER_LENGTH);
	header[FV_HEADER_LENGTH + 20U] = VARIABLE_FORMATTED;
	header[FV_HEADER_LENGTH + 21U] = VARIABLE_HEALTHY;
	size = sizeof(header);
	return cdk2_smmstore_write(store, 0, 0, &size, header);
}

static EFI_STATUS validate_fv(const struct cdk2_smmstore *store,
			      const UINT8 *header, UINT64 total)
{
	UINT32 checksum = 0;
	UINTN index;

	if (!guid_equal(header + 16, &system_nv_fv_guid) ||
	    read64(header + 32) != total ||
	    read32(header + 40) != FV_SIGNATURE ||
	    read32(header + 44) != FV_ATTRIBUTES ||
	    read16(header + 48) != FV_HEADER_LENGTH ||
	    header[55] != FV_REVISION ||
	    read32(header + 56) != store->info.num_blocks ||
	    read32(header + 60) != store->info.block_size ||
	    read32(header + 64) != 0 || read32(header + 68) != 0)
		return EFI_COMPROMISED_DATA;
	for (index = 0; index < FV_HEADER_LENGTH; index += 2U)
		checksum += read16(header + index);
	return (UINT16)checksum == 0 ? EFI_SUCCESS : EFI_CRC_ERROR;
}

EFI_STATUS cdk2_variable_store_validate(struct cdk2_smmstore *store,
					UINTN *variable_count)
{
	UINT8 header[FV_HEADER_LENGTH + VARIABLE_STORE_HEADER_LENGTH];
	UINT8 variable[AUTH_VARIABLE_HEADER_LENGTH];
	UINT64 total;
	UINT64 offset;
	UINT32 store_size;
	UINTN count = 0;
	EFI_STATUS status;

	if (store == NULL || variable_count == NULL)
		return EFI_INVALID_PARAMETER;
	*variable_count = 0;
	status = cdk2_smmstore_total_size(store, &total);
	if (EFI_ERROR(status) || total > MAX_UINT32)
		return EFI_UNSUPPORTED;
	status = read_linear(store, 0, sizeof(header), header);
	if (EFI_ERROR(status))
		return status;
	status = validate_fv(store, header, total);
	if (EFI_ERROR(status))
		return status;
	if (!guid_equal(header + FV_HEADER_LENGTH, &authenticated_store_guid) ||
	    header[FV_HEADER_LENGTH + 20U] != VARIABLE_FORMATTED ||
	    header[FV_HEADER_LENGTH + 21U] != VARIABLE_HEALTHY)
		return EFI_COMPROMISED_DATA;
	store_size = read32(header + FV_HEADER_LENGTH + 16U);
	if (store_size != total - FV_HEADER_LENGTH ||
	    store_size < VARIABLE_STORE_HEADER_LENGTH)
		return EFI_COMPROMISED_DATA;
	offset = FV_HEADER_LENGTH + VARIABLE_STORE_HEADER_LENGTH;
	while (offset < total) {
		UINT64 occupied;
		UINT32 name_size;
		UINT32 data_size;
		UINT8 terminator[2];

		status = read_linear(store, offset, sizeof(variable), variable);
		if (EFI_ERROR(status))
			return status;
		if (read16(variable) == MAX_UINT16)
			break;
		if (read16(variable) != VARIABLE_START_ID)
			return EFI_COMPROMISED_DATA;
		name_size = read32(variable + 36);
		data_size = read32(variable + 40);
		if (name_size < sizeof(CHAR16) || (name_size & 1U) != 0)
			return EFI_COMPROMISED_DATA;
		occupied = AUTH_VARIABLE_HEADER_LENGTH + (UINT64)name_size +
			   data_size;
		occupied = (occupied + 3U) & ~3ULL;
		if (occupied < AUTH_VARIABLE_HEADER_LENGTH ||
		    occupied > total - offset)
			return EFI_COMPROMISED_DATA;
		status = read_linear(store,
				     offset + AUTH_VARIABLE_HEADER_LENGTH +
					     name_size - 2U,
				     sizeof(terminator), terminator);
		if (EFI_ERROR(status))
			return status;
		if (terminator[0] != 0 || terminator[1] != 0)
			return EFI_COMPROMISED_DATA;
		offset += occupied;
		count++;
	}
	*variable_count = count;
	return EFI_SUCCESS;
}
