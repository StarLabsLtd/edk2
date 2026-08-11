/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

static void copy_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *out = destination;
	const UINT8 *in = source;

	while (size-- != 0)
		*out++ = *in++;
}

EFI_STATUS cdk2_smmstore_total_size(const struct cdk2_smmstore *store,
				    UINT64 *size)
{
	if (store == NULL || size == NULL || store->info.num_blocks == 0 ||
	    store->info.block_size == 0)
		return EFI_INVALID_PARAMETER;
	*size = (UINT64)store->info.num_blocks * store->info.block_size;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_smmstore_initialize(struct cdk2_smmstore *store,
				    const SMMSTORE_INFO *info,
				    cdk2_smmstore_invoke_fn *invoke,
				    void *context)
{
	UINT64 total_size;

	if (store == NULL || info == NULL || invoke == NULL ||
	    info->num_blocks == 0 || info->block_size == 0 ||
	    info->com_buffer == 0 ||
	    info->com_buffer_size < info->block_size ||
	    info->com_buffer > MAX_UINT64 - info->com_buffer_size ||
	    info->apm_cmd == 0)
		return EFI_INVALID_PARAMETER;
	total_size = (UINT64)info->num_blocks * info->block_size;
	if (total_size == 0 || (info->mmio_address != 0 &&
				info->mmio_address > MAX_UINT64 - total_size))
		return EFI_INVALID_PARAMETER;
	store->info = *info;
	store->invoke = invoke;
	store->context = context;
	store->communication_buffer = (UINT8 *)(UINTN)info->com_buffer;
	return EFI_SUCCESS;
}

static EFI_STATUS transfer(struct cdk2_smmstore *store, BOOLEAN write,
			   UINT32 block, UINT32 offset, UINTN *size,
			   void *buffer)
{
	struct cdk2_smmstore_request request;
	UINTN transfer_size;
	EFI_STATUS status = EFI_SUCCESS;

	if (store == NULL || store->invoke == NULL || size == NULL ||
	    block >= store->info.num_blocks ||
	    offset >= store->info.block_size || (*size != 0 && buffer == NULL))
		return EFI_INVALID_PARAMETER;
	transfer_size = *size;
	if (transfer_size > store->info.block_size - offset) {
		transfer_size = store->info.block_size - offset;
		status = EFI_BAD_BUFFER_SIZE;
	}
	*size = transfer_size;
	if (transfer_size == 0)
		return status;
	request.size = (UINT32)transfer_size;
	request.offset = offset;
	request.block = block;
	if (write)
		copy_bytes(store->communication_buffer + offset, buffer,
			   transfer_size);
	if (store->invoke(store->context,
			  write ? CDK2_SMMSTORE_RAW_WRITE
				: CDK2_SMMSTORE_RAW_READ,
			  &request) != 0)
		return EFI_DEVICE_ERROR;
	if (!write)
		copy_bytes(buffer, store->communication_buffer + offset,
			   transfer_size);
	return status;
}

EFI_STATUS cdk2_smmstore_read(struct cdk2_smmstore *store, UINT32 block,
			      UINT32 offset, UINTN *size, void *buffer)
{
	return transfer(store, FALSE, block, offset, size, buffer);
}

EFI_STATUS cdk2_smmstore_write(struct cdk2_smmstore *store, UINT32 block,
			       UINT32 offset, UINTN *size, const void *buffer)
{
	return transfer(store, TRUE, block, offset, size, (void *)buffer);
}

EFI_STATUS cdk2_smmstore_erase(struct cdk2_smmstore *store, UINT32 block)
{
	struct cdk2_smmstore_request request;

	if (store == NULL || store->invoke == NULL ||
	    block >= store->info.num_blocks)
		return EFI_INVALID_PARAMETER;
	request.size = 0;
	request.offset = 0;
	request.block = block;
	return store->invoke(store->context, CDK2_SMMSTORE_RAW_CLEAR,
			     &request) == 0
		       ? EFI_SUCCESS
		       : EFI_DEVICE_ERROR;
}
