/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/smmstore_fvb.h>

#include <stdarg.h>

#define ERASE_LIST_END MAX_UINT32

static struct cdk2_smmstore_fvb *
from_protocol(struct cdk2_fvb_protocol *protocol)
{
	return (struct cdk2_smmstore_fvb *)((UINT8 *)protocol -
					    offsetof(struct cdk2_smmstore_fvb,
						     protocol));
}

static EFI_STATUS CDK2_MS_ABI get_attributes(struct cdk2_fvb_protocol *protocol,
						     UINT32 * attributes)
{
	if (protocol == NULL || attributes == NULL)
		return EFI_INVALID_PARAMETER;
	*attributes = from_protocol(protocol)->attributes;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI set_attributes(struct cdk2_fvb_protocol *protocol,
						     UINT32 * attributes)
{
	struct cdk2_smmstore_fvb *fvb;

	if (protocol == NULL || attributes == NULL)
		return EFI_INVALID_PARAMETER;
	fvb = from_protocol(protocol);
	if (*attributes != fvb->attributes) {
		*attributes = fvb->attributes;
		return EFI_UNSUPPORTED;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_physical_address(
	struct cdk2_fvb_protocol *protocol, EFI_PHYSICAL_ADDRESS * address)
{
	if (protocol == NULL || address == NULL)
		return EFI_INVALID_PARAMETER;
	*address = from_protocol(protocol)->store.info.mmio_address;
	return *address == 0 ? EFI_UNSUPPORTED : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_block_size(struct cdk2_fvb_protocol *protocol,
						     UINT32 block,
						     UINTN * block_size,
						     UINTN * remaining_blocks)
{
	struct cdk2_smmstore_fvb *fvb;

	if (protocol == NULL || block_size == NULL || remaining_blocks == NULL)
		return EFI_INVALID_PARAMETER;
	fvb = from_protocol(protocol);
	if (block >= fvb->store.info.num_blocks)
		return EFI_INVALID_PARAMETER;
	*block_size = fvb->store.info.block_size;
	*remaining_blocks = fvb->store.info.num_blocks - block;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI read_block(struct cdk2_fvb_protocol *protocol,
					 UINT32 block, UINTN offset,
						 UINTN * size, void *buffer)
{
	if (protocol == NULL || offset > MAX_UINT32)
		return EFI_INVALID_PARAMETER;
	return cdk2_smmstore_read(&from_protocol(protocol)->store, block,
				  (UINT32)offset, size, buffer);
}

static EFI_STATUS CDK2_MS_ABI write_block(struct cdk2_fvb_protocol *protocol,
					  UINT32 block, UINTN offset,
						  UINTN * size, void *buffer)
{
	if (protocol == NULL || offset > MAX_UINT32)
		return EFI_INVALID_PARAMETER;
	return cdk2_smmstore_write(&from_protocol(protocol)->store, block,
				   (UINT32)offset, size, buffer);
}

EFI_STATUS cdk2_smmstore_fvb_erase_range(struct cdk2_smmstore_fvb *fvb,
					 UINT32 start_block, UINT32 block_count)
{
	UINT32 block;
	EFI_STATUS status;

	if (fvb == NULL || block_count == 0 ||
	    start_block >= fvb->store.info.num_blocks ||
	    block_count > fvb->store.info.num_blocks - start_block)
		return EFI_INVALID_PARAMETER;
	for (block = 0; block < block_count; block++) {
		status = cdk2_smmstore_erase(&fvb->store, start_block + block);
		if (EFI_ERROR(status))
			return status;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI erase_blocks(struct cdk2_fvb_protocol *protocol,
					   ...)
{
	struct cdk2_smmstore_fvb *fvb;
	va_list ranges;
	UINT32 start;
	EFI_STATUS status = EFI_SUCCESS;

	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	fvb = from_protocol(protocol);
	va_start(ranges, protocol);
	for (;;) {
		UINT32 count;

		start = va_arg(ranges, UINT32);
		if (start == ERASE_LIST_END)
			break;
		count = va_arg(ranges, UINT32);
		status = cdk2_smmstore_fvb_erase_range(fvb, start, count);
		if (EFI_ERROR(status))
			break;
	}
	va_end(ranges);
	return status;
}

EFI_STATUS cdk2_smmstore_fvb_initialize(struct cdk2_smmstore_fvb *fvb,
					const SMMSTORE_INFO * info,
					cdk2_smmstore_invoke_fn * invoke,
					void *context)
{
	EFI_STATUS status;

	if (fvb == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_smmstore_initialize(&fvb->store, info, invoke, context);
	if (EFI_ERROR(status))
		return status;
	fvb->attributes = CDK2_SMMSTORE_FVB_ATTRIBUTES;
	fvb->protocol = (struct cdk2_fvb_protocol){
		get_attributes, set_attributes, get_physical_address,
		get_block_size, read_block,	write_block,
		erase_blocks};
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_smmstore_fvb_virtualize(struct cdk2_smmstore_fvb *fvb,
					cdk2_convert_pointer_fn * convert)
{
	EFI_STATUS status;

	if (fvb == NULL || convert == NULL)
		return EFI_INVALID_PARAMETER;
	status = convert((void **)&fvb->store.communication_buffer);
	if (EFI_ERROR(status))
		return status;
	if (fvb->store.context != NULL) {
		status = convert(&fvb->store.context);
		if (EFI_ERROR(status))
			return status;
	}
	status = convert((void **)&fvb->store.invoke);
	if (EFI_ERROR(status))
		return status;
	status = convert((void **)&fvb->protocol.get_attributes);
	if (EFI_ERROR(status))
		return status;
	status = convert((void **)&fvb->protocol.set_attributes);
	if (EFI_ERROR(status))
		return status;
	status = convert((void **)&fvb->protocol.get_physical_address);
	if (EFI_ERROR(status))
		return status;
	status = convert((void **)&fvb->protocol.get_block_size);
	if (EFI_ERROR(status))
		return status;
	status = convert((void **)&fvb->protocol.read);
	if (EFI_ERROR(status))
		return status;
	status = convert((void **)&fvb->protocol.write);
	if (EFI_ERROR(status))
		return status;
	return convert((void **)&fvb->protocol.erase_blocks);
}
