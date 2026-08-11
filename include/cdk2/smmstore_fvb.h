/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SMMSTORE_FVB_H_
#define CDK2_SMMSTORE_FVB_H_

#include <guid/smmstore_info.h>
#include <uefi.h>

#define CDK2_SMMSTORE_RAW_READ 5U
#define CDK2_SMMSTORE_RAW_WRITE 6U
#define CDK2_SMMSTORE_RAW_CLEAR 7U

struct cdk2_smmstore_request {
	UINT32 size;
	UINT32 offset;
	UINT32 block;
} __packed;

typedef UINT32 cdk2_smmstore_invoke_fn(void *context, UINT8 command,
				       void *request);

struct cdk2_smmstore {
	SMMSTORE_INFO info;
	cdk2_smmstore_invoke_fn *invoke;
	void *context;
	UINT8 *communication_buffer;
};

EFI_STATUS cdk2_smmstore_initialize(struct cdk2_smmstore *store,
				    const SMMSTORE_INFO *info,
				    cdk2_smmstore_invoke_fn *invoke,
				    void *context);
EFI_STATUS cdk2_smmstore_read(struct cdk2_smmstore *store, UINT32 block,
			      UINT32 offset, UINTN *size, void *buffer);
EFI_STATUS cdk2_smmstore_write(struct cdk2_smmstore *store, UINT32 block,
			       UINT32 offset, UINTN *size, const void *buffer);
EFI_STATUS cdk2_smmstore_erase(struct cdk2_smmstore *store, UINT32 block);
EFI_STATUS cdk2_smmstore_total_size(const struct cdk2_smmstore *store,
				    UINT64 *size);
EFI_STATUS cdk2_variable_store_format(struct cdk2_smmstore *store);
EFI_STATUS cdk2_variable_store_validate(struct cdk2_smmstore *store,
					UINTN *variable_count);

#define CDK2_FVB_READ_ENABLED_CAP 0x00000002U
#define CDK2_FVB_READ_STATUS 0x00000004U
#define CDK2_FVB_WRITE_ENABLED_CAP 0x00000010U
#define CDK2_FVB_WRITE_STATUS 0x00000020U
#define CDK2_FVB_MEMORY_MAPPED 0x00000400U
#define CDK2_FVB_ERASE_POLARITY 0x00000800U
#define CDK2_SMMSTORE_FVB_ATTRIBUTES 0x00000c36U

struct cdk2_fvb_protocol;
typedef EFI_STATUS CDK2_MS_ABI
cdk2_fvb_get_attributes_fn(struct cdk2_fvb_protocol *, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI
cdk2_fvb_set_attributes_fn(struct cdk2_fvb_protocol *, UINT64 *);
typedef EFI_STATUS CDK2_MS_ABI
cdk2_fvb_get_address_fn(struct cdk2_fvb_protocol *, EFI_PHYSICAL_ADDRESS *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fvb_get_block_size_fn(
	struct cdk2_fvb_protocol *, UINT32, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fvb_rw_fn(struct cdk2_fvb_protocol *,
					      UINT32, UINTN, UINTN *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_fvb_erase_fn(struct cdk2_fvb_protocol *,
						 ...);

struct cdk2_fvb_protocol {
	cdk2_fvb_get_attributes_fn *get_attributes;
	cdk2_fvb_set_attributes_fn *set_attributes;
	cdk2_fvb_get_address_fn *get_physical_address;
	cdk2_fvb_get_block_size_fn *get_block_size;
	cdk2_fvb_rw_fn *read;
	cdk2_fvb_rw_fn *write;
	cdk2_fvb_erase_fn *erase_blocks;
};

typedef EFI_STATUS cdk2_convert_pointer_fn(void **pointer);

struct cdk2_smmstore_fvb {
	struct cdk2_fvb_protocol protocol;
	struct cdk2_smmstore store;
	UINT64 attributes;
};

EFI_STATUS cdk2_smmstore_fvb_initialize(struct cdk2_smmstore_fvb *fvb,
					const SMMSTORE_INFO *info,
					cdk2_smmstore_invoke_fn *invoke,
					void *context);
EFI_STATUS cdk2_smmstore_fvb_erase_range(struct cdk2_smmstore_fvb *fvb,
					 UINT32 start_block,
					 UINT32 block_count);
EFI_STATUS cdk2_smmstore_fvb_virtualize(struct cdk2_smmstore_fvb *fvb,
					cdk2_convert_pointer_fn *convert);

#endif
