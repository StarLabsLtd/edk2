/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PARTITION_H_
#define CDK2_PARTITION_H_

#include <uefi.h>

#define CDK2_GPT_NAME_CHARS 36U

enum cdk2_partition_scheme {
	CDK2_PARTITION_GPT = 1,
	CDK2_PARTITION_MBR = 2,
	CDK2_PARTITION_EL_TORITO = 3,
	CDK2_PARTITION_UDF = 4,
};

struct cdk2_partition {
	enum cdk2_partition_scheme scheme;
	UINT64 start_lba;
	UINT64 end_lba;
	UINT64 attributes;
	EFI_GUID type_guid;
	EFI_GUID unique_guid;
	CHAR16 name[CDK2_GPT_NAME_CHARS];
	UINT32 index;
	UINT8 mbr_type;
};

typedef EFI_STATUS cdk2_partition_read_fn(void *context, UINT64 lba,
	UINTN blocks, void *buffer);

struct cdk2_partition_media {
	void *context;
	cdk2_partition_read_fn *read;
	UINT32 block_size;
	UINT64 last_block;
};

UINT32 cdk2_partition_crc32(const void *buffer, UINTN size);
EFI_STATUS cdk2_partition_parse_gpt(const struct cdk2_partition_media *media,
	void *header_block, UINTN header_capacity, void *entry_buffer,
	UINTN entry_capacity, struct cdk2_partition *partitions,
	UINTN partition_capacity, UINTN *partition_count);

#endif
