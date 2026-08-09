/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PARTITION_H_
#define CDK2_PARTITION_H_

#include <uefi.h>
#include <cdk2/disk_io.h>

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
	UINT32 disk_signature;
	UINT32 boot_entry;
	UINT8 mbr_type;
	UINT8 mbr_record[16];
};

typedef EFI_STATUS cdk2_partition_read_fn(void *context, UINT64 lba,
	UINTN blocks, void *buffer);

struct cdk2_partition_media {
	void *context;
	cdk2_partition_read_fn *read;
	UINT32 block_size;
	UINT64 last_block;
};

struct cdk2_block_io2_token {
	void *event;
	EFI_STATUS transaction_status;
};
struct cdk2_block_io2;
typedef EFI_STATUS CDK2_MS_ABI cdk2_block2_reset_fn(struct cdk2_block_io2 *,
	BOOLEAN, struct cdk2_block_io2_token *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_block2_rw_fn(struct cdk2_block_io2 *, UINT32,
	UINT64, struct cdk2_block_io2_token *, UINTN, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_block2_flush_fn(struct cdk2_block_io2 *,
	struct cdk2_block_io2_token *);
struct cdk2_block_io2 {
	struct cdk2_block_media *media;
	cdk2_block2_reset_fn *reset;
	cdk2_block2_rw_fn *read_blocks;
	cdk2_block2_rw_fn *write_blocks;
	cdk2_block2_flush_fn *flush_blocks;
};

struct cdk2_mbr_partition_record {
	UINT8 boot_indicator, start_head, start_sector, start_track;
	UINT8 os_indicator, end_head, end_sector, end_track;
	UINT8 starting_lba[4], size_in_lba[4];
} __packed;

struct cdk2_gpt_partition_entry {
	EFI_GUID partition_type_guid;
	EFI_GUID unique_partition_guid;
	UINT64 starting_lba;
	UINT64 ending_lba;
	UINT64 attributes;
	CHAR16 partition_name[CDK2_GPT_NAME_CHARS];
} __packed;

struct cdk2_partition_info {
	UINT32 revision;
	UINT32 type;
	UINT8 system;
	UINT8 reserved[7];
	union {
		struct cdk2_mbr_partition_record mbr;
		struct cdk2_gpt_partition_entry gpt;
	} info;
} __packed;

typedef char cdk2_mbr_partition_record_size[
	(sizeof(struct cdk2_mbr_partition_record) == 16U) ? 1 : -1];
typedef char cdk2_gpt_partition_entry_size[
	(sizeof(struct cdk2_gpt_partition_entry) == 128U) ? 1 : -1];
typedef char cdk2_partition_info_size[
	(sizeof(struct cdk2_partition_info) == 144U) ? 1 : -1];

struct cdk2_partition_child;
struct cdk2_partition_child_services {
	EFI_STATUS (*allocate)(UINTN size, void **buffer);
	void (*free)(void *buffer);
	EFI_STATUS (*install)(void **handle, struct cdk2_block_io *block,
		struct cdk2_block_io2 *block2, struct cdk2_disk_io *disk,
		struct cdk2_disk_io2 *disk2, void *device_path,
		struct cdk2_partition_info *info);
	EFI_STATUS (*uninstall)(void *handle, struct cdk2_block_io *block,
		struct cdk2_block_io2 *block2, struct cdk2_disk_io *disk,
		struct cdk2_disk_io2 *disk2, void *device_path,
		struct cdk2_partition_info *info);
	EFI_STATUS (*open_parent)(void *parent, void *child);
	EFI_STATUS (*close_parent)(void *parent, void *child);
	EFI_STATUS (*signal_event)(void *event);
};

EFI_STATUS cdk2_partition_child_create(
	const struct cdk2_partition_child_services *services, void *parent,
	struct cdk2_block_io *parent_block, struct cdk2_block_io2 *parent_block2,
	struct cdk2_disk_io *parent_disk, struct cdk2_disk_io2 *parent_disk2,
	void *device_path, const struct cdk2_partition *partition,
	struct cdk2_partition_child **child);
EFI_STATUS cdk2_partition_child_destroy(struct cdk2_partition_child *child);
struct cdk2_block_io *cdk2_partition_child_block(struct cdk2_partition_child *child);
struct cdk2_block_io2 *cdk2_partition_child_block2(
	struct cdk2_partition_child *child);
struct cdk2_disk_io *cdk2_partition_child_disk(struct cdk2_partition_child *child);
struct cdk2_disk_io2 *cdk2_partition_child_disk2(struct cdk2_partition_child *child);
void *cdk2_partition_child_handle(struct cdk2_partition_child *child);

UINT32 cdk2_partition_crc32(const void *buffer, UINTN size);
EFI_STATUS cdk2_partition_parse_gpt(const struct cdk2_partition_media *media,
	void *header_block, UINTN header_capacity, void *entry_buffer,
	UINTN entry_capacity, struct cdk2_partition *partitions,
	UINTN partition_capacity, UINTN *partition_count);
EFI_STATUS cdk2_partition_parse_mbr(const struct cdk2_partition_media *media,
	void *block_buffer, UINTN block_capacity,
	struct cdk2_partition *partitions, UINTN partition_capacity,
	UINTN *partition_count);
EFI_STATUS cdk2_partition_parse_el_torito(
	const struct cdk2_partition_media *media, void *sector_buffer,
	UINTN sector_capacity, struct cdk2_partition *partitions,
	UINTN partition_capacity, UINTN *partition_count);
EFI_STATUS cdk2_partition_parse_udf(const struct cdk2_partition_media *media,
	void *block_buffer, UINTN block_capacity,
	struct cdk2_partition *partitions, UINTN partition_capacity,
	UINTN *partition_count);

#endif
