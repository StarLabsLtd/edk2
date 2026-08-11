/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_FTW_H
#define CDK2_FTW_H
#include <uefi.h>

#define CDK2_FTW_MAX_WRITES 16U
#define CDK2_FTW_MAX_PRIVATE 64U
#define CDK2_FTW_MAGIC 0x4a575446U
#ifndef EFI_VOLUME_CORRUPTED
#define EFI_VOLUME_CORRUPTED EFIERR(10)
#define EFI_ACCESS_DENIED EFIERR(15)
#define EFI_BAD_BUFFER_SIZE EFIERR(4)
#define EFI_WRITE_PROTECTED EFIERR(8)
#define EFI_ABORTED EFIERR(21)
#endif

enum cdk2_ftw_phase { CDK2_FTW_EMPTY, CDK2_FTW_ALLOCATED,
		      CDK2_FTW_SPARE_COMPLETE, CDK2_FTW_DESTINATION_COMPLETE,
		      CDK2_FTW_ABORTED, CDK2_FTW_BATCH_COMPLETE
		    };

struct cdk2_ftw_record {
	UINT64 lba, offset, length;
	INT64 relative_offset;
	UINT32 private_size;
	UINT8 phase;
	UINT8 reserved[3];
	UINT8 private_data[CDK2_FTW_MAX_PRIVATE];
};
struct cdk2_ftw_journal {
	UINT32 magic, crc32;
	EFI_GUID caller_id;
	UINT32 private_size, write_count, next_write;
	UINT8 phase, reserved[3];
	struct cdk2_ftw_record records[CDK2_FTW_MAX_WRITES];
};

typedef EFI_STATUS cdk2_ftw_journal_read_fn(void *, struct cdk2_ftw_journal *);
typedef EFI_STATUS cdk2_ftw_journal_write_fn(void *, const struct cdk2_ftw_journal *);
typedef EFI_STATUS cdk2_ftw_block_read_fn(void *, UINT64, void *, UINTN);
typedef EFI_STATUS cdk2_ftw_block_write_fn(void *, UINT64, const void *, UINTN);
typedef EFI_STATUS cdk2_ftw_block_erase_fn(void *, UINT64);
struct cdk2_ftw_ops {
	cdk2_ftw_journal_read_fn *journal_read;
	cdk2_ftw_journal_write_fn *journal_write;
	cdk2_ftw_block_read_fn *target_read;
	cdk2_ftw_block_write_fn *target_write;
	cdk2_ftw_block_erase_fn *target_erase;
	cdk2_ftw_block_read_fn *spare_read;
	cdk2_ftw_block_write_fn *spare_write;
	cdk2_ftw_block_erase_fn *spare_erase;
};
struct cdk2_ftw {
	const struct cdk2_ftw_ops *ops;
	void *context;
	UINTN block_size;
	UINT8 *scratch;
	struct cdk2_ftw_journal journal;
	INT64 relative_offset;
};

UINT32 cdk2_ftw_crc32(const void *data, UINTN bytes);
EFI_STATUS cdk2_ftw_initialize(struct cdk2_ftw *ftw);
EFI_STATUS cdk2_ftw_allocate(struct cdk2_ftw *ftw, const EFI_GUID *caller,
			     UINTN private_size, UINTN writes);
void cdk2_ftw_set_relative_offset(struct cdk2_ftw *ftw, INT64 relative_offset);
EFI_STATUS cdk2_ftw_write(struct cdk2_ftw *ftw, UINT64 lba, UINTN offset,
			  UINTN length, const void *private_data, const void *buffer);
EFI_STATUS cdk2_ftw_restart(struct cdk2_ftw *ftw);
EFI_STATUS cdk2_ftw_abort(struct cdk2_ftw *ftw);
EFI_STATUS cdk2_ftw_get_last_write(struct cdk2_ftw *ftw, EFI_GUID *caller,
				   UINT64 *lba, UINTN *offset, UINTN *length, UINTN *private_size,
				   void *private_data, BOOLEAN *complete);
#endif
