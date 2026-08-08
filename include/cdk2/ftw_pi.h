/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_FTW_PI_H
#define CDK2_FTW_PI_H
#include <cdk2/ftw.h>

struct cdk2_ftw_pi_work_header {
	EFI_GUID signature;
	UINT32 crc32;
	UINT8 state, reserved[3];
	UINT64 write_queue_size;
};
struct cdk2_ftw_pi_write_header {
	UINT8 state, pad[3];
	EFI_GUID caller_id;
	UINT32 pad2;
	UINT64 number_of_writes, private_data_size;
};
struct cdk2_ftw_pi_record {
	UINT8 state, pad[7];
	UINT64 lba, offset, length;
	INT64 relative_offset;
};
typedef char cdk2_ftw_pi_work_header_size[(sizeof(struct cdk2_ftw_pi_work_header) == 32) ? 1 : -1];
typedef char cdk2_ftw_pi_write_header_size[(sizeof(struct cdk2_ftw_pi_write_header) == 40) ? 1 : -1];
typedef char cdk2_ftw_pi_record_size[(sizeof(struct cdk2_ftw_pi_record) == 40) ? 1 : -1];

EFI_STATUS cdk2_ftw_pi_initialize(UINT8 *workspace, UINTN size);
EFI_STATUS cdk2_ftw_pi_decode(const UINT8 *workspace, UINTN size,
	struct cdk2_ftw_journal *journal);
EFI_STATUS cdk2_ftw_pi_encode(UINT8 *workspace, UINTN size,
	const struct cdk2_ftw_journal *journal);
#endif
