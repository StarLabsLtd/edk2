/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_DISK_IO_H_
#define CDK2_DISK_IO_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_DISK_IO_REVISION 0x00010000ULL
#define CDK2_DISK_IO2_REVISION 0x00020000ULL

struct cdk2_block_media {
	uint32_t media_id;
	uint8_t removable_media, media_present, logical_partition, read_only;
	uint8_t write_caching;
	uint8_t pad[3];
	uint32_t block_size;
	uint32_t io_align;
	uint64_t last_block;
};

struct cdk2_block_io;
typedef uint64_t CDK2_MS_ABI cdk2_block_reset_fn(struct cdk2_block_io *, uint8_t);
typedef uint64_t CDK2_MS_ABI cdk2_block_rw_fn(struct cdk2_block_io *, uint32_t,
	uint64_t, size_t, void *);
typedef uint64_t CDK2_MS_ABI cdk2_block_flush_fn(struct cdk2_block_io *);
struct cdk2_block_io {
	uint64_t revision;
	struct cdk2_block_media *media;
	cdk2_block_reset_fn *reset;
	cdk2_block_rw_fn *read_blocks;
	cdk2_block_rw_fn *write_blocks;
	cdk2_block_flush_fn *flush_blocks;
};

struct cdk2_disk_io;
typedef uint64_t CDK2_MS_ABI cdk2_disk_rw_fn(struct cdk2_disk_io *, uint32_t,
	uint64_t, size_t, void *);
struct cdk2_disk_io {
	uint64_t revision;
	cdk2_disk_rw_fn *read_disk;
	cdk2_disk_rw_fn *write_disk;
};

struct cdk2_disk_io2_token { void *event; uint64_t transaction_status; };
struct cdk2_disk_io2;
typedef uint64_t CDK2_MS_ABI cdk2_disk2_cancel_fn(struct cdk2_disk_io2 *);
typedef uint64_t CDK2_MS_ABI cdk2_disk2_rw_fn(struct cdk2_disk_io2 *, uint32_t,
	uint64_t, struct cdk2_disk_io2_token *, size_t, void *);
typedef uint64_t CDK2_MS_ABI cdk2_disk2_flush_fn(struct cdk2_disk_io2 *,
	struct cdk2_disk_io2_token *);
struct cdk2_disk_io2 {
	uint64_t revision;
	cdk2_disk2_cancel_fn *cancel;
	cdk2_disk2_rw_fn *read_disk_ex;
	cdk2_disk2_rw_fn *write_disk_ex;
	cdk2_disk2_flush_fn *flush_disk_ex;
};

#endif
