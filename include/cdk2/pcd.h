/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PCD_H_
#define CDK2_PCD_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_PCD_SERVICE_VERSION 7U
#define CDK2_PCD_MAX_CALLBACKS 64U
#define CDK2_PCD_INVALID_TOKEN 0U

struct cdk2_pcd_database_header {
	EFI_GUID signature;
	uint32_t build_version, length;
	uint64_t system_sku_id;
	uint32_t length_all_skus, uninitialized_size;
	uint32_t local_tokens_offset, ex_map_offset, guid_offset;
	uint32_t string_offset, size_offset, sku_offset, name_offset;
	uint16_t local_token_count, ex_token_count, guid_count;
	uint8_t pad[6];
};

struct cdk2_pcd_ex_map {
	uint32_t external_token;
	uint16_t local_token, guid_index;
};

typedef void (CDK2_MS_ABI *cdk2_pcd_callback)(const EFI_GUID *, uint32_t,
	void *, size_t);

struct cdk2_pcd_callback_slot {
	const EFI_GUID *space;
	uint32_t token;
	cdk2_pcd_callback callback;
};

struct cdk2_pcd_context {
	uint8_t *database;
	size_t capacity;
	struct cdk2_pcd_database_header *header;
	struct cdk2_pcd_callback_slot callbacks[CDK2_PCD_MAX_CALLBACKS];
};

uint64_t cdk2_pcd_init(struct cdk2_pcd_context *context, void *database,
	size_t capacity);
uint64_t cdk2_pcd_get(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, void **value, size_t *size);
uint64_t cdk2_pcd_set(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, const void *value, size_t *size);
uint64_t cdk2_pcd_register(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, cdk2_pcd_callback callback);
uint64_t cdk2_pcd_unregister(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, cdk2_pcd_callback callback);
uint64_t cdk2_pcd_next_token(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t *token);
uint64_t cdk2_pcd_set_sku(struct cdk2_pcd_context *context, uint64_t sku);

#endif
