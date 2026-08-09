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

typedef void CDK2_MS_ABI cdk2_pcd_callback(const EFI_GUID *, uint32_t,
	void *, size_t);

struct cdk2_pcd_callback_slot {
	EFI_GUID space;
	uint8_t has_space;
	uint32_t token;
	cdk2_pcd_callback *callback;
};

typedef uint64_t CDK2_MS_ABI cdk2_pcd_get_variable_fn(const uint16_t *,
	const EFI_GUID *, uint32_t *, size_t *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_set_variable_fn(const uint16_t *,
	const EFI_GUID *, uint32_t, size_t, const void *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_lock_variable_fn(const uint16_t *,
	const EFI_GUID *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_allocate_fn(uint32_t, size_t, void **);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_free_fn(void *);
typedef void CDK2_MS_ABI cdk2_pcd_event_notify_fn(void *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_create_event_fn(uint32_t, size_t,
	cdk2_pcd_event_notify_fn *, void *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_close_event_fn(void *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_register_notify_fn(const EFI_GUID *,
	void *, void **);

struct cdk2_pcd_context {
	uint8_t *database;
	size_t capacity;
	struct cdk2_pcd_database_header *header;
	struct cdk2_pcd_callback_slot callbacks[CDK2_PCD_MAX_CALLBACKS];
	cdk2_pcd_get_variable_fn *get_variable;
	cdk2_pcd_set_variable_fn *set_variable;
	cdk2_pcd_lock_variable_fn *lock_variable;
	uint8_t *vpd;
	size_t vpd_size;
	uint8_t *variable;
	size_t variable_capacity;
	cdk2_pcd_allocate_fn *allocate_pool;
	cdk2_pcd_free_fn *free_pool;
	uint8_t variable_inline[4096];
};

struct cdk2_pcd_info {
	size_t pcd_type;
	size_t pcd_size;
	char *pcd_name;
};

typedef void CDK2_MS_ABI cdk2_pcd_set_sku_fn(size_t);
typedef uint8_t CDK2_MS_ABI cdk2_pcd_get8_fn(size_t);
typedef uint16_t CDK2_MS_ABI cdk2_pcd_get16_fn(size_t);
typedef uint32_t CDK2_MS_ABI cdk2_pcd_get32_fn(size_t);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_get64_fn(size_t);
typedef void *CDK2_MS_ABI cdk2_pcd_get_ptr_fn(size_t);
typedef size_t CDK2_MS_ABI cdk2_pcd_get_size_fn(size_t);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_set8_fn(size_t, uint8_t);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_set16_fn(size_t, uint16_t);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_set32_fn(size_t, uint32_t);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_set64_fn(size_t, uint64_t);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_set_ptr_fn(size_t, size_t *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_get_next_fn(const EFI_GUID *, size_t *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_next_space_fn(const EFI_GUID **);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_callback_fn(const EFI_GUID *, size_t,
	cdk2_pcd_callback *);

struct cdk2_pcd_protocol {
	cdk2_pcd_set_sku_fn *set_sku;
	cdk2_pcd_get8_fn *get8;
	cdk2_pcd_get16_fn *get16;
	cdk2_pcd_get32_fn *get32;
	cdk2_pcd_get64_fn *get64;
	cdk2_pcd_get_ptr_fn *get_ptr;
	cdk2_pcd_get8_fn *get_bool;
	cdk2_pcd_get_size_fn *get_size;
	void *get_ex[7];
	cdk2_pcd_set8_fn *set8;
	cdk2_pcd_set16_fn *set16;
	cdk2_pcd_set32_fn *set32;
	cdk2_pcd_set64_fn *set64;
	cdk2_pcd_set_ptr_fn *set_ptr;
	cdk2_pcd_set8_fn *set_bool;
	void *set_ex[6];
	cdk2_pcd_callback_fn *callback_on_set;
	cdk2_pcd_callback_fn *cancel_callback;
	cdk2_pcd_get_next_fn *get_next_token;
	cdk2_pcd_next_space_fn *get_next_token_space;
};

struct cdk2_efi_pcd_protocol {
	cdk2_pcd_set_sku_fn *set_sku;
	void *get_ex[7];
	void *set_ex[6];
	cdk2_pcd_callback_fn *callback_on_set;
	cdk2_pcd_callback_fn *cancel_callback;
	cdk2_pcd_get_next_fn *get_next_token;
	cdk2_pcd_next_space_fn *get_next_token_space;
};

typedef uint64_t CDK2_MS_ABI cdk2_pcd_info_fn(size_t,
	struct cdk2_pcd_info *);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_info_ex_fn(const EFI_GUID *, size_t,
	struct cdk2_pcd_info *);
typedef size_t CDK2_MS_ABI cdk2_pcd_sku_fn(void);

struct cdk2_get_pcd_info_protocol {
	cdk2_pcd_info_fn *get_info;
	cdk2_pcd_info_ex_fn *get_info_ex;
	cdk2_pcd_sku_fn *get_sku;
};

struct cdk2_efi_get_pcd_info_protocol {
	cdk2_pcd_info_ex_fn *get_info;
	cdk2_pcd_sku_fn *get_sku;
};

typedef uint64_t CDK2_MS_ABI cdk2_pcd_install_fn(void **,
	const EFI_GUID *, void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_uninstall_fn(void *,
	const EFI_GUID *, void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_locate_fn(const EFI_GUID *, void *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_pcd_handle_fn(void *, const EFI_GUID *, void **);

struct cdk2_pcd_boot_services {
	uint8_t before_allocate_pool[64];
	cdk2_pcd_allocate_fn *allocate_pool;
	cdk2_pcd_free_fn *free_pool;
	cdk2_pcd_create_event_fn *create_event;
	uint8_t before_close_event[24];
	cdk2_pcd_close_event_fn *close_event;
	uint8_t before_handle[32];
	cdk2_pcd_handle_fn *handle_protocol;
	void *reserved;
	cdk2_pcd_register_notify_fn *register_protocol_notify;
	uint8_t before_locate[144];
	cdk2_pcd_locate_fn *locate_protocol;
	cdk2_pcd_install_fn *install_multiple_protocols;
	cdk2_pcd_uninstall_fn *uninstall_multiple_protocols;
};

uint64_t cdk2_pcd_init(struct cdk2_pcd_context *context, void *database,
	size_t capacity);
uint64_t cdk2_pcd_get(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, void **value, size_t *size);
uint64_t cdk2_pcd_get_info(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, size_t *datum_type, size_t *size);
uint64_t cdk2_pcd_get_name(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, char **name);
uint64_t cdk2_pcd_set(struct cdk2_pcd_context *context, const EFI_GUID *space,
	uint32_t token, const void *value, size_t *size);
uint64_t cdk2_pcd_register(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, cdk2_pcd_callback callback);
uint64_t cdk2_pcd_unregister(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t token, cdk2_pcd_callback callback);
uint64_t cdk2_pcd_next_token(struct cdk2_pcd_context *context,
	const EFI_GUID *space, uint32_t *token);
uint64_t cdk2_pcd_set_sku(struct cdk2_pcd_context *context, uint64_t sku);
uint64_t cdk2_pcd_apply_sku_delta(struct cdk2_pcd_context *context,
	uint64_t sku);
uint64_t cdk2_pcd_merge_hob(struct cdk2_pcd_context *context,
	void *pei_database, size_t pei_size);
uint64_t cdk2_pcd_configure_storage(struct cdk2_pcd_context *context,
	cdk2_pcd_get_variable_fn *get_variable,
	cdk2_pcd_set_variable_fn *set_variable, uint8_t *vpd, size_t vpd_size);
uint64_t cdk2_pcd_lock_read_only(struct cdk2_pcd_context *context,
	cdk2_pcd_lock_variable_fn *lock_variable);
uint64_t cdk2_pcd_publish(struct cdk2_pcd_context *context,
	struct cdk2_pcd_boot_services *boot_services);
uint64_t CDK2_MS_ABI cdk2_pcd_driver_entry(void *image_handle,
	void *system_table);

#endif
