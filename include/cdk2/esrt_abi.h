/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_ESRT_ABI_H
#define CDK2_ESRT_ABI_H
#include <stddef.h>
#include <cdk2/capsule_runtime_abi.h>

struct cdk2_fmp_descriptor {
	UINT8 image_index;
	EFI_GUID image_type_id;
	UINT64 image_id;
	CHAR16 *image_id_name;
	UINT32 version;
	CHAR16 *version_name;
	UINTN size;
	UINT64 attributes_supported;
	UINT64 attributes_setting;
	UINT64 compatibilities;
	UINT32 lowest_supported_version;
	UINT32 last_attempt_version;
	UINT32 last_attempt_status;
	UINT64 hardware_instance;
	void *dependencies;
};
struct cdk2_fmp_protocol;
typedef EFI_STATUS CDK2_MS_ABI cdk2_fmp_get_info_fn(struct cdk2_fmp_protocol *,
	UINTN *, struct cdk2_fmp_descriptor *, UINT32 *, UINT8 *, UINTN *, UINT32 *, CHAR16 **);
struct cdk2_fmp_protocol {
	cdk2_fmp_get_info_fn *get_image_info;
	void *other[6];
};

struct cdk2_variable_policy_entry {
	UINT32 version; UINT16 size, offset_to_name; EFI_GUID name_space;
	UINT32 min_size, max_size, attributes_must_have, attributes_cant_have;
	UINT8 lock_policy_type, padding[3];
} __packed;
struct cdk2_variable_lock_state_policy {
	EFI_GUID name_space;
	UINT8 value;
	UINT8 padding;
} __packed;
typedef EFI_STATUS CDK2_MS_ABI cdk2_register_policy_fn(
	const struct cdk2_variable_policy_entry *);
struct cdk2_variable_policy_protocol {
	UINT64 revision; void *disable, *is_enabled;
	cdk2_register_policy_fn *register_policy;
	void *dump, *lock, *get_info, *get_lock_info;
};

typedef char cdk2_fmp_image_type_abi[(offsetof(struct cdk2_fmp_descriptor, image_type_id) == 4) ? 1 : -1];
typedef char cdk2_fmp_version_abi[(offsetof(struct cdk2_fmp_descriptor, version) == 40) ? 1 : -1];
typedef char cdk2_fmp_attributes_abi[(offsetof(struct cdk2_fmp_descriptor, attributes_supported) == 64) ? 1 : -1];
typedef char cdk2_fmp_descriptor_abi[(sizeof(struct cdk2_fmp_descriptor) == 120) ? 1 : -1];
typedef char cdk2_policy_entry_abi[(sizeof(struct cdk2_variable_policy_entry) == 44) ? 1 : -1];
typedef char cdk2_policy_state_abi[(sizeof(struct cdk2_variable_lock_state_policy) == 18) ? 1 : -1];
typedef char cdk2_policy_register_abi[(offsetof(struct cdk2_variable_policy_protocol, register_policy) == 24) ? 1 : -1];

struct cdk2_system_table_view { struct cdk2_table_header header; CHAR16 *vendor;
	UINT32 revision; void *console_in_handle, *console_in, *console_out_handle, *console_out;
	void *stderr_handle, *stderr; struct cdk2_runtime_services_view *runtime;
	struct cdk2_boot_services_view *boot; UINTN table_entries; void *configuration_table; };

EFI_STATUS CDK2_MS_ABI cdk2_esrt_entry(void *image,
	struct cdk2_system_table_view *system);
#endif
