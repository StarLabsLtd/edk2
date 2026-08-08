/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PROTOCOL_TCG2_H_
#define CDK2_PROTOCOL_TCG2_H_

#include <industry_standard/uefi_tcg_platform.h>

#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2 1U
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_2 2U
#define EFI_TCG2_BOOT_HASH_ALG_SHA1 1U
#define EFI_TCG2_BOOT_HASH_ALG_SHA256 2U
#define EFI_TCG2_BOOT_HASH_ALG_SHA384 4U
#define EFI_TCG2_BOOT_HASH_ALG_SHA512 8U
#define EFI_TCG2_BOOT_HASH_ALG_SM3_256 16U
#define EFI_TCG2_EXTEND_ONLY 1ULL
#define PE_COFF_IMAGE 0x10ULL
#define EFI_TCG2_EVENT_HEADER_VERSION 1U
#define EFI_TCG2_FINAL_EVENTS_TABLE_VERSION 1ULL

typedef struct efi_tcg2_protocol EFI_TCG2_PROTOCOL;
typedef struct { UINT8 major; UINT8 minor; } EFI_TCG2_VERSION;
typedef UINT32 EFI_TCG2_EVENT_LOG_BITMAP;
typedef UINT32 EFI_TCG2_EVENT_LOG_FORMAT;
typedef UINT32 EFI_TCG2_EVENT_ALGORITHM_BITMAP;

typedef struct efi_tcg2_boot_service_capability {
	UINT8 size;
	EFI_TCG2_VERSION structure_version;
	EFI_TCG2_VERSION protocol_version;
	EFI_TCG2_EVENT_ALGORITHM_BITMAP hash_algorithm_bitmap;
	EFI_TCG2_EVENT_LOG_BITMAP supported_event_logs;
	BOOLEAN tpm_present_flag;
	UINT16 max_command_size;
	UINT16 max_response_size;
	UINT32 manufacturer_id;
	UINT32 number_of_pcr_banks;
	EFI_TCG2_EVENT_ALGORITHM_BITMAP active_pcr_banks;
} EFI_TCG2_BOOT_SERVICE_CAPABILITY;

typedef struct efi_tcg2_event_header {
	UINT32 header_size;
	UINT16 header_version;
	TCG_PCRINDEX pcr_index;
	TCG_EVENTTYPE event_type;
} __packed EFI_TCG2_EVENT_HEADER;

typedef struct efi_tcg2_event {
	UINT32 size;
	EFI_TCG2_EVENT_HEADER header;
	UINT8 event[];
} __packed EFI_TCG2_EVENT;

typedef struct efi_tcg2_protocol *efi_tcg2_protocol_ptr;
typedef struct efi_tcg2_boot_service_capability *efi_tcg2_capability_ptr;
typedef UINT64 efi_physical_address_ptr[1];
typedef UINT8 *efi_boolean_ptr;
typedef struct efi_tcg2_event *efi_tcg2_event_ptr;
typedef UINT8 *efi_uint8_ptr;
typedef UINT32 *efi_uint32_ptr;

typedef EFI_STATUS CDK2_MS_ABI efi_tcg2_get_capability_fn(efi_tcg2_protocol_ptr self,
	efi_tcg2_capability_ptr capability);
typedef EFI_STATUS CDK2_MS_ABI efi_tcg2_get_event_log_fn(efi_tcg2_protocol_ptr self,
	EFI_TCG2_EVENT_LOG_FORMAT format, efi_physical_address_ptr location,
	efi_physical_address_ptr last_entry, efi_boolean_ptr truncated);
typedef EFI_STATUS CDK2_MS_ABI efi_tcg2_hash_log_extend_fn(efi_tcg2_protocol_ptr self,
	UINT64 flags, EFI_PHYSICAL_ADDRESS data, UINT64 data_size,
	efi_tcg2_event_ptr event);
typedef EFI_STATUS CDK2_MS_ABI efi_tcg2_submit_command_fn(efi_tcg2_protocol_ptr self,
	UINT32 input_size, efi_uint8_ptr input, UINT32 output_size, efi_uint8_ptr output);
typedef EFI_STATUS CDK2_MS_ABI efi_tcg2_get_active_banks_fn(efi_tcg2_protocol_ptr self,
	efi_uint32_ptr active);
typedef EFI_STATUS CDK2_MS_ABI efi_tcg2_set_active_banks_fn(efi_tcg2_protocol_ptr self,
	UINT32 active);
typedef EFI_STATUS CDK2_MS_ABI efi_tcg2_get_set_result_fn(efi_tcg2_protocol_ptr self,
	efi_uint32_ptr operation_present, efi_uint32_ptr response);

struct efi_tcg2_protocol {
	efi_tcg2_get_capability_fn *get_capability;
	efi_tcg2_get_event_log_fn *get_event_log;
	efi_tcg2_hash_log_extend_fn *hash_log_extend_event;
	efi_tcg2_submit_command_fn *submit_command;
	efi_tcg2_get_active_banks_fn *get_active_pcr_banks;
	efi_tcg2_set_active_banks_fn *set_active_pcr_banks;
	efi_tcg2_get_set_result_fn *get_result_of_set_active_pcr_banks;
};

typedef struct {
	UINT64 version;
	UINT64 number_of_events;
} EFI_TCG2_FINAL_EVENTS_TABLE;

extern const EFI_GUID efi_tcg2_protocol_guid;
extern const EFI_GUID efi_tcg2_final_events_table_guid;

#endif
