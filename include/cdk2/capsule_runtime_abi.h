/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_CAPSULE_RUNTIME_ABI_H
#define CDK2_CAPSULE_RUNTIME_ABI_H
#include <stddef.h>
#include <uefi.h>

typedef UINT32 * cdk2_uint32_ptr;
typedef UINT64 * cdk2_uint64_ptr;
typedef void **cdk2_void_ptr_ptr;
typedef const EFI_GUID * cdk2_const_guid_ptr;

struct cdk2_table_header { UINT64 signature; UINT32 revision, size, crc32, reserved; };
struct cdk2_runtime_services_view {
	struct cdk2_table_header header;
	void *get_time, *set_time, *get_wakeup, *set_wakeup;
	void *set_virtual_map, *convert_pointer, *get_variable, *get_next_variable;
	void *set_variable, *get_next_high_mono, *reset_system;
	void *update_capsule, *query_capsule, *query_variable_info;
};
typedef EFI_STATUS CDK2_MS_ABI cdk2_crc32_fn(
	void *data, UINTN size, UINT32 result[static 1]);
struct cdk2_boot_services_view {
	struct cdk2_table_header header;
	void *raise_tpl, *restore_tpl, *allocate_pages, *free_pages, *get_memory_map;
	void *allocate_pool, *free_pool, *create_event, *set_timer, *wait_for_event;
	void *signal_event, *close_event, *check_event, *install_protocol;
	void *reinstall_protocol, *uninstall_protocol, *handle_protocol, *reserved;
	void *register_protocol_notify, *locate_handle, *locate_device_path;
	void *install_configuration_table, *load_image, *start_image, *exit;
	void *unload_image, *exit_boot_services, *get_next_monotonic_count, *stall;
	void *set_watchdog_timer, *connect_controller, *disconnect_controller;
	void *open_protocol, *close_protocol, *open_protocol_information;
	void *protocols_per_handle, *locate_handle_buffer;
	void *locate_protocol, *install_multiple, *uninstall_multiple;
	cdk2_crc32_fn *calculate_crc32;
	void *copy_mem, *set_mem, *create_event_ex;
};

typedef char cdk2_table_header_abi[(sizeof(struct cdk2_table_header) == 24) ? 1 : -1];
typedef char cdk2_update_capsule_abi[
	(offsetof(struct cdk2_runtime_services_view, update_capsule) == 112) ? 1 : -1];
typedef char cdk2_query_capsule_abi[
	(offsetof(struct cdk2_runtime_services_view, query_capsule) == 120) ? 1 : -1];
typedef char cdk2_runtime_table_abi[
	(sizeof(struct cdk2_runtime_services_view) == 136) ? 1 : -1];
typedef char cdk2_calculate_crc32_abi[
	(offsetof(struct cdk2_boot_services_view, calculate_crc32) == 344) ? 1 : -1];
typedef char cdk2_install_multiple_abi[
	(offsetof(struct cdk2_boot_services_view, install_multiple) == 328) ? 1 : -1];
typedef char cdk2_uninstall_multiple_abi[
	(offsetof(struct cdk2_boot_services_view, uninstall_multiple) == 336) ? 1 : -1];
typedef char cdk2_create_event_ex_abi[
	(offsetof(struct cdk2_boot_services_view, create_event_ex) == 368) ? 1 : -1];
typedef char cdk2_allocate_pool_abi[
	(offsetof(struct cdk2_boot_services_view, allocate_pool) == 64) ? 1 : -1];
typedef char cdk2_free_pool_abi[
	(offsetof(struct cdk2_boot_services_view, free_pool) == 72) ? 1 : -1];
typedef char cdk2_close_event_abi[
	(offsetof(struct cdk2_boot_services_view, close_event) == 112) ? 1 : -1];
typedef char cdk2_handle_protocol_abi[
	(offsetof(struct cdk2_boot_services_view, handle_protocol) == 152) ? 1 : -1];
typedef char cdk2_install_configuration_table_abi[
	(offsetof(struct cdk2_boot_services_view, install_configuration_table) == 192) ? 1 : -1];
typedef char cdk2_locate_handle_buffer_abi[
	(offsetof(struct cdk2_boot_services_view, locate_handle_buffer) == 312) ? 1 : -1];

EFI_STATUS cdk2_capsule_install_runtime_slots(
	struct cdk2_runtime_services_view *runtime,
	struct cdk2_boot_services_view *boot, void *update_capsule,
	void *query_capsule);
#endif
