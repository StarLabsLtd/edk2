/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_CAPSULE_RUNTIME_ABI_H
#define CDK2_CAPSULE_RUNTIME_ABI_H
#include <stddef.h>
#include <uefi.h>

struct cdk2_table_header { UINT64 signature; UINT32 revision, size, crc32, reserved; };
struct cdk2_runtime_services_view {
	struct cdk2_table_header header;
	void *get_time, *set_time, *get_wakeup, *set_wakeup;
	void *set_virtual_map, *convert_pointer, *get_variable, *get_next_variable;
	void *set_variable, *get_next_high_mono, *reset_system;
	void *update_capsule, *query_capsule, *query_variable_info;
};
typedef EFI_STATUS CDK2_MS_ABI (*cdk2_crc32_fn)(void *, UINTN, UINT32 *);
struct cdk2_boot_services_view {
	struct cdk2_table_header header;
	void *slots_before_crc[40];
	cdk2_crc32_fn calculate_crc32;
	void *copy_mem, *set_mem, *create_event_ex;
};

_Static_assert(sizeof(struct cdk2_table_header) == 24, "UEFI table header ABI");
_Static_assert(offsetof(struct cdk2_runtime_services_view, update_capsule) == 112, "UpdateCapsule ABI");
_Static_assert(offsetof(struct cdk2_runtime_services_view, query_capsule) == 120, "QueryCapsule ABI");
_Static_assert(sizeof(struct cdk2_runtime_services_view) == 136, "runtime table ABI");
_Static_assert(offsetof(struct cdk2_boot_services_view, calculate_crc32) == 344, "CalculateCrc32 ABI");
_Static_assert(offsetof(struct cdk2_boot_services_view, create_event_ex) == 368, "CreateEventEx ABI");

EFI_STATUS cdk2_capsule_install_runtime_slots(struct cdk2_runtime_services_view *,
	struct cdk2_boot_services_view *, void *, void *);
#endif
