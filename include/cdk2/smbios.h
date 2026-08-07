/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SMBIOS_H_
#define CDK2_SMBIOS_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_SMBIOS_HANDLE_PI_RESERVED 0xfffeU
#define CDK2_SMBIOS_TYPE_END_OF_TABLE 127U

struct cdk2_smbios_header {
	uint8_t type;
	uint8_t length;
	uint16_t handle;
} __packed;

struct cdk2_smbios;
typedef uint64_t CDK2_MS_ABI cdk2_smbios_add_fn(const struct cdk2_smbios *, void *,
	uint16_t *, struct cdk2_smbios_header *);
typedef uint64_t CDK2_MS_ABI cdk2_smbios_update_string_fn(const struct cdk2_smbios *,
	uint16_t *, size_t *, char *);
typedef uint64_t CDK2_MS_ABI cdk2_smbios_remove_fn(const struct cdk2_smbios *, uint16_t);
typedef uint64_t CDK2_MS_ABI cdk2_smbios_get_next_fn(const struct cdk2_smbios *,
	uint16_t *, uint8_t *, struct cdk2_smbios_header **, void **);

struct cdk2_smbios {
	cdk2_smbios_add_fn *add;
	cdk2_smbios_update_string_fn *update_string;
	cdk2_smbios_remove_fn *remove;
	cdk2_smbios_get_next_fn *get_next;
	uint8_t major_version;
	uint8_t minor_version;
};

#endif
