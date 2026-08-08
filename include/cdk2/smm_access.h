/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SMM_ACCESS_H_
#define CDK2_SMM_ACCESS_H_

#include <guid/smram_memory.h>

struct cdk2_smm_access2_protocol;
typedef const struct cdk2_smm_access2_protocol *cdk2_smm_access_const_ptr;
typedef UINTN * cdk2_uintn_ptr;
typedef EFI_SMRAM_DESCRIPTOR * cdk2_smram_descriptor_ptr;
typedef EFI_STATUS cdk2_smm_access_action(
	struct cdk2_smm_access2_protocol *protocol) CDK2_MS_ABI;
typedef EFI_STATUS cdk2_smm_get_capabilities(
	cdk2_smm_access_const_ptr protocol, cdk2_uintn_ptr map_size,
	cdk2_smram_descriptor_ptr map) CDK2_MS_ABI;

struct cdk2_smm_access2_protocol {
	cdk2_smm_access_action *open;
	cdk2_smm_access_action *close;
	cdk2_smm_access_action *lock;
	cdk2_smm_get_capabilities *get_capabilities;
	BOOLEAN lock_state;
	BOOLEAN open_state;
};

#endif
