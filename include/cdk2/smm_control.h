/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SMM_CONTROL_H_
#define CDK2_SMM_CONTROL_H_

#include <uefi.h>

struct cdk2_smm_control2_protocol;
typedef const struct cdk2_smm_control2_protocol *cdk2_smm_control_const_ptr;
typedef UINT8 * cdk2_uint8_ptr;

typedef EFI_STATUS CDK2_MS_ABI cdk2_smm_trigger(
	cdk2_smm_control_const_ptr protocol, cdk2_uint8_ptr command,
	cdk2_uint8_ptr data, BOOLEAN periodic, UINTN interval);
typedef EFI_STATUS CDK2_MS_ABI cdk2_smm_clear(
	cdk2_smm_control_const_ptr protocol, BOOLEAN periodic);

struct cdk2_smm_control2_protocol {
	cdk2_smm_trigger *trigger;
	cdk2_smm_clear *clear;
	UINTN minimum_trigger_period;
};

#endif
