/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PCH_SMI_DISPATCH_H_
#define CDK2_PCH_SMI_DISPATCH_H_

#include <uefi.h>

#define CDK2_SMM_SW_SMI_MAX 0xffU
#define CDK2_SMM_SW_SMI_AUTO MAX_UINTN

struct cdk2_smm_sw_dispatch2_protocol;

struct cdk2_smm_sw_register_context {
	UINTN sw_smi_input_value;
};

struct cdk2_smm_sw_context {
	UINTN sw_smi_cpu_index;
	UINT8 command_port;
	UINT8 data_port;
};

typedef EFI_STATUS CDK2_MS_ABI cdk2_smm_handler(void *dispatch_handle,
	const void *register_context, void *communication_buffer,
	UINTN *communication_buffer_size);
typedef EFI_STATUS CDK2_MS_ABI cdk2_smm_sw_register(
	const struct cdk2_smm_sw_dispatch2_protocol *protocol,
	cdk2_smm_handler *handler, struct cdk2_smm_sw_register_context *context,
	void **dispatch_handle);
typedef EFI_STATUS CDK2_MS_ABI cdk2_smm_sw_unregister(
	const struct cdk2_smm_sw_dispatch2_protocol *protocol,
	void *dispatch_handle);

struct cdk2_smm_sw_dispatch2_protocol {
	cdk2_smm_sw_register *register_handler;
	cdk2_smm_sw_unregister *unregister_handler;
	UINTN maximum_swi_value;
};

#endif
