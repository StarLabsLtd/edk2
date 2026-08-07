/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_STATUS_CODE_ROUTER_H_
#define CDK2_STATUS_CODE_ROUTER_H_

#include <stdint.h>
#include <uefi.h>

struct cdk2_guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

struct cdk2_status_code_data {
	uint16_t header_size;
	uint16_t size;
	struct cdk2_guid type;
};

typedef uint64_t CDK2_MS_ABI cdk2_status_code_callback(uint32_t code_type,
	uint32_t value, uint32_t instance, struct cdk2_guid *caller_id,
	struct cdk2_status_code_data *data);
typedef uint64_t CDK2_MS_ABI cdk2_status_code_register(
	cdk2_status_code_callback callback, uint64_t tpl);
typedef uint64_t CDK2_MS_ABI cdk2_status_code_unregister(
	cdk2_status_code_callback callback);
typedef uint64_t CDK2_MS_ABI cdk2_report_status_code(uint32_t code_type,
	uint32_t value, uint32_t instance, struct cdk2_guid *caller_id,
	struct cdk2_status_code_data *data);

struct cdk2_rsc_handler_protocol {
	cdk2_status_code_register *register_handler;
	cdk2_status_code_unregister *unregister_handler;
};

struct cdk2_status_code_protocol {
	cdk2_report_status_code *report_status_code;
};

#endif
