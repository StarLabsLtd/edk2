/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_NULL_MEMORY_TEST_H_
#define CDK2_NULL_MEMORY_TEST_H_

#include <stdint.h>

struct cdk2_generic_memory_test;

typedef uint64_t (__attribute__((ms_abi)) *cdk2_memory_test_init_fn)(
	struct cdk2_generic_memory_test *memory_test, uint32_t level,
	uint8_t *require_soft_ecc_init);
typedef uint64_t (__attribute__((ms_abi)) *cdk2_perform_memory_test_fn)(
	struct cdk2_generic_memory_test *memory_test, uint64_t *tested_memory_size,
	uint64_t *total_memory_size, uint8_t *error_out, uint8_t test_abort);
typedef uint64_t (__attribute__((ms_abi)) *cdk2_memory_test_finished_fn)(
	struct cdk2_generic_memory_test *memory_test);
typedef uint64_t (__attribute__((ms_abi)) *cdk2_compatible_range_test_fn)(
	struct cdk2_generic_memory_test *memory_test, uint64_t start, uint64_t length);

struct cdk2_generic_memory_test {
	cdk2_memory_test_init_fn initialize;
	cdk2_perform_memory_test_fn perform;
	cdk2_memory_test_finished_fn finished;
	cdk2_compatible_range_test_fn test_compatible_range;
};

#endif
