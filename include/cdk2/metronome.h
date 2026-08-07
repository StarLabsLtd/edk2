/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_METRONOME_H_
#define CDK2_METRONOME_H_

#include <stdint.h>
#include <uefi.h>

struct cdk2_metronome;

typedef uint64_t (CDK2_MS_ABI *cdk2_wait_for_tick_fn)(
	struct cdk2_metronome *metronome, uint32_t ticks);

struct cdk2_metronome {
	cdk2_wait_for_tick_fn wait_for_tick;
	uint32_t tick_period;
};

uint64_t CDK2_MS_ABI
cdk2_metronome_wait_for_tick(struct cdk2_metronome *metronome, uint32_t ticks);

#endif
