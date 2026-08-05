/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_UEFI_TCG_PLATFORM_H_
#define CDK2_ABI_UEFI_TCG_PLATFORM_H_

#include <industry_standard/tpm20.h>

typedef UINT32 TCG_EVENTTYPE;
typedef TPM_PCRINDEX TCG_PCRINDEX;
typedef TPM_DIGEST TCG_DIGEST;

#define EV_NO_ACTION ((TCG_EVENTTYPE)0x00000003U)

typedef struct {
	TCG_PCRINDEX pcr_index;
	TCG_EVENTTYPE event_type;
	TCG_DIGEST digest;
	UINT32 event_size;
} __packed TCG_PCR_EVENT_HDR;

#endif
