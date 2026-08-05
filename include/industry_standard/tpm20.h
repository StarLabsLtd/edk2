/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_TPM20_H_
#define CDK2_ABI_TPM20_H_

#include <uefi.h>

#define SHA1_DIGEST_SIZE    20U
#define SHA256_DIGEST_SIZE  32U
#define SHA384_DIGEST_SIZE  48U
#define SHA512_DIGEST_SIZE  64U
#define SM3_256_DIGEST_SIZE 32U

#define HASH_COUNT 5U

typedef UINT16 TPM_ALG_ID;
typedef UINT16 TPMI_ALG_HASH;

#define TPM_ALG_SHA1    ((TPM_ALG_ID)0x0004U)
#define TPM_ALG_SHA256  ((TPM_ALG_ID)0x000bU)
#define TPM_ALG_SHA384  ((TPM_ALG_ID)0x000cU)
#define TPM_ALG_SHA512  ((TPM_ALG_ID)0x000dU)
#define TPM_ALG_SM3_256 ((TPM_ALG_ID)0x0012U)

typedef UINT32 TPM_PCRINDEX;
typedef struct {
	UINT8 digest[SHA1_DIGEST_SIZE];
} TPM_DIGEST;

#endif
