/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_NATIVE_SYMBOLS_H_
#define CDK2_NATIVE_SYMBOLS_H_

#include <uefi.h>
#include "module.h"

extern const struct cdk2_native_module __cdk2_modules_start[];
extern const struct cdk2_native_module __cdk2_modules_end[];

extern UINT8 __cdk2_image_start[];
extern UINT8 __cdk2_image_end[];

#if defined(__GNUC__)
extern const UINT8 __cdk2_fv_start[] __weak;
extern const UINT8 __cdk2_fv_end[] __weak;
#else
extern const UINT8 __cdk2_fv_start[];
extern const UINT8 __cdk2_fv_end[];
#endif

void cdk2_native_exception_dead_loop(void);

#endif
