/** @file

  Native cdk2 printk-style logging.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_PRINTK_H_
#define CDK2_PRINTK_H_

#include <Library/Cdk2NativeServices.h>

#define CDK2_BIOS_EMERG    0U
#define CDK2_BIOS_ALERT    1U
#define CDK2_BIOS_CRIT     2U
#define CDK2_BIOS_ERR      3U
#define CDK2_BIOS_WARNING  4U
#define CDK2_BIOS_NOTICE   5U
#define CDK2_BIOS_INFO     6U
#define CDK2_BIOS_DEBUG    7U
#define CDK2_BIOS_SPEW     8U

VOID
EFIAPI
Cdk2NativeLogWrite (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Level,
  IN     CONST CHAR8           *Buffer,
  IN     UINTN                 Length
  );

VOID
EFIAPI
Cdk2Printk (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Level,
  IN     CONST CHAR8           *Format,
  ...
  );

#endif
