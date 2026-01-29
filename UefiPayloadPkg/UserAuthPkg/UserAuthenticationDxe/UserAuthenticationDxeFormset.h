/** @file
  Header file for UserAuthentication formset.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _USER_AUTHENTICATION_DXE_FORMSET_H_
#define _USER_AUTHENTICATION_DXE_FORMSET_H_

//
// Vendor GUID of the formset
//
#define USER_AUTHENTICATION_FORMSET_GUID \
  { 0x760e3022, 0xf149, 0x4560, {0x9c, 0x6f, 0x33, 0xaa, 0x7d, 0x48, 0x75, 0xfa} }

#define USER_PASSWORD_SET_KEY_ID       0x2001
#define USER_PASSWORD_CHANGE_KEY_ID    0x2002
#define USER_PASSWORD_REMOVE_KEY_ID    0x2003
#define USER_PASSWORD_REFRESH_KEY_ID   0x2004

#define MAX_PASSWORD_LEN  64
#define MIN_PASSWORD_LEN  0

#endif
