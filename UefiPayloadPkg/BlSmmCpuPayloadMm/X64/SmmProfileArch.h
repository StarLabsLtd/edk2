/** @file
X64 processor specific header file to enable SMM profile.

Copyright (c) 2012 - 2024, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _SMM_PROFILE_ARCH_H_
#define _SMM_PROFILE_ARCH_H_

extern BOOLEAN  m1GPageTableSupport;

#define PHYSICAL_ADDRESS_MASK  ((1ull << 52) - SIZE_4KB)

/**
  Set sub-entries number in entry.

  @param[in, out] Entry        Pointer to entry
  @param[in]      SubEntryNum  Sub-entries number based on 0:
                               0 means there is 1 sub-entry under this entry
                               0x1ff means there is 512 sub-entries under this entry

**/
VOID
SetSubEntriesNum (
  IN OUT UINT64  *Entry,
  IN     UINT64  SubEntryNum
  );

/**
  Return sub-entries number in entry.

  @param[in] Entry        Pointer to entry

  @return Sub-entries number based on 0:
          0 means there is 1 sub-entry under this entry
          0x1ff means there is 512 sub-entries under this entry
**/
UINT64
GetSubEntriesNum (
  IN UINT64  *Entry
  );

/**
  Allocate free Page for PageFault handler use.

  @return Page address.

**/
UINT64
AllocPage (
  VOID
  );

/**
  Set access record in entry.

  @param[in, out] Entry        Pointer to entry
  @param[in]      Acc          Access record value

**/
VOID
SetAccNum (
  IN OUT UINT64  *Entry,
  IN     UINT64  Acc
  );

#endif // _SMM_PROFILE_ARCH_H_
