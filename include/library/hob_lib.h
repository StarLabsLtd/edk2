/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_HOB_LIB_H_
#define CDK2_ABI_HOB_LIB_H_

#include <pi/hob.h>

#define GET_HOB_TYPE(hob_start) ((*(EFI_HOB_GENERIC_HEADER **)&(hob_start))->hob_type)

#define GET_HOB_LENGTH(hob_start) ((*(EFI_HOB_GENERIC_HEADER **)&(hob_start))->hob_length)

#define GET_NEXT_HOB(hob_start) \
	((VOID *)(*(UINT8 **)&(hob_start) + GET_HOB_LENGTH(hob_start)))

#define END_OF_HOB_LIST(hob_start) \
	(GET_HOB_TYPE(hob_start) == (UINT16)EFI_HOB_TYPE_END_OF_HOB_LIST)

#define GET_GUID_HOB_DATA(hob_start) \
	((VOID *)(*(UINT8 **)&(hob_start) + sizeof(EFI_HOB_GUID_TYPE)))

#define GET_GUID_HOB_DATA_SIZE(hob_start) \
	((UINT16)(GET_HOB_LENGTH(hob_start) - sizeof(EFI_HOB_GUID_TYPE)))

#endif
