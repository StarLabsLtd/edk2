/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_CFR_SETUP_MENU_GUID_H_
#define CDK2_ABI_CFR_SETUP_MENU_GUID_H_

#include <uefi.h>

#define CB_CFR_VERSION 0U

enum cfr_option_flags {
	CFR_OPTFLAG_READONLY = 1 << 0,
	CFR_OPTFLAG_INACTIVE = 1 << 1,
	CFR_OPTFLAG_SUPPRESS = 1 << 2,
	CFR_OPTFLAG_VOLATILE = 1 << 3,
	CFR_OPTFLAG_RUNTIME = 1 << 4,
};

#define CB_TAG_CFR_VARCHAR_OPT_NAME    0x0007U
#define CB_TAG_CFR_VARCHAR_UI_NAME     0x0008U
#define CB_TAG_CFR_VARCHAR_UI_HELPTEXT 0x0009U
#define CB_TAG_CFR_VARCHAR_DEF_VALUE   0x000aU
#define CB_TAG_CFR_DEP_VALUES          0x000cU
#define CB_TAG_CFR_RUNTIME_APPLY       0x000dU

typedef struct {
	UINT32 tag;
	UINT32 size;
	UINT32 data_length;
	UINT8 data[];
} __packed CFR_VARBINARY;

typedef struct {
	UINT32 tag;
	UINT32 size;
	UINT32 method;
	UINT32 id;
} __packed CFR_RUNTIME_APPLY;

#define CB_TAG_CFR_ENUM_VALUE 0x0002U

typedef struct {
	UINT32 tag;
	UINT32 size;
	UINT32 value;
} __packed CFR_ENUM_VALUE;

#define CB_TAG_CFR_OPTION_ENUM   0x0003U
#define CB_TAG_CFR_OPTION_NUMBER 0x0004U
#define CB_TAG_CFR_OPTION_BOOL   0x0005U

typedef struct {
	UINT32 tag;
	UINT32 size;
	UINT64 object_id;
	UINT64 dependency_id;
	UINT32 flags;
	UINT32 default_value;
	UINT32 min;
	UINT32 max;
	UINT32 step;
	UINT32 display_flags;
} __packed CFR_OPTION_NUMERIC;

#define CB_TAG_CFR_OPTION_VARCHAR 0x0006U

typedef struct {
	UINT32 tag;
	UINT32 size;
	UINT64 object_id;
	UINT64 dependency_id;
	UINT32 flags;
} __packed CFR_OPTION_VARCHAR;

#define CB_TAG_CFR_OPTION_COMMENT 0x000bU

typedef struct {
	UINT32 tag;
	UINT32 size;
	UINT64 object_id;
	UINT64 dependency_id;
	UINT32 flags;
} __packed CFR_OPTION_COMMENT;

#define CB_TAG_CFR_OPTION_FORM 0x0001U

typedef struct {
	UINT32 tag;
	UINT32 size;
	UINT64 object_id;
	UINT64 dependency_id;
	UINT32 flags;
} __packed CFR_OPTION_FORM;

#endif
