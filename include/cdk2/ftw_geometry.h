/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_FTW_GEOMETRY_H
#define CDK2_FTW_GEOMETRY_H
#include <guid/smmstore_info.h>

struct cdk2_ftw_geometry {
	UINT64 storage_base, storage_size;
	UINT64 variable_base, variable_size;
	UINT64 working_base, working_size;
	UINT64 spare_base, spare_size;
	UINT32 block_size, block_count;
};
EFI_STATUS cdk2_ftw_geometry_from_smmstore(const SMMSTORE_INFO *info,
					   struct cdk2_ftw_geometry *geometry);
#endif
