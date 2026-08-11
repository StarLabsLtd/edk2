/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/ftw_geometry.h>

EFI_STATUS cdk2_ftw_geometry_from_smmstore(const SMMSTORE_INFO *info,
					   struct cdk2_ftw_geometry *g)
{
	UINT64 total, spare, working, variable;
	if (!info || !g || !info->mmio_address || !info->block_size ||
	   info->num_blocks < 4 || (info->num_blocks & 1U))
		return EFI_NOT_FOUND;
	total = (UINT64)info->num_blocks * info->block_size;
	if (total / info->block_size != info->num_blocks ||
	   info->mmio_address > MAX_UINT64 - total)
		return EFI_COMPROMISED_DATA;
	spare = (UINT64)(info->num_blocks / 2U) * info->block_size;
	working = info->block_size;
	variable = total - spare - working;
	if (!variable || variable % info->block_size)
		return EFI_COMPROMISED_DATA;
	*g = (struct cdk2_ftw_geometry) {
		info->mmio_address, total,
		     info->mmio_address, variable, info->mmio_address + variable, working,
		     info->mmio_address + variable + working, spare,
		     info->block_size, info->num_blocks
	};
	return EFI_SUCCESS;
}
