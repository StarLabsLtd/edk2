/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <cdk2/ftw_geometry.h>
int main(void)
{
	SMMSTORE_INFO info = { .num_blocks = 8, .block_size = 0x10000,
			       .mmio_address = 0xff800000
			     };
	struct cdk2_ftw_geometry g;
	assert(cdk2_ftw_geometry_from_smmstore(&info, &g) == EFI_SUCCESS);
	assert(g.storage_size == 0x80000 && g.variable_base == 0xff800000 &&
	       g.variable_size == 0x30000 && g.working_base == 0xff830000 &&
	       g.working_size == 0x10000 && g.spare_base == 0xff840000 &&
	       g.spare_size == 0x40000);
	info.mmio_address = 0;
	assert(cdk2_ftw_geometry_from_smmstore(&info, &g) == EFI_NOT_FOUND);
	info.mmio_address = 1;
	info.num_blocks = 7;
	assert(cdk2_ftw_geometry_from_smmstore(&info, &g) == EFI_NOT_FOUND);
	info.num_blocks = 8;
	info.block_size = 0;
	assert(cdk2_ftw_geometry_from_smmstore(&info, &g) == EFI_NOT_FOUND);
	return 0;
}
