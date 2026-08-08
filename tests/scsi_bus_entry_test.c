/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_bus_binding.h>

struct cdk2_system_table;
EFI_STATUS CDK2_MS_ABI cdk2_scsi_bus_entry(void *, struct cdk2_system_table *);

int main(void)
{
	return cdk2_scsi_bus_entry((void *)1, NULL) == EFI_INVALID_PARAMETER ? 0 : 1;
}
