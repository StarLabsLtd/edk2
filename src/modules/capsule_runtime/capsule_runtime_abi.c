/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/capsule_runtime_abi.h>

EFI_STATUS cdk2_capsule_install_runtime_slots(struct cdk2_runtime_services_view *rt,
	struct cdk2_boot_services_view *bs, void *update, void *query)
{
	void *old_update, *old_query;
	UINT32 old_crc, crc;
	EFI_STATUS status;

	if (rt == NULL || bs == NULL || bs->calculate_crc32 == NULL ||
	    update == NULL || query == NULL || rt->header.size < sizeof(*rt))
		return EFI_INVALID_PARAMETER;
	old_update = rt->update_capsule;
	old_query = rt->query_capsule;
	old_crc = rt->header.crc32;
	rt->update_capsule = update;
	rt->query_capsule = query;
	rt->header.crc32 = 0;
	status = bs->calculate_crc32(rt, rt->header.size, &crc);
	if (EFI_ERROR(status)) {
		rt->update_capsule = old_update;
		rt->query_capsule = old_query;
		rt->header.crc32 = old_crc;
		return status;
	}
	rt->header.crc32 = crc;
	return EFI_SUCCESS;
}
