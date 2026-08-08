/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/capsule_runtime.h>

static EFI_STATUS validate(const struct cdk2_capsule_header *capsule,
	const struct cdk2_capsule_policy *policy, cdk2_capsule_support_fn support,
	void *context)
{
	UINT32 flags;

	if (capsule == NULL || capsule->header_size < sizeof(*capsule) ||
	    capsule->image_size < capsule->header_size)
		return EFI_INVALID_PARAMETER;
	flags = capsule->flags;
	if ((flags & CDK2_CAPSULE_POPULATE) && !(flags & CDK2_CAPSULE_PERSIST))
		return EFI_INVALID_PARAMETER;
	if ((flags & CDK2_CAPSULE_RESET) && !(flags & CDK2_CAPSULE_PERSIST))
		return EFI_INVALID_PARAMETER;
	if ((flags & CDK2_CAPSULE_PERSIST) && !policy->persist)
		return EFI_UNSUPPORTED;
	if (!(flags & CDK2_CAPSULE_POPULATE) && support != NULL)
		return support(capsule, context);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_capsule_update(struct cdk2_capsule_runtime *r,
	const struct cdk2_capsule_header *const *a, UINTN count, UINT64 sg,
	const struct cdk2_capsule_policy *p, cdk2_capsule_support_fn support)
{
	BOOLEAN need, reset;
	EFI_STATUS status;
	UINTN i;
	if (r == NULL || r->process == NULL || r->persist == NULL ||
	    r->writeback == NULL || r->warm_reset == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_capsule_preflight(a, count, sg, r->at_runtime, p, support,
		r->context, &need, &reset);
	if (EFI_ERROR(status)) return status;
	for (i = 0; i < count; i++)
		if (!(a[i]->flags & CDK2_CAPSULE_PERSIST)) {
			status = r->process(a[i], r->context);
			if (EFI_ERROR(status)) return status;
		}
	if (!need) return EFI_SUCCESS;
	r->writeback(sg, r->context);
	status = r->persist(r->sequence, sg, r->context);
	if (EFI_ERROR(status)) return status;
	r->sequence++;
	if (reset) r->warm_reset(r->context);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_capsule_convert_runtime(struct cdk2_capsule_runtime *r,
	EFI_STATUS (*convert)(void **, void *), void *context)
{
	void *p[4]; UINTN i; EFI_STATUS status;
	if (r == NULL || convert == NULL) return EFI_INVALID_PARAMETER;
	p[0]=(void *)r->process; p[1]=(void *)r->persist;
	p[2]=(void *)r->writeback; p[3]=(void *)r->warm_reset;
	for (i=0; i<4; i++) {
		status=convert(&p[i], context);
		if (EFI_ERROR(status)) return status;
	}
	r->process=(void *)p[0]; r->persist=(void *)p[1];
	r->writeback=(void *)p[2]; r->warm_reset=(void *)p[3];
	r->at_runtime=TRUE;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_capsule_query(const struct cdk2_capsule_header *const *capsules,
	UINTN count, const struct cdk2_capsule_policy *policy,
	cdk2_capsule_support_fn support, void *context, UINT64 *maximum_size,
	UINT32 *reset_type)
{
	BOOLEAN populate = FALSE;
	UINTN i;
	EFI_STATUS status;

	if (capsules == NULL || policy == NULL || maximum_size == NULL ||
	    reset_type == NULL || count == 0)
		return EFI_INVALID_PARAMETER;
	for (i = 0; i < count; i++) {
		status = validate(capsules[i], policy, support, context);
		if (EFI_ERROR(status))
			return status;
		populate |= (capsules[i]->flags & CDK2_CAPSULE_POPULATE) != 0;
	}
	*maximum_size = populate ? policy->max_populate : policy->max_nonpopulate;
	*reset_type = 1; /* EfiResetWarm */
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_capsule_preflight(const struct cdk2_capsule_header *const *capsules,
	UINTN count, UINT64 scatter_gather, BOOLEAN at_runtime,
	const struct cdk2_capsule_policy *policy, cdk2_capsule_support_fn support,
	void *context, BOOLEAN *needs_reset, BOOLEAN *initiate_reset)
{
	UINTN i;
	EFI_STATUS status;

	if (capsules == NULL || policy == NULL || needs_reset == NULL ||
	    initiate_reset == NULL || count == 0)
		return EFI_INVALID_PARAMETER;
	if (!policy->in_ram)
		return EFI_UNSUPPORTED;
	*needs_reset = FALSE;
	*initiate_reset = FALSE;
	for (i = 0; i < count; i++) {
		status = validate(capsules[i], policy, support, context);
		if (EFI_ERROR(status))
			return status;
		if (at_runtime && !(capsules[i]->flags & CDK2_CAPSULE_PERSIST) &&
		    !policy->process_at_runtime)
			return EFI_OUT_OF_RESOURCES;
		*needs_reset |= (capsules[i]->flags & CDK2_CAPSULE_PERSIST) != 0;
		*initiate_reset |= (capsules[i]->flags & CDK2_CAPSULE_RESET) != 0;
	}
	if (*needs_reset && scatter_gather == 0)
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}
