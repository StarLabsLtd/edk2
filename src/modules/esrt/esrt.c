/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/esrt.h>

static BOOLEAN guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	const UINT8 *x = (const UINT8 *)a, *y = (const UINT8 *)b;
	UINTN i;
	for (i = 0; i < sizeof(*a); i++)
		if (x[i] != y[i])
			return FALSE;
	return TRUE;
}

static EFI_STATUS load(struct cdk2_esrt *esrt, enum cdk2_esrt_store store,
	struct cdk2_esrt_entry *entries, UINTN capacity, UINTN *count)
{
	EFI_STATUS status;
	if (esrt == NULL || esrt->ops == NULL || esrt->ops->read == NULL || count == NULL)
		return EFI_INVALID_PARAMETER;
	status = esrt->ops->read(esrt->context, store, entries, capacity, count);
	if (status == EFI_NOT_FOUND) {
		*count = 0;
		return EFI_SUCCESS;
	}
	if (EFI_ERROR(status))
		return status;
	if (*count > capacity)
		return EFI_COMPROMISED_DATA;
	return EFI_SUCCESS;
}

static EFI_STATUS find_in(struct cdk2_esrt *esrt, enum cdk2_esrt_store store,
	const EFI_GUID *id, struct cdk2_esrt_entry *entry)
{
	struct cdk2_esrt_entry cache[64]; UINTN count, i;
	UINTN cap = store == CDK2_ESRT_FMP ? esrt->max_fmp : esrt->max_non_fmp;
	if (cap > ARRAY_SIZE(cache))
		return EFI_OUT_OF_RESOURCES;
	EFI_STATUS status = load(esrt, store, cache, cap, &count);
	if (EFI_ERROR(status))
		return status;
	for (i = 0; i < count; i++)
		if (guid_equal(id, &cache[i].firmware_class)) {
			*entry = cache[i];
			return EFI_SUCCESS;
		}
	return EFI_NOT_FOUND;
}

EFI_STATUS cdk2_esrt_get(struct cdk2_esrt *esrt, const EFI_GUID *id,
	struct cdk2_esrt_entry *entry)
{
	EFI_STATUS status;
	if (esrt == NULL || id == NULL || entry == NULL)
		return EFI_INVALID_PARAMETER;
	status = find_in(esrt, CDK2_ESRT_NON_FMP, id, entry);
	if (status == EFI_NOT_FOUND)
		status = find_in(esrt, CDK2_ESRT_FMP, id, entry);
	return status;
}

EFI_STATUS cdk2_esrt_register(struct cdk2_esrt *esrt, const struct cdk2_esrt_entry *entry)
{
	struct cdk2_esrt_entry cache[64], found; UINTN count;
	EFI_STATUS status;
	if (esrt == NULL || entry == NULL || esrt->ops == NULL || esrt->ops->write == NULL)
		return EFI_INVALID_PARAMETER;
	if (esrt->locked)
		return EFI_WRITE_PROTECTED;
	status = find_in(esrt, CDK2_ESRT_FMP, &entry->firmware_class, &found);
	if (status != EFI_NOT_FOUND)
		return status;
	status = find_in(esrt, CDK2_ESRT_NON_FMP, &entry->firmware_class, &found);
	if (status != EFI_NOT_FOUND)
		return status;
	if (esrt->max_non_fmp > ARRAY_SIZE(cache))
		return EFI_OUT_OF_RESOURCES;
	status = load(esrt, CDK2_ESRT_NON_FMP, cache, esrt->max_non_fmp, &count);
	if (EFI_ERROR(status))
		return status;
	if (count == esrt->max_non_fmp)
		return EFI_OUT_OF_RESOURCES;
	cache[count++] = *entry;
	return esrt->ops->write(esrt->context, CDK2_ESRT_NON_FMP, cache, count);
}

static EFI_STATUS mutate(struct cdk2_esrt *esrt, enum cdk2_esrt_store store,
	const EFI_GUID *id, const struct cdk2_esrt_entry *replacement)
{
	struct cdk2_esrt_entry cache[64]; UINTN cap, count, i;
	EFI_STATUS status;
	if (esrt->locked)
		return EFI_WRITE_PROTECTED;
	cap = store == CDK2_ESRT_FMP ? esrt->max_fmp : esrt->max_non_fmp;
	if (cap > ARRAY_SIZE(cache))
		return EFI_OUT_OF_RESOURCES;
	status = load(esrt, store, cache, cap, &count);
	if (EFI_ERROR(status))
		return status;
	for (i = 0; i < count; i++)
		if (guid_equal(id, &cache[i].firmware_class)) {
			if (replacement != NULL) {
				cache[i] = *replacement;
			} else {
				for (; i + 1 < count; i++)
					cache[i] = cache[i + 1];
				count--;
			}
			return esrt->ops->write(esrt->context, store, cache, count);
		}
	return EFI_NOT_FOUND;
}

EFI_STATUS cdk2_esrt_unregister(struct cdk2_esrt *esrt, const EFI_GUID *id)
{
	if (esrt == NULL || id == NULL || esrt->ops == NULL || esrt->ops->write == NULL)
		return EFI_INVALID_PARAMETER;
	return mutate(esrt, CDK2_ESRT_NON_FMP, id, NULL);
}

EFI_STATUS cdk2_esrt_update(struct cdk2_esrt *esrt, const struct cdk2_esrt_entry *entry)
{
	EFI_STATUS status;
	if (esrt == NULL || entry == NULL || esrt->ops == NULL || esrt->ops->write == NULL)
		return EFI_INVALID_PARAMETER;
	status = mutate(esrt, CDK2_ESRT_FMP, &entry->firmware_class, entry);
	if (status == EFI_NOT_FOUND)
		status = mutate(esrt, CDK2_ESRT_NON_FMP, &entry->firmware_class, entry);
	return status;
}

static UINT32 published_type(const struct cdk2_esrt_table *table, const EFI_GUID *id,
	BOOLEAN *found)
{
	UINTN i; *found = FALSE;
	if (table == NULL)
		return 0;
	for (i = 0; i < table->resource_count; i++)
		if (guid_equal(id, &table->entries[i].firmware_class) &&
		    table->entries[i].firmware_type >= CDK2_ESRT_TYPE_SYSTEM &&
		    table->entries[i].firmware_type <= CDK2_ESRT_TYPE_UEFI_DRIVER) {
			*found = TRUE; return table->entries[i].firmware_type;
		}
	return 0;
}

static BOOLEAN system_class(const struct cdk2_esrt *esrt, const EFI_GUID *id)
{
	UINTN i; for (i = 0; i < esrt->system_class_count; i++)
		if (guid_equal(id, &esrt->system_classes[i]))
			return TRUE;
	return FALSE;
}

static void from_fmp(struct cdk2_esrt *esrt, struct cdk2_esrt_entry *out,
	const struct cdk2_esrt_fmp_image *in, const struct cdk2_esrt_table *published)
{
	BOOLEAN found;
	out->firmware_class = in->image_type_id;
	out->firmware_version = in->version;
	out->firmware_type = published_type(published, &in->image_type_id, &found);
	if (!found)
		out->firmware_type = system_class(esrt, &in->image_type_id) ?
			CDK2_ESRT_TYPE_SYSTEM : CDK2_ESRT_TYPE_DEVICE;
	out->lowest_supported_version = in->descriptor_version >= 2 ?
		in->lowest_supported_version : 0;
	out->last_attempt_version = in->descriptor_version >= 3 ? in->last_attempt_version : 0;
	out->last_attempt_status = in->descriptor_version >= 3 ? in->last_attempt_status :
		CDK2_ESRT_LAST_ATTEMPT_SUCCESS;
	out->capsule_flags = ((in->attributes_supported & CDK2_ESRT_IMAGE_RESET_REQUIRED) &&
		(in->attributes_setting & CDK2_ESRT_IMAGE_RESET_REQUIRED)) ?
		esrt->reboot_capsule_flags : 0;
}

EFI_STATUS cdk2_esrt_sync_fmp(struct cdk2_esrt *esrt,
	const struct cdk2_esrt_fmp_image *images, UINTN image_count,
	const struct cdk2_esrt_table *published)
{
	struct cdk2_esrt_entry cache[64], non_fmp[64];
	UINTN count = 0, non_count, i, j;
	EFI_STATUS status;
	if (esrt == NULL || esrt->ops == NULL || esrt->ops->write == NULL ||
	    (image_count && images == NULL))
		return EFI_INVALID_PARAMETER;
	if (esrt->locked)
		return EFI_WRITE_PROTECTED;
	if (esrt->max_fmp > ARRAY_SIZE(cache) || esrt->max_non_fmp > ARRAY_SIZE(non_fmp))
		return EFI_OUT_OF_RESOURCES;
	status = load(esrt, CDK2_ESRT_NON_FMP, non_fmp, esrt->max_non_fmp, &non_count);
	if (EFI_ERROR(status))
		return status;
	for (i = 0; i < image_count; i++) {
		if ((images[i].attributes_supported & CDK2_ESRT_IMAGE_IN_USE) &&
		    !(images[i].attributes_setting & CDK2_ESRT_IMAGE_IN_USE))
			continue;
		for (j = 0; j < non_count; j++)
			if (guid_equal(&non_fmp[j].firmware_class, &images[i].image_type_id))
				break;
		if (j < non_count)
			continue;
		for (j = 0; j < count; j++)
			if (guid_equal(&cache[j].firmware_class, &images[i].image_type_id))
				break;
		if (j < count && cache[j].firmware_version <= images[i].version)
			continue;
		if (j == count) {
			if (count == esrt->max_fmp)
				return EFI_OUT_OF_RESOURCES;
			count++;
		}
		from_fmp(esrt, &cache[j], &images[i], published);
	}
	return esrt->ops->write(esrt->context, CDK2_ESRT_FMP, cache, count);
}

EFI_STATUS cdk2_esrt_lock(struct cdk2_esrt *esrt)
{
	EFI_STATUS status;
	if (esrt == NULL || esrt->ops == NULL || esrt->ops->lock == NULL)
		return EFI_INVALID_PARAMETER;
	status = esrt->ops->lock(esrt->context, CDK2_ESRT_FMP);
	if (EFI_ERROR(status))
		return status;
	status = esrt->ops->lock(esrt->context, CDK2_ESRT_NON_FMP);
	if (!EFI_ERROR(status))
		esrt->locked = TRUE;
	return status;
}

EFI_STATUS cdk2_esrt_ready_to_boot(struct cdk2_esrt *esrt)
{
	struct { struct cdk2_esrt_table table; struct cdk2_esrt_entry entries[128]; } image;
	UINTN non_count, fmp_count; EFI_STATUS status;
	if (esrt == NULL || esrt->ops == NULL || esrt->ops->publish == NULL)
		return EFI_INVALID_PARAMETER;
	if (esrt->max_non_fmp + esrt->max_fmp > ARRAY_SIZE(image.entries))
		return EFI_OUT_OF_RESOURCES;
	status = load(esrt, CDK2_ESRT_NON_FMP, image.entries, esrt->max_non_fmp, &non_count);
	if (EFI_ERROR(status))
		return status;
	status = load(esrt, CDK2_ESRT_FMP, image.entries + non_count, esrt->max_fmp, &fmp_count);
	if (EFI_ERROR(status))
		return status;
	image.table.resource_count = (UINT32)(non_count + fmp_count);
	image.table.resource_count_max = image.table.resource_count;
	image.table.resource_version = 1;
	status = esrt->ops->publish(esrt->context, &image.table,
		sizeof(image.table) + (non_count + fmp_count) * sizeof(image.entries[0]));
	if (!EFI_ERROR(status) && esrt->ready_event && esrt->ops->close_event) {
		status = esrt->ops->close_event(esrt->context, esrt->ready_event);
		if (!EFI_ERROR(status))
			esrt->ready_event = NULL;
	}
	return status;
}

EFI_STATUS cdk2_esrt_activate(struct cdk2_esrt *esrt)
{
	EFI_STATUS status, rollback;
	if (esrt == NULL || esrt->ops == NULL || esrt->ops->install_management == NULL ||
	    esrt->ops->uninstall_management == NULL || esrt->ops->create_ready_to_boot == NULL)
		return EFI_INVALID_PARAMETER;
	status = esrt->ops->create_ready_to_boot(esrt->context, esrt, &esrt->ready_event);
	if (EFI_ERROR(status))
		return status;
	status = esrt->ops->install_management(esrt->context, esrt);
	if (EFI_ERROR(status)) {
		rollback = esrt->ops->close_event ?
			esrt->ops->close_event(esrt->context, esrt->ready_event) : EFI_UNSUPPORTED;
		if (EFI_ERROR(rollback))
			/* Keep the image resident while its callback remains registered. */
			return EFI_SUCCESS;
		esrt->ready_event = NULL;
		return status;
	}
	esrt->management_installed = TRUE;
	return EFI_SUCCESS;
}
