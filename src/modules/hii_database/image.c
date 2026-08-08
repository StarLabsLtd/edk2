/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/hii_database.h>

#define HII_DRAW_TRANSPARENT 1U

static BOOLEAN valid_handle(struct cdk2_hii_database *database, void *handle)
{
	struct cdk2_hii_list *list = handle;
	return list >= database->lists && list < database->lists + CDK2_HII_MAX_LISTS &&
		list->active;
}

static EFI_STATUS image_bytes(const struct cdk2_hii_image_input *image,
	UINTN *bytes)
{
	UINTN pixels;

	if (image == NULL || bytes == NULL || image->width == 0U ||
	    image->height == 0U || image->bitmap == NULL)
		return EFI_INVALID_PARAMETER;
	pixels = (UINTN)image->width * image->height;
	if (pixels > (~(UINTN)0) / sizeof(*image->bitmap))
		return EFI_OUT_OF_RESOURCES;
	*bytes = pixels * sizeof(*image->bitmap);
	return EFI_SUCCESS;
}

static struct cdk2_hii_image_entry *find_image(struct cdk2_hii_database *database,
	void *handle, UINT16 id)
{
	UINTN index;
	for (index = 0; index < CDK2_HII_MAX_IMAGES; index++)
		if (database->images[index].active &&
		    database->images[index].package_handle == handle &&
		    database->images[index].id == id)
			return &database->images[index];
	return NULL;
}

EFI_STATUS cdk2_hii_set_image(struct cdk2_hii_database *database,
	void *package_handle, UINT16 image_id,
	const struct cdk2_hii_image_input *image)
{
	struct cdk2_hii_image_entry *entry;
	struct cdk2_hii_pixel *copy;
	EFI_STATUS status;
	UINTN bytes, index;

	if (database == NULL || !valid_handle(database, package_handle) || image_id == 0U)
		return EFI_INVALID_PARAMETER;
	status = image_bytes(image, &bytes);
	if (EFI_ERROR(status))
		return status;
	entry = find_image(database, package_handle, image_id);
	if (entry == NULL)
		for (index = 0; index < CDK2_HII_MAX_IMAGES; index++)
			if (!database->images[index].active) {
				entry = &database->images[index];
				break;
			}
	if (entry == NULL)
		return EFI_OUT_OF_RESOURCES;
	status = database->ops->allocate(database->context, bytes, (void **)&copy);
	if (EFI_ERROR(status))
		return status;
	__builtin_memcpy(copy, image->bitmap, bytes);
	if (entry->active)
		database->ops->release(database->context, entry->image.bitmap);
	entry->package_handle = package_handle;
	entry->id = image_id;
	entry->image = (struct cdk2_hii_image_input) {
		image->width, image->height, copy
	};
	entry->active = TRUE;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_new_image(struct cdk2_hii_database *database,
	void *package_handle, UINT16 *image_id,
	const struct cdk2_hii_image_input *image)
{
	EFI_STATUS status;
	UINT16 candidate;

	if (database == NULL || image_id == NULL)
		return EFI_INVALID_PARAMETER;
	candidate = *image_id == 0U ? database->next_image_id++ : *image_id;
	if (candidate == 0U)
		return EFI_OUT_OF_RESOURCES;
	status = cdk2_hii_set_image(database, package_handle, candidate, image);
	if (!EFI_ERROR(status))
		*image_id = candidate;
	return status;
}

EFI_STATUS cdk2_hii_get_image(struct cdk2_hii_database *database,
	void *package_handle, UINT16 image_id, struct cdk2_hii_image_input *image)
{
	struct cdk2_hii_image_entry *entry;
	EFI_STATUS status;
	UINTN bytes;

	if (database == NULL || image == NULL || !valid_handle(database, package_handle))
		return EFI_INVALID_PARAMETER;
	entry = find_image(database, package_handle, image_id);
	if (entry == NULL)
		return EFI_NOT_FOUND;
	status = image_bytes(&entry->image, &bytes);
	if (EFI_ERROR(status))
		return status;
	status = database->ops->allocate(database->context, bytes,
		(void **)&image->bitmap);
	if (EFI_ERROR(status))
		return status;
	__builtin_memcpy(image->bitmap, entry->image.bitmap, bytes);
	image->width = entry->image.width;
	image->height = entry->image.height;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_draw_image(struct cdk2_hii_database *database,
	const struct cdk2_hii_image_input *image, UINTN flags,
	struct cdk2_hii_image_output **output, UINTN x, UINTN y,
	cdk2_hii_screen_blt_fn *screen_blt)
{
	struct cdk2_hii_image_output *target;
	struct cdk2_hii_pixel pixel, transparent;
	EFI_STATUS status;
	UINTN bytes, row, column, target_index, source_index;

	if (database == NULL || output == NULL)
		return EFI_INVALID_PARAMETER;
	status = image_bytes(image, &bytes);
	if (EFI_ERROR(status))
		return status;
	target = *output;
	if (target != NULL && target->image.screen != NULL && screen_blt != NULL)
		return screen_blt(target->image.screen, image->bitmap, x, y,
			image->width, image->height);
	if (target == NULL) {
		status = database->ops->allocate(database->context, sizeof(*target),
			(void **)&target);
		if (EFI_ERROR(status))
			return status;
		*target = (struct cdk2_hii_image_output) {
			.width = (UINT16)(x + image->width),
			.height = (UINT16)(y + image->height)
		};
		status = database->ops->allocate(database->context,
			(UINTN)target->width * target->height * sizeof(pixel),
			(void **)&target->image.bitmap);
		if (EFI_ERROR(status)) {
			database->ops->release(database->context, target);
			*output = NULL;
			return status;
		}
		__builtin_memset(target->image.bitmap, 0,
			(UINTN)target->width * target->height * sizeof(pixel));
		*output = target;
	}
	if (target->image.bitmap == NULL || x + image->width > target->width ||
	    y + image->height > target->height)
		return EFI_INVALID_PARAMETER;
	transparent = image->bitmap[0];
	for (row = 0; row < image->height; row++)
		for (column = 0; column < image->width; column++) {
			source_index = row * image->width + column;
			pixel = image->bitmap[source_index];
			if ((flags & HII_DRAW_TRANSPARENT) != 0U &&
			    pixel.blue == transparent.blue && pixel.green == transparent.green &&
			    pixel.red == transparent.red)
				continue;
			target_index = (y + row) * target->width + x + column;
			target->image.bitmap[target_index] = pixel;
		}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_hii_draw_image_id(struct cdk2_hii_database *database,
	void *package_handle, UINT16 image_id, UINTN flags,
	struct cdk2_hii_image_output **output, UINTN x, UINTN y,
	cdk2_hii_screen_blt_fn *screen_blt)
{
	struct cdk2_hii_image_entry *entry;

	if (database == NULL || !valid_handle(database, package_handle))
		return EFI_INVALID_PARAMETER;
	entry = find_image(database, package_handle, image_id);
	return entry == NULL ? EFI_NOT_FOUND : cdk2_hii_draw_image(database,
		&entry->image, flags, output, x, y, screen_blt);
}

void cdk2_hii_remove_images(struct cdk2_hii_database *database,
	void *package_handle)
{
	UINTN index;
	if (database == NULL)
		return;
	for (index = 0; index < CDK2_HII_MAX_IMAGES; index++)
		if (database->images[index].active &&
		    database->images[index].package_handle == package_handle) {
			database->ops->release(database->context,
				database->images[index].image.bitmap);
			database->images[index] = (struct cdk2_hii_image_entry) { 0 };
		}
}
